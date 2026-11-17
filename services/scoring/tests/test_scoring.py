"""
Unit and integration tests for the Scoring Service.
Verifies parallel orchestration across Rule Engine, Reputation, and Velocity,
dynamic Risk Score calculation (0.0..100.0), ALLOW/DENY threshold (>= 60.0),
TTL rule caching, X-Request-ID propagation, RabbitMQ event publishing
('antifraud.events' / 'inspection.completed'), and health/readiness probes.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any
from uuid import UUID

import aio_pika
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

current_dir = Path(__file__).resolve().parent
service_root = current_dir.parent
project_root = service_root.parent.parent

if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def _load_service_package(pkg_name: str, pkg_dir: Path) -> None:
    """Loads service src package under a unique namespace to avoid sys.modules collisions."""
    if pkg_name in sys.modules:
        return
    init_file = pkg_dir / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        init_file,
        submodule_search_locations=[str(pkg_dir)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)


_load_service_package("scoring_src", service_root / "src")

from scoring_src.clients import DownstreamOrchestrator  # noqa: E402
from scoring_src.main import app, get_orchestrator, get_publisher  # noqa: E402
from scoring_src.publisher import RabbitMQPublisher  # noqa: E402


DEFAULT_RULES_PAYLOAD = [
    {
        "id": 1,
        "name": "High velocity IP (>10 req/min)",
        "metric_type": "VELOCITY",
        "threshold_val": 10.0,
        "weight": 40.0,
        "is_active": True,
    },
    {
        "id": 2,
        "name": "High velocity Destination (>30 req/min)",
        "metric_type": "VELOCITY",
        "threshold_val": 30.0,
        "weight": 50.0,
        "is_active": True,
    },
    {
        "id": 3,
        "name": "Blacklisted prefix/IP",
        "metric_type": "REPUTATION",
        "threshold_val": 0.0,
        "weight": 100.0,
        "is_active": True,
    },
]


class FakeRabbitExchange:
    """Captures published aio_pika messages for verification."""

    def __init__(self, fail_with: Exception | None = None) -> None:
        self.published: list[tuple[aio_pika.Message, str]] = []
        self.fail_with = fail_with

    async def publish(self, message: aio_pika.Message, routing_key: str) -> None:
        if self.fail_with is not None:
            raise self.fail_with
        self.published.append((message, routing_key))


class FakeConnectionOrChannel:
    """Minimal stand-in exposing is_closed for readiness checks."""

    def __init__(self, is_closed: bool = False) -> None:
        self.is_closed = is_closed

    async def close(self) -> None:
        self.is_closed = True


def _build_fake_publisher(
    connected: bool = True,
    fail_publish: Exception | None = None,
) -> tuple[RabbitMQPublisher, FakeRabbitExchange]:
    publisher = RabbitMQPublisher(
        exchange_name="antifraud.events",
        routing_key="inspection.completed",
    )
    exchange = FakeRabbitExchange(fail_with=fail_publish)
    if connected:
        publisher._connection = FakeConnectionOrChannel(is_closed=False)  # type: ignore[assignment]
        publisher._channel = FakeConnectionOrChannel(is_closed=False)  # type: ignore[assignment]
        publisher._exchange = exchange  # type: ignore[assignment]
    return publisher, exchange


def _build_mock_orchestrator(
    rules_payload: list[dict[str, Any]] | None = None,
    reputation_payload: dict[str, Any] | None = None,
    velocity_payload: dict[str, Any] | None = None,
    call_log: list[tuple[str, str, str | None]] | None = None,
    fail_rule_engine: bool = False,
    fail_velocity: bool = False,
) -> DownstreamOrchestrator:
    rules_data = rules_payload if rules_payload is not None else DEFAULT_RULES_PAYLOAD
    rep_data = (
        reputation_payload
        if reputation_payload is not None
        else {"is_blacklisted": False, "matched_entities": []}
    )
    vel_data = (
        velocity_payload
        if velocity_payload is not None
        else {"ip_count_1m": 1, "phone_count_5m": 1}
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if call_log is not None:
            call_log.append(
                (request.method, str(request.url), request.headers.get("X-Request-ID"))
            )
        if request.url.path == "/api/v1/rules":
            if fail_rule_engine:
                raise httpx.ReadTimeout("Rule Engine timed out")
            return httpx.Response(200, json=rules_data)
        if request.url.path == "/api/v1/reputation/check":
            return httpx.Response(200, json=rep_data)
        if request.url.path == "/api/v1/velocity/hit":
            if fail_velocity:
                return httpx.Response(503, json={"error": "Service Unavailable"})
            return httpx.Response(200, json=vel_data)
        return httpx.Response(404)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return DownstreamOrchestrator(
        rule_engine_url="http://service-rule-engine:8001",
        reputation_url="http://service-reputation:8002",
        velocity_url="http://service-velocity:8003",
        rules_cache_ttl=30.0,
        http_client=mock_client,
    )


def _sample_sms_request() -> dict[str, Any]:
    return {
        "client_ip": "198.51.100.24",
        "phone_number": "+24101234567",
        "mcc_mnc": "62801",
        "timestamp": "2026-11-17T18:55:00Z",
        "message_length": 28,
        "sender_id": "AUTH_VERIFY",
    }


@pytest.mark.asyncio
async def test_health_endpoint():
    """GET /health returns 200 ok immediately."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "service-scoring"
    assert "X-Request-ID" in resp.headers


@pytest.mark.asyncio
async def test_ready_endpoint_connected_and_disconnected():
    """GET /ready returns 200 when RabbitMQ publisher is connected and 503 when disconnected."""
    connected_pub, _ = _build_fake_publisher(connected=True)
    app.dependency_overrides[get_publisher] = lambda: connected_pub
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            ok_resp = await client.get("/ready")
            assert ok_resp.status_code == 200
            ok_data = ok_resp.json()
            assert ok_data["status"] == "ready"
            assert ok_data["rabbitmq"] == "connected"
            assert ok_data["exchange"] == "antifraud.events"

        disconnected_pub, _ = _build_fake_publisher(connected=False)
        app.dependency_overrides[get_publisher] = lambda: disconnected_pub
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            err_resp = await client.get("/ready")
            assert err_resp.status_code == 503
            err_data = err_resp.json()
            assert err_data["status"] == "error"
            assert err_data["rabbitmq"] == "disconnected"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_score_clean_traffic_allow_and_rabbitmq_publish():
    """Clean traffic returns ALLOW (0.0) and publishes full event to 'antifraud.events'."""
    call_log: list[tuple[str, str, str | None]] = []
    orchestrator = _build_mock_orchestrator(
        reputation_payload={"is_blacklisted": False, "matched_entities": []},
        velocity_payload={"ip_count_1m": 2, "phone_count_5m": 1},
        call_log=call_log,
    )
    publisher, fake_exchange = _build_fake_publisher(connected=True)

    app.dependency_overrides[get_orchestrator] = lambda: orchestrator
    app.dependency_overrides[get_publisher] = lambda: publisher
    transport = ASGITransport(app=app)
    try:
        req_uuid = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/score",
                headers={"X-Request-ID": req_uuid},
                json=_sample_sms_request(),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["request_id"] == req_uuid
        assert data["verdict"] == "ALLOW"
        assert data["risk_score"] == 0.0
        assert data["reasons"] == []
        assert data["latency_ms"] >= 0.0
        assert resp.headers["X-Request-ID"] == req_uuid

        # Verify all 3 downstream services received the propagated X-Request-ID
        assert len(call_log) == 3
        assert all(hdr == req_uuid for _, _, hdr in call_log)

        # Verify RabbitMQ publication to 'antifraud.events' with 'inspection.completed'
        assert len(fake_exchange.published) == 1
        msg, routing_key = fake_exchange.published[0]
        assert routing_key == "inspection.completed"
        assert msg.correlation_id == req_uuid
        assert msg.content_type == "application/json"
        published_body = json.loads(msg.body.decode("utf-8"))
        assert published_body["request_id"] == req_uuid
        assert published_body["verdict"] == "ALLOW"
        assert published_body["risk_score"] == 0.0
        assert published_body["client_ip"] == "198.51.100.24"
        assert published_body["mcc_mnc"] == "62801"
    finally:
        await orchestrator._client.aclose()  # type: ignore[union-attr]
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_score_partial_risk_below_60_returns_allow():
    """IP velocity spike alone (weight 40.0 < 60.0) returns ALLOW with reason."""
    orchestrator = _build_mock_orchestrator(
        reputation_payload={"is_blacklisted": False, "matched_entities": []},
        velocity_payload={"ip_count_1m": 15, "phone_count_5m": 2},
    )
    publisher, fake_exchange = _build_fake_publisher(connected=True)

    app.dependency_overrides[get_orchestrator] = lambda: orchestrator
    app.dependency_overrides[get_publisher] = lambda: publisher
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/score", json=_sample_sms_request())
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "ALLOW"
        assert data["risk_score"] == 40.0
        assert len(data["reasons"]) == 1
        assert "VELOCITY_IP_EXCEEDED" in data["reasons"][0]
        assert len(fake_exchange.published) == 1
    finally:
        await orchestrator._client.aclose()  # type: ignore[union-attr]
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_score_combined_velocity_ge_60_returns_deny():
    """Combined IP (40.0) + Destination (50.0) spikes yield 90.0 >= 60.0 -> DENY."""
    orchestrator = _build_mock_orchestrator(
        reputation_payload={"is_blacklisted": False, "matched_entities": []},
        velocity_payload={"ip_count_1m": 15, "phone_count_5m": 35},
    )
    publisher, fake_exchange = _build_fake_publisher(connected=True)

    app.dependency_overrides[get_orchestrator] = lambda: orchestrator
    app.dependency_overrides[get_publisher] = lambda: publisher
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/score", json=_sample_sms_request())
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "DENY"
        assert data["risk_score"] == 90.0
        assert len(data["reasons"]) == 2
        assert UUID(data["request_id"])
        assert len(fake_exchange.published) == 1
        published_body = json.loads(fake_exchange.published[0][0].body.decode("utf-8"))
        assert published_body["verdict"] == "DENY"
        assert published_body["risk_score"] == 90.0
    finally:
        await orchestrator._client.aclose()  # type: ignore[union-attr]
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_score_blacklisted_and_geo_clamped_to_100():
    """Blacklist match + velocity spike + GEO rule clamps risk_score cleanly to 100.0."""
    rules_with_geo = DEFAULT_RULES_PAYLOAD + [
        {
            "id": 4,
            "name": "High-risk GEO prefix",
            "metric_type": "GEO",
            "threshold_val": 0.0,
            "weight": 40.0,
            "is_active": True,
        }
    ]
    orchestrator = _build_mock_orchestrator(
        rules_payload=rules_with_geo,
        reputation_payload={
            "is_blacklisted": True,
            "matched_entities": [
                {
                    "type": "IP",
                    "value": "198.51.100.24",
                    "reason": "Known Tor exit node",
                },
                {
                    "type": "MCC_MNC",
                    "value": "62801",
                    "reason": "Gabon test range",
                },
            ],
        },
        velocity_payload={"ip_count_1m": 25, "phone_count_5m": 1},
    )
    publisher, _ = _build_fake_publisher(connected=True)

    app.dependency_overrides[get_orchestrator] = lambda: orchestrator
    app.dependency_overrides[get_publisher] = lambda: publisher
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/score", json=_sample_sms_request())
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "DENY"
        assert data["risk_score"] == 100.0
        assert any("REPUTATION_BLACKLIST_MATCH" in r for r in data["reasons"])
        assert any("VELOCITY_IP_EXCEEDED" in r for r in data["reasons"])
        assert any("GEO_HIGH_RISK_MCC" in r for r in data["reasons"])
    finally:
        await orchestrator._client.aclose()  # type: ignore[union-attr]
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_rules_ttl_cache_avoids_redundant_calls():
    """Second scoring call within TTL serves rules from cache without hitting Rule Engine again."""
    call_log: list[tuple[str, str, str | None]] = []
    orchestrator = _build_mock_orchestrator(call_log=call_log)
    publisher, _ = _build_fake_publisher(connected=True)

    app.dependency_overrides[get_orchestrator] = lambda: orchestrator
    app.dependency_overrides[get_publisher] = lambda: publisher
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r1 = await client.post("/api/v1/score", json=_sample_sms_request())
            r2 = await client.post("/api/v1/score", json=_sample_sms_request())
        assert r1.status_code == 200 and r2.status_code == 200

        rule_calls = [u for _, u, _ in call_log if "/api/v1/rules" in u]
        rep_calls = [u for _, u, _ in call_log if "/api/v1/reputation/check" in u]
        vel_calls = [u for _, u, _ in call_log if "/api/v1/velocity/hit" in u]

        assert len(rule_calls) == 1
        assert len(rep_calls) == 2
        assert len(vel_calls) == 2
    finally:
        await orchestrator._client.aclose()  # type: ignore[union-attr]
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_graceful_degradation_when_downstreams_and_broker_fail():
    """Downstream timeouts and RabbitMQ publish failures do not crash the scoring response."""
    orchestrator = _build_mock_orchestrator(
        reputation_payload={
            "is_blacklisted": True,
            "matched_entities": [
                {"type": "IP", "value": "198.51.100.24", "reason": "Known bad actor"}
            ],
        },
        fail_rule_engine=True,
        fail_velocity=True,
    )
    publisher, _ = _build_fake_publisher(
        connected=True,
        fail_publish=RuntimeError("Broker channel closed"),
    )

    app.dependency_overrides[get_orchestrator] = lambda: orchestrator
    app.dependency_overrides[get_publisher] = lambda: publisher
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/score", json=_sample_sms_request())
        assert resp.status_code == 200
        data = resp.json()
        # Fallback rules still catch the blacklisted IP cleanly!
        assert data["verdict"] == "DENY"
        assert data["risk_score"] == 100.0
    finally:
        await orchestrator._client.aclose()  # type: ignore[union-attr]
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_score_validation_error_returns_422_envelope():
    """Invalid SMSCheckRequest returns standardized 422 ErrorEnvelope without stack trace."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/score",
            headers={"X-Request-ID": "score-val-err-1"},
            json={
                "client_ip": "198.51.100.24",
                "phone_number": "24101234567",  # Missing '+' for E.164
                "mcc_mnc": "62801",
                "message_length": 20,
            },
        )
    assert resp.status_code == 422
    err = resp.json()
    assert err["error_code"] == "VALIDATION_ERROR"
    assert err["request_id"] == "score-val-err-1"
