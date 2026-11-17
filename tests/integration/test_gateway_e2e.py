"""
End-to-end integration tests for the full A2P Anti-Fraud microservice topology.
Wires the real FastAPI applications together in-process via ASGI transport:
  API Gateway -> Scoring Service -> (Rule Engine + Reputation + Velocity)
              -> In-process RabbitMQ fanout -> (Analytics Consumer + Alerting Consumer)
"""

from __future__ import annotations

import base64
import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import aio_pika
import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _load_pkg(pkg_name: str, pkg_dir: Path) -> None:
    if pkg_name in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        pkg_dir / "__init__.py",
        submodule_search_locations=[str(pkg_dir)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)


_load_pkg("gateway_src", PROJECT_ROOT / "gateway" / "src")
_load_pkg("scoring_src", PROJECT_ROOT / "services" / "scoring" / "src")
_load_pkg("rule_engine_src", PROJECT_ROOT / "services" / "rule-engine" / "src")
_load_pkg("reputation_src", PROJECT_ROOT / "services" / "reputation" / "src")
_load_pkg("velocity_src", PROJECT_ROOT / "services" / "velocity" / "src")
_load_pkg("analytics_src", PROJECT_ROOT / "services" / "analytics" / "src")
_load_pkg("alerting_src", PROJECT_ROOT / "services" / "alerting" / "src")

from alerting_src.consumer import AlertingConsumer  # noqa: E402
from alerting_src.main import app as alerting_app, get_consumer as get_alert_consumer, get_storage as get_alert_storage  # noqa: E402
from alerting_src.storage import AlertAuditStorage  # noqa: E402
from analytics_src.consumer import AnalyticsConsumer  # noqa: E402
from analytics_src.main import app as analytics_app, get_consumer as get_analytics_consumer, get_storage as get_analytics_storage  # noqa: E402
from analytics_src.storage import ClickHouseStorage  # noqa: E402
from gateway_src.main import app as gateway_app, get_proxy  # noqa: E402
from gateway_src.proxy import GatewayProxyClient  # noqa: E402
from reputation_src.crud import seed_mock_bad_actors  # noqa: E402
from reputation_src.database import get_db as get_reputation_db  # noqa: E402
from reputation_src.main import app as reputation_app  # noqa: E402
from reputation_src.models import Base as ReputationBase  # noqa: E402
from rule_engine_src.crud import seed_default_rules_if_empty  # noqa: E402
from rule_engine_src.database import get_db as get_rules_db  # noqa: E402
from rule_engine_src.main import app as rule_engine_app  # noqa: E402
from rule_engine_src.models import Base as RulesBase  # noqa: E402
from scoring_src.clients import DownstreamOrchestrator  # noqa: E402
from scoring_src.main import app as scoring_app, get_orchestrator, get_publisher  # noqa: E402
from scoring_src.publisher import RabbitMQPublisher  # noqa: E402
from velocity_src.main import app as velocity_app  # noqa: E402
from velocity_src.redis_client import get_redis_client  # noqa: E402


class _InMemoryPipeline:
    def __init__(self, store: "_InMemoryRedis") -> None:
        self._store = store
        self._cmds: list[tuple[str, tuple[Any, ...]]] = []

    async def __aenter__(self) -> "_InMemoryPipeline":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    def zremrangebyscore(self, key: str, low: str | float, high: float) -> "_InMemoryPipeline":
        self._cmds.append(("zrem", (key, low, high)))
        return self

    def zadd(self, key: str, mapping: dict[str, float]) -> "_InMemoryPipeline":
        self._cmds.append(("zadd", (key, mapping)))
        return self

    def zcard(self, key: str) -> "_InMemoryPipeline":
        self._cmds.append(("zcard", (key,)))
        return self

    def expire(self, key: str, seconds: int) -> "_InMemoryPipeline":
        self._cmds.append(("expire", (key, seconds)))
        return self

    async def execute(self) -> list[Any]:
        results: list[Any] = []
        for cmd, args in self._cmds:
            if cmd == "zrem":
                key, low, high = args
                zset = self._store.zsets.setdefault(key, {})
                lo = float("-inf") if low == "-inf" else float(low)
                for m in [k for k, v in zset.items() if lo <= v <= float(high)]:
                    del zset[m]
                results.append(0)
            elif cmd == "zadd":
                key, mapping = args
                zset = self._store.zsets.setdefault(key, {})
                for k, v in mapping.items():
                    zset[k] = float(v)
                results.append(len(mapping))
            elif cmd == "zcard":
                (key,) = args
                results.append(len(self._store.zsets.get(key, {})))
            elif cmd == "expire":
                results.append(True)
        return results


class _InMemoryRedis:
    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}

    def pipeline(self, transaction: bool = True) -> _InMemoryPipeline:
        return _InMemoryPipeline(self)

    async def ping(self) -> bool:
        return True


class _InMemoryClickHouse:
    def __init__(self) -> None:
        self.rows: list[list[Any]] = []

    def command(self, cmd: str) -> None:
        return None

    def ping(self) -> bool:
        return True

    def insert(self, table: str, data: list[Any], column_names: list[str]) -> None:
        self.rows.extend(data)

    def query(self, query_str: str) -> Any:
        total = len(self.rows)
        blocked = sum(1 for r in self.rows if r[5] == "DENY")
        allowed = sum(1 for r in self.rows if r[5] == "ALLOW")
        avg_lat = sum(float(r[7]) for r in self.rows) / total if total else 0.0
        avg_risk = sum(float(r[6]) for r in self.rows) / total if total else 0.0
        return SimpleNamespace(result_rows=[(total, blocked, allowed, avg_lat, avg_risk)])


class _InProcessMessage:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.delivery_tag = 1
        self.acked = False

    async def ack(self) -> None:
        self.acked = True

    async def nack(self, requeue: bool = True) -> None:
        return None

    async def reject(self, requeue: bool = False) -> None:
        return None


class _InProcessFanoutExchange:
    """Delivers published RabbitMQ messages directly to Analytics and Alerting consumers."""

    def __init__(self, consumers: list[Any]) -> None:
        self.consumers = consumers
        self.published: list[tuple[aio_pika.Message, str]] = []

    async def publish(self, message: aio_pika.Message, routing_key: str) -> None:
        self.published.append((message, routing_key))
        for consumer in self.consumers:
            await consumer.handle_message(_InProcessMessage(message.body))


class _OpenStub:
    is_closed = False


class _MultiAppASGITransport(httpx.AsyncBaseTransport):
    """Routes internal service hostnames directly to their real FastAPI ASGI apps."""

    def __init__(self, host_to_app: dict[str, Any]) -> None:
        self._transports = {
            host: ASGITransport(app=target_app)
            for host, target_app in host_to_app.items()
        }

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        transport = self._transports.get(host)
        if transport is None:
            return httpx.Response(502, json={"error": f"Unknown host {host}"})
        return await transport.handle_async_request(request)

    async def aclose(self) -> None:
        for transport in self._transports.values():
            await transport.aclose()


@pytest.fixture
async def e2e_platform():
    """Spins up the entire 7-app platform in-process with isolated in-memory persistence."""
    # 1. Rule Engine DB (SQLite in-memory)
    rules_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    rules_session_maker = async_sessionmaker(rules_engine, expire_on_commit=False, class_=AsyncSession)
    async with rules_engine.begin() as conn:
        await conn.run_sync(RulesBase.metadata.create_all)
    async with rules_session_maker() as session:
        await seed_default_rules_if_empty(session)

    async def override_rules_db():
        async with rules_session_maker() as s:
            yield s
            await s.commit()

    # 2. Reputation DB (SQLite in-memory, pre-seeded with 198.51.100.24 & 62801)
    rep_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    rep_session_maker = async_sessionmaker(rep_engine, expire_on_commit=False, class_=AsyncSession)
    async with rep_engine.begin() as conn:
        await conn.run_sync(ReputationBase.metadata.create_all)
    async with rep_session_maker() as session:
        await seed_mock_bad_actors(session)

    async def override_rep_db():
        async with rep_session_maker() as s:
            yield s
            await s.commit()

    # 3. Velocity Redis (in-memory sliding window)
    fake_redis = _InMemoryRedis()

    # 4. Analytics ClickHouse + Consumer (flush every 1 item for immediate E2E visibility)
    fake_ch = _InMemoryClickHouse()
    analytics_storage = ClickHouseStorage(database="analytics_db", client=fake_ch)
    analytics_consumer = AnalyticsConsumer(storage=analytics_storage, batch_size=1, flush_interval=60.0)

    # 5. Alerting SQLite + Consumer
    alert_storage = AlertAuditStorage(db_path=":memory:")
    await alert_storage.connect_and_init()
    alert_consumer = AlertingConsumer(storage=alert_storage)
    alert_consumer._connection = _OpenStub()  # type: ignore[assignment]
    alert_consumer._channel = _OpenStub()  # type: ignore[assignment]

    # 6. Scoring Publisher connected to in-process fanout -> Analytics & Alerting
    fanout_exchange = _InProcessFanoutExchange([analytics_consumer, alert_consumer])
    scoring_publisher = RabbitMQPublisher(exchange_name="antifraud.events", routing_key="inspection.completed")
    scoring_publisher._connection = _OpenStub()  # type: ignore[assignment]
    scoring_publisher._channel = _OpenStub()  # type: ignore[assignment]
    scoring_publisher._exchange = fanout_exchange  # type: ignore[assignment]

    # 7. Internal ASGI router for inter-service HTTP calls
    internal_transport = _MultiAppASGITransport(
        {
            "service-rule-engine": rule_engine_app,
            "service-reputation": reputation_app,
            "service-velocity": velocity_app,
            "service-scoring": scoring_app,
            "service-analytics": analytics_app,
            "service-alerting": alerting_app,
        }
    )
    internal_http_client = httpx.AsyncClient(transport=internal_transport)

    orchestrator = DownstreamOrchestrator(
        rule_engine_url="http://service-rule-engine:8001",
        reputation_url="http://service-reputation:8002",
        velocity_url="http://service-velocity:8003",
        rules_cache_ttl=30.0,
        http_client=internal_http_client,
    )
    gateway_proxy = GatewayProxyClient(
        scoring_url="http://service-scoring:8004",
        analytics_url="http://service-analytics:8005",
        rule_engine_url="http://service-rule-engine:8001",
        reputation_url="http://service-reputation:8002",
        alerting_url="http://service-alerting:8006",
        http_client=internal_http_client,
    )

    # Wire dependency overrides across all apps
    rule_engine_app.dependency_overrides[get_rules_db] = override_rules_db
    reputation_app.dependency_overrides[get_reputation_db] = override_rep_db
    velocity_app.dependency_overrides[get_redis_client] = lambda: fake_redis
    scoring_app.dependency_overrides[get_orchestrator] = lambda: orchestrator
    scoring_app.dependency_overrides[get_publisher] = lambda: scoring_publisher
    analytics_app.dependency_overrides[get_analytics_storage] = lambda: analytics_storage
    analytics_app.dependency_overrides[get_analytics_consumer] = lambda: analytics_consumer
    alerting_app.dependency_overrides[get_alert_storage] = lambda: alert_storage
    alerting_app.dependency_overrides[get_alert_consumer] = lambda: alert_consumer
    gateway_app.dependency_overrides[get_proxy] = lambda: gateway_proxy

    gateway_transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=gateway_transport, base_url="http://gateway") as client:
        yield client, fanout_exchange

    # Teardown
    for target_app in (
        gateway_app,
        scoring_app,
        rule_engine_app,
        reputation_app,
        velocity_app,
        analytics_app,
        alerting_app,
    ):
        target_app.dependency_overrides.clear()

    await internal_http_client.aclose()
    await alert_storage.close()
    await rules_engine.dispose()
    await rep_engine.dispose()


def _bearer_headers(request_id: str | None = None) -> dict[str, str]:
    headers = {"Authorization": "Bearer antifraud-demo-key"}
    if request_id:
        headers["X-Request-ID"] = request_id
    return headers


@pytest.mark.asyncio
async def test_gateway_rejects_unauthenticated_verify_request(e2e_platform):
    """Requests without valid API key or Basic credentials return 401 with X-Request-ID."""
    client, _ = e2e_platform
    resp = await client.post(
        "/api/v1/verify",
        json={
            "client_ip": "203.0.113.10",
            "phone_number": "+14155552671",
            "mcc_mnc": "310260",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_length": 24,
        },
    )
    assert resp.status_code == 401
    assert "X-Request-ID" in resp.headers
    assert UUID(resp.headers["X-Request-ID"])
    body = resp.json()
    assert body["error_code"] == "UNAUTHORIZED"
    assert body["request_id"] == resp.headers["X-Request-ID"]


@pytest.mark.asyncio
async def test_gateway_e2e_verify_allow_and_basic_auth(e2e_platform):
    """Clean SMS via Gateway returns ALLOW (0.0), generated UUID4 X-Request-ID, and records analytics."""
    client, exchange = e2e_platform

    basic_creds = base64.b64encode(b"antifraud:antifraud-secret").decode("ascii")
    resp = await client.post(
        "/api/v1/verify",
        headers={"Authorization": f"Basic {basic_creds}"},
        json={
            "client_ip": "203.0.113.15",
            "phone_number": "+14155550199",
            "mcc_mnc": "310260",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_length": 32,
        },
    )
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers
    data = resp.json()
    assert data["verdict"] == "ALLOW"
    assert data["risk_score"] == 0.0
    assert data["reasons"] == []
    assert data["request_id"] == resp.headers["X-Request-ID"]
    assert UUID(data["request_id"])
    assert len(exchange.published) == 1


@pytest.mark.asyncio
async def test_gateway_e2e_verify_deny_triggers_alert_and_analytics(e2e_platform):
    """
    Full E2E flow for a bad actor (IP 198.51.100.24 + Gabon MCC_MNC 62801):
      1. POST /api/v1/verify -> verdict DENY, risk_score 100.0, correlated X-Request-ID
      2. Event published to 'antifraud.events' ('inspection.completed')
      3. GET /api/v1/alerts -> returns generated CRITICAL CEF security alert
      4. GET /api/v1/analytics/stats/summary -> reflects total=1, blocked=1
    """
    client, exchange = e2e_platform

    verify_resp = await client.post(
        "/api/v1/verify",
        headers=_bearer_headers(),
        json={
            "client_ip": "198.51.100.24",
            "phone_number": "+24101234567",
            "mcc_mnc": "62801",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_length": 24,
        },
    )
    assert verify_resp.status_code == 200
    req_id = verify_resp.headers["X-Request-ID"]
    assert UUID(req_id)

    verdict_data = verify_resp.json()
    assert verdict_data["request_id"] == req_id
    assert verdict_data["verdict"] == "DENY"
    assert verdict_data["risk_score"] == 100.0
    assert any("REPUTATION_BLACKLIST_MATCH" in r for r in verdict_data["reasons"])
    assert len(exchange.published) == 1
    assert exchange.published[0][1] == "inspection.completed"

    # Verify Alerting Service generated and persisted a CRITICAL CEF alert
    alerts_resp = await client.get("/api/v1/alerts", headers=_bearer_headers())
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) == 1
    assert alerts[0]["request_id"] == req_id
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["cef_message"].startswith("CEF:0|AntifraudPlatform|A2PSecurityGuard|1.0|AF-CRIT-001|")

    # Verify Analytics Service ingested the event and serves summary via Gateway
    stats_resp = await client.get("/api/v1/analytics/stats/summary", headers=_bearer_headers())
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total"] == 1
    assert stats["blocked"] == 1
    assert stats["block_rate_pct"] == 100.0


@pytest.mark.asyncio
async def test_gateway_e2e_velocity_spike_and_rules_routing(e2e_platform):
    """
    Verifies Gateway routing to /api/v1/rules and end-to-end Redis velocity escalation:
    11th request from same clean IP exceeds threshold (>10 req/min) -> risk_score 40.0.
    """
    client, _ = e2e_platform

    # Verify /api/v1/rules proxy
    rules_resp = await client.get("/api/v1/rules", headers=_bearer_headers())
    assert rules_resp.status_code == 200
    assert len(rules_resp.json()) == 3

    # Send 11 requests from same clean IP
    last_data: dict[str, Any] = {}
    for idx in range(11):
        resp = await client.post(
            "/api/v1/verify",
            headers=_bearer_headers(),
            json={
                "client_ip": "192.0.2.55",
                "phone_number": f"+141555501{idx:02d}",
                "mcc_mnc": "310260",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message_length": 20,
            },
        )
        assert resp.status_code == 200
        last_data = resp.json()

    assert last_data["verdict"] == "ALLOW"
    assert last_data["risk_score"] == 40.0
    assert any("VELOCITY_IP_EXCEEDED" in r for r in last_data["reasons"])

    # Verify Gateway /ready reports all downstream services healthy
    ready_resp = await client.get("/ready")
    assert ready_resp.status_code == 200
    ready_data = ready_resp.json()
    assert ready_data["status"] == "ready"
    assert ready_data["downstreams"]["scoring"] == "ok"
    assert ready_data["downstreams"]["rule_engine"] == "ok"
    assert ready_data["downstreams"]["analytics"] == "ok"
    assert ready_data["downstreams"]["alerting"] == "ok"
