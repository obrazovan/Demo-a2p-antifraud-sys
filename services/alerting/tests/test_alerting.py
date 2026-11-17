"""
Unit and integration tests for the Alerting & Security Audit Service.
Verifies CEF alert formatting, DENY / risk_score >= 80.0 triggering rules,
structured WARNING/ERROR JSON logging, SQLite audit persistence, last-50
retrieval via GET /api/v1/alerts, and /health + /ready probes.
"""

from __future__ import annotations

import importlib.util
import io
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

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


_load_service_package("alerting_src", service_root / "src")

from alerting_src.consumer import AlertingConsumer  # noqa: E402
from alerting_src.main import app, get_consumer, get_storage, logger as service_logger  # noqa: E402
from alerting_src.storage import AlertAuditStorage  # noqa: E402
from shared.schemas import CommonJSONFormatter  # noqa: E402


class FakeConnectionOrChannel:
    """Stand-in exposing is_closed for RabbitMQ readiness checks."""

    def __init__(self, is_closed: bool = False) -> None:
        self.is_closed = is_closed


class FakeIncomingMessage:
    """Stand-in for aio_pika.abc.AbstractIncomingMessage tracking ack/nack/reject."""

    def __init__(self, body: bytes, delivery_tag: int = 1) -> None:
        self.body = body
        self.delivery_tag = delivery_tag
        self.acked: bool = False
        self.nacked: bool = False
        self.nack_requeue: bool | None = None
        self.rejected: bool = False
        self.reject_requeue: bool | None = None

    async def ack(self) -> None:
        self.acked = True

    async def nack(self, requeue: bool = True) -> None:
        self.nacked = True
        self.nack_requeue = requeue

    async def reject(self, requeue: bool = False) -> None:
        self.rejected = True
        self.reject_requeue = requeue


def _make_event_bytes(
    verdict: str = "DENY",
    risk_score: float = 85.0,
    request_id: str | None = None,
    reasons: list[str] | None = None,
) -> tuple[str, bytes]:
    req_id = request_id or str(uuid4())
    payload = {
        "event_id": str(uuid4()),
        "request_id": req_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": "198.51.100.24",
        "phone_number": "+24101234567",
        "mcc_mnc": "62801",
        "verdict": verdict,
        "risk_score": risk_score,
        "reasons": reasons if reasons is not None else ["REPUTATION_BLACKLIST_MATCH: IP 198.51.100.24"],
        "latency_ms": 3.8,
    }
    return req_id, json.dumps(payload).encode("utf-8")


@pytest.fixture
async def audit_storage():
    """Isolated in-memory SQLite audit database for testing."""
    storage = AlertAuditStorage(db_path=":memory:")
    await storage.connect_and_init()
    yield storage
    await storage.close()


@pytest.mark.asyncio
async def test_allow_low_risk_event_skipped(audit_storage: AlertAuditStorage):
    """ALLOW events with risk_score < 80.0 are acked without creating a security alert."""
    consumer = AlertingConsumer(storage=audit_storage)
    _, body = _make_event_bytes(verdict="ALLOW", risk_score=20.0, reasons=[])
    msg = FakeIncomingMessage(body)

    await consumer.handle_message(msg)  # type: ignore[arg-type]

    assert msg.acked is True
    alerts = await audit_storage.get_recent_alerts(limit=50)
    assert alerts == []


@pytest.mark.asyncio
async def test_deny_moderate_risk_creates_cef_warning_alert(audit_storage: AlertAuditStorage):
    """DENY with risk_score < 80.0 creates HIGH CEF alert and emits structured WARNING log."""
    consumer = AlertingConsumer(storage=audit_storage)
    req_id, body = _make_event_bytes(
        verdict="DENY",
        risk_score=65.0,
        reasons=["VELOCITY_IP_EXCEEDED: count=15 > 10"],
    )
    msg = FakeIncomingMessage(body)

    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(CommonJSONFormatter(service_name="service-alerting"))
    service_logger.addHandler(handler)
    try:
        await consumer.handle_message(msg)  # type: ignore[arg-type]
    finally:
        service_logger.removeHandler(handler)

    assert msg.acked is True
    alerts = await audit_storage.get_recent_alerts(limit=50)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity.value == "HIGH"
    assert str(alert.request_id) == req_id
    assert alert.cef_message.startswith(
        "CEF:0|AntifraudPlatform|A2PSecurityGuard|1.0|AF-DENY-001|SMS Authentication Traffic Blocked|7|"
    )
    assert "src=198.51.100.24" in alert.cef_message
    assert "cn1=65.00" in alert.cef_message
    assert f"externalId={req_id}" in alert.cef_message
    # Escaped '=' inside extension message
    assert "count\\=15" in alert.cef_message

    parsed_logs = [json.loads(line) for line in buffer.getvalue().strip().splitlines() if line.strip()]
    warning_logs = [entry for entry in parsed_logs if entry["level"] == "WARNING"]
    assert len(warning_logs) == 1
    assert warning_logs[0]["request_id"] == req_id
    assert warning_logs[0]["message"].startswith("CEF:0|")


@pytest.mark.asyncio
async def test_critical_risk_ge_80_creates_cef_error_alert(audit_storage: AlertAuditStorage):
    """Events with risk_score >= 80.0 (even regardless of verdict) trigger CRITICAL CEF + ERROR log."""
    consumer = AlertingConsumer(storage=audit_storage)
    req_id, body = _make_event_bytes(verdict="ALLOW", risk_score=85.0)
    msg = FakeIncomingMessage(body)

    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(CommonJSONFormatter(service_name="service-alerting"))
    service_logger.addHandler(handler)
    try:
        await consumer.handle_message(msg)  # type: ignore[arg-type]
    finally:
        service_logger.removeHandler(handler)

    assert msg.acked is True
    alerts = await audit_storage.get_recent_alerts(limit=50)
    assert len(alerts) == 1
    assert alerts[0].severity.value == "CRITICAL"
    assert alerts[0].cef_message.startswith(
        "CEF:0|AntifraudPlatform|A2PSecurityGuard|1.0|AF-CRIT-001|Critical SMS Fraud Risk Detected|9|"
    )

    parsed_logs = [json.loads(line) for line in buffer.getvalue().strip().splitlines() if line.strip()]
    error_logs = [entry for entry in parsed_logs if entry["level"] == "ERROR"]
    assert len(error_logs) == 1
    assert error_logs[0]["request_id"] == req_id
    assert "AF-CRIT-001" in error_logs[0]["message"]


@pytest.mark.asyncio
async def test_get_alerts_returns_last_50_newest_first_and_filters(audit_storage: AlertAuditStorage):
    """GET /api/v1/alerts returns last 50 alerts ordered newest first and supports severity filter."""
    consumer = AlertingConsumer(storage=audit_storage)
    for idx in range(55):
        score = 95.0 if idx % 2 == 0 else 65.0
        _, body = _make_event_bytes(verdict="DENY", risk_score=score)
        msg = FakeIncomingMessage(body, delivery_tag=idx + 1)
        await consumer.handle_message(msg)  # type: ignore[arg-type]

    app.dependency_overrides[get_storage] = lambda: audit_storage
    app.dependency_overrides[get_consumer] = lambda: consumer
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/alerts")
            assert resp.status_code == 200
            alerts = resp.json()
            assert len(alerts) == 50
            # Newest first -> IDs strictly descending from 55 down to 6
            assert alerts[0]["id"] == 55
            assert alerts[-1]["id"] == 6

            crit_resp = await client.get("/api/v1/alerts", params={"severity": "CRITICAL"})
            assert crit_resp.status_code == 200
            crit_alerts = crit_resp.json()
            assert len(crit_alerts) > 0
            assert all(a["severity"] == "CRITICAL" for a in crit_alerts)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_malformed_message_rejected_and_storage_error_nacked(audit_storage: AlertAuditStorage):
    """Malformed JSON is rejected (requeue=False); DB failure nacks (requeue=True)."""
    consumer = AlertingConsumer(storage=audit_storage)

    bad_msg = FakeIncomingMessage(b"not-valid-json", delivery_tag=1)
    await consumer.handle_message(bad_msg)  # type: ignore[arg-type]
    assert bad_msg.rejected is True and bad_msg.reject_requeue is False

    # Close storage so save_alert fails
    await audit_storage.close()
    _, body = _make_event_bytes(verdict="DENY", risk_score=90.0)
    retry_msg = FakeIncomingMessage(body, delivery_tag=2)
    await consumer.handle_message(retry_msg)  # type: ignore[arg-type]
    assert retry_msg.nacked is True and retry_msg.nack_requeue is True
    assert not retry_msg.acked


@pytest.mark.asyncio
async def test_health_and_ready_endpoints(audit_storage: AlertAuditStorage):
    """GET /health returns 200; GET /ready verifies both SQLite and RabbitMQ consumer."""
    consumer = AlertingConsumer(storage=audit_storage)
    consumer._connection = FakeConnectionOrChannel(is_closed=False)  # type: ignore[assignment]
    consumer._channel = FakeConnectionOrChannel(is_closed=False)  # type: ignore[assignment]

    app.dependency_overrides[get_storage] = lambda: audit_storage
    app.dependency_overrides[get_consumer] = lambda: consumer
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"
            assert health.json()["service"] == "service-alerting"

            ready = await client.get("/ready")
            assert ready.status_code == 200
            ready_data = ready.json()
            assert ready_data["status"] == "ready"
            assert ready_data["database"] == "connected"
            assert ready_data["rabbitmq"] == "connected"

            # Simulate RabbitMQ disconnect
            consumer._connection = FakeConnectionOrChannel(is_closed=True)  # type: ignore[assignment]
            unready = await client.get("/ready")
            assert unready.status_code == 503
            unready_data = unready.json()
            assert unready_data["status"] == "error"
            assert unready_data["rabbitmq"] == "disconnected"
    finally:
        app.dependency_overrides.clear()
