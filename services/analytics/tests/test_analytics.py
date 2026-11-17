"""
Unit and integration tests for the Analytics Ingestion & Reporting Service.
Verifies ClickHouse MergeTree DDL, RabbitMQ batch consumer (50-item threshold
and time-based flush), manual ack/nack/reject reliability, last-hour summary
aggregation, and /health + /ready endpoints.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
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


_load_service_package("analytics_src", service_root / "src")

from analytics_src.consumer import AnalyticsConsumer  # noqa: E402
from analytics_src.main import app, get_consumer, get_storage  # noqa: E402
from analytics_src.storage import ClickHouseStorage, SMS_INSPECTIONS_COLUMNS  # noqa: E402


class FakeClickHouseClient:
    """In-memory stand-in for clickhouse-connect Client."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.inserted_batches: list[tuple[str, list[Any], list[str]]] = []
        self.query_rows: list[tuple[Any, ...]] = [(0, 0, 0, float("nan"), float("nan"))]
        self.ping_ok: bool = True
        self.ping_error: Exception | None = None
        self.insert_error: Exception | None = None
        self.query_error: Exception | None = None
        self.closed: bool = False

    def command(self, cmd: str) -> None:
        self.commands.append(cmd)

    def insert(self, table: str, data: list[Any], column_names: list[str]) -> None:
        if self.insert_error is not None:
            raise self.insert_error
        self.inserted_batches.append((table, list(data), list(column_names)))

    def query(self, query_str: str) -> Any:
        if self.query_error is not None:
            raise self.query_error
        return SimpleNamespace(result_rows=self.query_rows)

    def ping(self) -> bool:
        if self.ping_error is not None:
            raise self.ping_error
        return self.ping_ok

    def close(self) -> None:
        self.closed = True


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


def _make_event_bytes(verdict: str = "DENY", risk_score: float = 85.0) -> bytes:
    payload = {
        "event_id": str(uuid4()),
        "request_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": "198.51.100.24",
        "phone_number": "+24101234567",
        "mcc_mnc": "62801",
        "verdict": verdict,
        "risk_score": risk_score,
        "reasons": ["REPUTATION_BLACKLIST_MATCH: IP 198.51.100.24"],
        "latency_ms": 4.25,
    }
    return json.dumps(payload).encode("utf-8")


@pytest.mark.asyncio
async def test_clickhouse_schema_initialization_ddl():
    """connect_and_init creates MergeTree table sms_inspections with exact schema and ORDER BY."""
    fake_ch = FakeClickHouseClient()
    storage = ClickHouseStorage(database="analytics_db", client=fake_ch)
    await storage.connect_and_init()

    assert len(fake_ch.commands) == 1
    ddl = fake_ch.commands[0]
    assert "CREATE TABLE IF NOT EXISTS analytics_db.sms_inspections" in ddl
    assert "event_time DateTime" in ddl
    assert "request_id UUID" in ddl
    assert "client_ip String" in ddl
    assert "destination_phone String" in ddl
    assert "mcc_mnc LowCardinality(String)" in ddl
    assert "verdict LowCardinality(String)" in ddl
    assert "risk_score Float32" in ddl
    assert "latency_ms Float32" in ddl
    assert "reasons Array(String)" in ddl
    assert "ENGINE = MergeTree()" in ddl
    assert "ORDER BY (event_time, verdict, mcc_mnc)" in ddl


@pytest.mark.asyncio
async def test_consumer_flushes_at_50_items_batch_size():
    """Consumer buffers up to 49 messages and executes one batch INSERT of 50 rows on the 50th."""
    fake_ch = FakeClickHouseClient()
    storage = ClickHouseStorage(database="analytics_db", client=fake_ch)
    consumer = AnalyticsConsumer(storage=storage, batch_size=50, flush_interval=60.0)

    messages: list[FakeIncomingMessage] = []
    for idx in range(49):
        msg = FakeIncomingMessage(_make_event_bytes(), delivery_tag=idx + 1)
        messages.append(msg)
        await consumer.handle_message(msg)  # type: ignore[arg-type]

    assert consumer.buffered_count == 49
    assert len(fake_ch.inserted_batches) == 0
    assert all(not m.acked for m in messages)

    # 50th message triggers immediate flush
    msg_50 = FakeIncomingMessage(_make_event_bytes(verdict="ALLOW", risk_score=0.0), delivery_tag=50)
    messages.append(msg_50)
    await consumer.handle_message(msg_50)  # type: ignore[arg-type]

    assert consumer.buffered_count == 0
    assert len(fake_ch.inserted_batches) == 1
    table, rows, columns = fake_ch.inserted_batches[0]
    assert table == "analytics_db.sms_inspections"
    assert columns == SMS_INSPECTIONS_COLUMNS
    assert len(rows) == 50
    assert all(m.acked for m in messages)


@pytest.mark.asyncio
async def test_consumer_periodic_timer_flush():
    """Buffered events smaller than batch_size flush automatically on the periodic timer."""
    fake_ch = FakeClickHouseClient()
    storage = ClickHouseStorage(database="analytics_db", client=fake_ch)
    consumer = AnalyticsConsumer(storage=storage, batch_size=50, flush_interval=0.05)

    consumer._running = True
    consumer._flush_task = asyncio.create_task(consumer._periodic_flush_loop())
    try:
        msgs = [FakeIncomingMessage(_make_event_bytes(), delivery_tag=i) for i in range(3)]
        for msg in msgs:
            await consumer.handle_message(msg)  # type: ignore[arg-type]

        assert consumer.buffered_count == 3
        await asyncio.sleep(0.12)

        assert consumer.buffered_count == 0
        assert len(fake_ch.inserted_batches) == 1
        assert len(fake_ch.inserted_batches[0][1]) == 3
        assert all(m.acked for m in msgs)
    finally:
        await consumer.stop()


@pytest.mark.asyncio
async def test_consumer_nacks_on_clickhouse_failure():
    """ClickHouse insert error nacks all messages in the batch with requeue=True."""
    fake_ch = FakeClickHouseClient()
    fake_ch.insert_error = RuntimeError("ClickHouse connection lost")
    storage = ClickHouseStorage(database="analytics_db", client=fake_ch)
    consumer = AnalyticsConsumer(storage=storage, batch_size=2, flush_interval=60.0)

    m1 = FakeIncomingMessage(_make_event_bytes(), delivery_tag=1)
    m2 = FakeIncomingMessage(_make_event_bytes(), delivery_tag=2)
    await consumer.handle_message(m1)  # type: ignore[arg-type]
    await consumer.handle_message(m2)  # type: ignore[arg-type]

    assert consumer.buffered_count == 0
    assert m1.nacked is True and m1.nack_requeue is True
    assert m2.nacked is True and m2.nack_requeue is True
    assert not m1.acked and not m2.acked


@pytest.mark.asyncio
async def test_consumer_rejects_malformed_message():
    """Malformed JSON is rejected without requeue and does not enter the buffer."""
    fake_ch = FakeClickHouseClient()
    storage = ClickHouseStorage(database="analytics_db", client=fake_ch)
    consumer = AnalyticsConsumer(storage=storage, batch_size=50)

    bad_msg = FakeIncomingMessage(b"{invalid-json", delivery_tag=99)
    await consumer.handle_message(bad_msg)  # type: ignore[arg-type]

    assert bad_msg.rejected is True
    assert bad_msg.reject_requeue is False
    assert consumer.buffered_count == 0


@pytest.mark.asyncio
async def test_stats_summary_populated_and_empty_and_error():
    """GET /api/v1/stats/summary handles populated aggregates, empty/NaN results, and DB outage."""
    fake_ch = FakeClickHouseClient()
    fake_ch.query_rows = [(100, 35, 65, 4.256, 38.5)]
    storage = ClickHouseStorage(database="analytics_db", client=fake_ch)
    consumer = AnalyticsConsumer(storage=storage)

    app.dependency_overrides[get_storage] = lambda: storage
    app.dependency_overrides[get_consumer] = lambda: consumer
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/stats/summary")
            assert resp.status_code == 200
            data = resp.json()
            assert data == {
                "window": "1h",
                "total": 100,
                "blocked": 35,
                "allowed": 65,
                "block_rate_pct": 35.0,
                "avg_latency_ms": 4.26,
                "avg_risk_score": 38.5,
            }

            # Empty table returning NaN from ClickHouse avg()
            fake_ch.query_rows = [(0, 0, 0, float("nan"), float("nan"))]
            empty_resp = await client.get("/api/v1/stats/summary")
            assert empty_resp.status_code == 200
            assert empty_resp.json()["total"] == 0
            assert empty_resp.json()["avg_latency_ms"] == 0.0
            assert empty_resp.json()["block_rate_pct"] == 0.0

            # ClickHouse query error -> 503 standardized ErrorEnvelope
            fake_ch.query_error = RuntimeError("ClickHouse unreachable")
            err_resp = await client.get("/api/v1/stats/summary")
            assert err_resp.status_code == 503
            assert err_resp.json()["error_code"] == "HTTP_ERROR"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_health_and_ready_endpoints():
    """GET /health returns 200; GET /ready verifies ClickHouse ping (200 vs 503)."""
    fake_ch = FakeClickHouseClient()
    storage = ClickHouseStorage(database="analytics_db", client=fake_ch)
    consumer = AnalyticsConsumer(storage=storage)

    app.dependency_overrides[get_storage] = lambda: storage
    app.dependency_overrides[get_consumer] = lambda: consumer
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"
            assert health.json()["service"] == "service-analytics"

            ready = await client.get("/ready")
            assert ready.status_code == 200
            assert ready.json()["status"] == "ready"
            assert ready.json()["clickhouse"] == "connected"

            fake_ch.ping_error = ConnectionError("ClickHouse connection refused")
            unready = await client.get("/ready")
            assert unready.status_code == 503
            assert unready.json()["status"] == "error"
            assert unready.json()["clickhouse"] == "disconnected"
    finally:
        app.dependency_overrides.clear()
