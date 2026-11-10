"""
Unit and integration tests for the Velocity Service.
Verifies Redis Sorted Set sliding-window counting (60s IP / 300s phone),
graceful zero-count fallback with warning logs on timeouts/errors,
X-Request-ID correlation, and health/readiness endpoints.
"""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

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


_load_service_package("velocity_src", service_root / "src")

from shared.schemas import CommonJSONFormatter  # noqa: E402
from velocity_src.main import app, logger as service_logger  # noqa: E402
from velocity_src.redis_client import get_redis_client  # noqa: E402


class InMemoryPipeline:
    """Async context manager emulating Redis MULTI/EXEC pipeline for Sorted Sets."""

    def __init__(self, store: "InMemorySlidingWindowRedis") -> None:
        self._store = store
        self._commands: list[tuple[str, tuple[Any, ...]]] = []

    async def __aenter__(self) -> "InMemoryPipeline":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    def zremrangebyscore(self, key: str, min_score: str | float, max_score: float) -> "InMemoryPipeline":
        self._commands.append(("zremrangebyscore", (key, min_score, max_score)))
        return self

    def zadd(self, key: str, mapping: dict[str, float]) -> "InMemoryPipeline":
        self._commands.append(("zadd", (key, mapping)))
        return self

    def zcard(self, key: str) -> "InMemoryPipeline":
        self._commands.append(("zcard", (key,)))
        return self

    def expire(self, key: str, seconds: int) -> "InMemoryPipeline":
        self._commands.append(("expire", (key, seconds)))
        return self

    async def execute(self) -> list[Any]:
        if self._store.execute_error is not None:
            raise self._store.execute_error
        if self._store.execute_delay > 0:
            await asyncio.sleep(self._store.execute_delay)

        results: list[Any] = []
        for cmd, args in self._commands:
            if cmd == "zremrangebyscore":
                key, min_score, max_score = args
                zset = self._store.zsets.setdefault(key, {})
                low = float("-inf") if min_score == "-inf" else float(min_score)
                to_delete = [m for m, s in zset.items() if low <= s <= float(max_score)]
                for m in to_delete:
                    del zset[m]
                results.append(len(to_delete))
            elif cmd == "zadd":
                key, mapping = args
                zset = self._store.zsets.setdefault(key, {})
                added = 0
                for member, score in mapping.items():
                    if member not in zset:
                        added += 1
                    zset[member] = float(score)
                results.append(added)
            elif cmd == "zcard":
                (key,) = args
                results.append(len(self._store.zsets.get(key, {})))
            elif cmd == "expire":
                key, seconds = args
                self._store.expirations[key] = seconds
                results.append(True)
        return results


class InMemorySlidingWindowRedis:
    """In-memory async Redis stand-in supporting Sorted Sets, ping, and failure injection."""

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.expirations: dict[str, int] = {}
        self.ping_error: Exception | None = None
        self.execute_error: Exception | None = None
        self.execute_delay: float = 0.0

    def pipeline(self, transaction: bool = True) -> InMemoryPipeline:
        return InMemoryPipeline(self)

    async def ping(self) -> bool:
        if self.ping_error is not None:
            raise self.ping_error
        return True

    async def aclose(self) -> None:
        return None


@pytest.fixture
def fake_redis() -> InMemorySlidingWindowRedis:
    return InMemorySlidingWindowRedis()


@pytest.fixture
async def client(fake_redis: InMemorySlidingWindowRedis):
    """Async HTTP client overriding Redis client dependency."""
    app.dependency_overrides[get_redis_client] = lambda: fake_redis
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    """GET /health returns 200 ok with X-Request-ID header."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "service-velocity"
    assert "X-Request-ID" in response.headers


@pytest.mark.asyncio
async def test_ready_endpoint_healthy(client: AsyncClient):
    """GET /ready returns 200 when Redis responds to ping."""
    response = await client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["redis"] == "connected"


@pytest.mark.asyncio
async def test_ready_endpoint_unhealthy(client: AsyncClient, fake_redis: InMemorySlidingWindowRedis):
    """GET /ready returns 503 when Redis ping fails or times out."""
    fake_redis.ping_error = RedisConnectionError("Connection refused")
    response = await client.get("/ready")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "error"
    assert data["redis"] == "disconnected"


@pytest.mark.asyncio
async def test_sliding_window_expiration_semantics(
    client: AsyncClient,
    fake_redis: InMemorySlidingWindowRedis,
    monkeypatch,
):
    """
    Verifies sliding window durations:
    - client_ip expires after 60 seconds
    - phone_number retains hits for 300 seconds
    """
    current_ts = 1_700_000_000.0
    monkeypatch.setattr("velocity_src.redis_client.time.time", lambda: current_ts)

    payload = {"ip": "198.51.100.24", "phone": "+24101234567"}

    # Hit 1 at t=0s
    r1 = await client.post("/api/v1/velocity/hit", json=payload)
    assert r1.status_code == 200
    assert r1.json() == {"ip_count_1m": 1, "phone_count_5m": 1}

    # Hit 2 at t=+20s
    current_ts += 20.0
    r2 = await client.post("/api/v1/velocity/hit", json=payload)
    assert r2.status_code == 200
    assert r2.json() == {"ip_count_1m": 2, "phone_count_5m": 2}

    # Hit 3 at t=+70s: Hit 1 (>60s old) evicted from IP window, retained in 300s phone window
    current_ts += 50.0
    r3 = await client.post("/api/v1/velocity/hit", json=payload)
    assert r3.status_code == 200
    assert r3.json() == {"ip_count_1m": 2, "phone_count_5m": 3}

    # Hit 4 at t=+380s: all previous hits (>300s old) evicted from both windows
    current_ts += 310.0
    r4 = await client.post("/api/v1/velocity/hit", json=payload)
    assert r4.status_code == 200
    assert r4.json() == {"ip_count_1m": 1, "phone_count_5m": 1}

    # Verify Redis TTL expiration safeguards
    assert fake_redis.expirations["ip:198.51.100.24"] == 65
    assert fake_redis.expirations["phone:+24101234567"] == 305


@pytest.mark.asyncio
async def test_velocity_hit_field_aliases(client: AsyncClient):
    """POST /api/v1/velocity/hit accepts both (ip, phone) and (client_ip, phone_number)."""
    response = await client.post(
        "/api/v1/velocity/hit",
        json={"client_ip": "203.0.113.9", "phone_number": "+14155552671"},
    )
    assert response.status_code == 200
    assert response.json() == {"ip_count_1m": 1, "phone_count_5m": 1}


@pytest.mark.asyncio
async def test_graceful_fallback_on_redis_timeout_and_warning_log(
    client: AsyncClient,
    fake_redis: InMemorySlidingWindowRedis,
):
    """Redis timeout falls back safely to (0, 0) and emits a WARNING JSON log with request_id."""
    fake_redis.execute_error = RedisTimeoutError("Timeout reading from socket")

    buffer = io.StringIO()
    capture_handler = logging.StreamHandler(buffer)
    capture_handler.setFormatter(CommonJSONFormatter(service_name="service-velocity"))
    service_logger.addHandler(capture_handler)

    try:
        resp = await client.post(
            "/api/v1/velocity/hit",
            headers={"X-Request-ID": "vel-timeout-999"},
            json={"ip": "198.51.100.24", "phone": "+24101234567"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"ip_count_1m": 0, "phone_count_5m": 0}
        assert resp.headers["X-Request-ID"] == "vel-timeout-999"
    finally:
        service_logger.removeHandler(capture_handler)

    parsed_logs = [json.loads(line) for line in buffer.getvalue().strip().splitlines() if line.strip()]
    warning_logs = [log for log in parsed_logs if log["level"] == "WARNING"]
    assert len(warning_logs) >= 1
    assert warning_logs[0]["request_id"] == "vel-timeout-999"
    assert "falling back to safe zero-count" in warning_logs[0]["message"]


@pytest.mark.asyncio
async def test_graceful_fallback_on_slow_redis_operation(
    client: AsyncClient,
    fake_redis: InMemorySlidingWindowRedis,
    monkeypatch,
):
    """Slow Redis operation exceeding REDIS_OPERATION_TIMEOUT triggers asyncio.TimeoutError fallback."""
    monkeypatch.setattr("velocity_src.redis_client.settings.REDIS_OPERATION_TIMEOUT", 0.05)
    fake_redis.execute_delay = 0.2

    resp = await client.post(
        "/api/v1/velocity/hit",
        json={"ip": "198.51.100.24", "phone": "+24101234567"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ip_count_1m": 0, "phone_count_5m": 0}


@pytest.mark.asyncio
async def test_graceful_fallback_when_redis_unavailable():
    """When Redis client is None, endpoint still returns safe zero-counts."""
    app.dependency_overrides[get_redis_client] = lambda: None
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post(
                "/api/v1/velocity/hit",
                json={"ip": "198.51.100.24", "phone": "+24101234567"},
            )
            assert resp.status_code == 200
            assert resp.json() == {"ip_count_1m": 0, "phone_count_5m": 0}
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_velocity_validation_error(client: AsyncClient):
    """Invalid IP returns standardized 422 ErrorEnvelope without stack trace."""
    resp = await client.post(
        "/api/v1/velocity/hit",
        headers={"X-Request-ID": "vel-val-422"},
        json={"ip": "invalid-ip", "phone": "+24101234567"},
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["error_code"] == "VALIDATION_ERROR"
    assert data["request_id"] == "vel-val-422"
