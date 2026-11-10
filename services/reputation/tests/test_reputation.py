"""
Unit and integration tests for the Reputation Service.
Covers BlacklistedEntity persistence, pre-seeded bad actors, check/blacklist APIs,
structured JSON logging with X-Request-ID propagation, and health/readiness probes.
"""

from __future__ import annotations

import importlib.util
import io
import json
import logging
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Resolve repository and service roots
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


_load_service_package("reputation_src", service_root / "src")

from reputation_src.crud import seed_mock_bad_actors  # noqa: E402
from reputation_src.database import get_db  # noqa: E402
from reputation_src.main import app, logger as service_logger  # noqa: E402
from reputation_src.models import Base  # noqa: E402
from shared.schemas import CommonJSONFormatter  # noqa: E402

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
async def test_session():
    """Provides an isolated in-memory SQLite session pre-seeded with mock bad actors."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        await seed_mock_bad_actors(session)
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def client(test_session: AsyncSession):
    """Async test HTTP client overriding DB dependency."""
    async def override_get_db():
        yield test_session

    app.dependency_overrides[get_db] = override_get_db
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
    assert data["service"] == "service-reputation"
    assert "X-Request-ID" in response.headers


@pytest.mark.asyncio
async def test_structured_json_logging_extracts_request_id(client: AsyncClient):
    """Logs emitted during a request must be structured JSON containing extracted X-Request-ID."""
    buffer = io.StringIO()
    capture_handler = logging.StreamHandler(buffer)
    capture_handler.setFormatter(CommonJSONFormatter(service_name="service-reputation"))
    service_logger.addHandler(capture_handler)

    try:
        custom_req_id = "req-reputation-trace-777"
        response = await client.post(
            "/api/v1/reputation/check",
            headers={"X-Request-ID": custom_req_id},
            json={"ip": "203.0.113.10"},
        )
        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == custom_req_id
    finally:
        service_logger.removeHandler(capture_handler)

    log_lines = [line for line in buffer.getvalue().strip().splitlines() if line.strip()]
    assert len(log_lines) >= 2

    parsed_records = [json.loads(line) for line in log_lines]
    for record in parsed_records:
        assert set(["timestamp", "service", "level", "request_id", "message"]).issubset(record.keys())
        assert record["service"] == "service-reputation"
        assert record["request_id"] == custom_req_id


@pytest.mark.asyncio
async def test_check_preseeded_mock_bad_actors(client: AsyncClient):
    """POST /api/v1/reputation/check detects pre-seeded IP 198.51.100.24 and MCC_MNC 62801."""
    response = await client.post(
        "/api/v1/reputation/check",
        json={
            "ip": "198.51.100.24",
            "phone": "+15550001234",
            "mcc_mnc": "62801",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_blacklisted"] is True
    assert data["checked_entities_count"] == 3
    assert len(data["matched_entities"]) == 2

    matched_by_type = {item["type"]: item for item in data["matched_entities"]}
    assert matched_by_type["IP"]["value"] == "198.51.100.24"
    assert "id" in matched_by_type["IP"]
    assert "created_at" in matched_by_type["IP"]
    assert "reason" in matched_by_type["IP"]

    assert matched_by_type["MCC_MNC"]["value"] == "62801"
    assert "Gabon" in matched_by_type["MCC_MNC"]["reason"]


@pytest.mark.asyncio
async def test_check_clean_entities(client: AsyncClient):
    """POST /api/v1/reputation/check returns is_blacklisted=False for clean traffic."""
    response = await client.post(
        "/api/v1/reputation/check",
        json={
            "ip": "203.0.113.5",
            "phone": "+14155552671",
            "mcc_mnc": "310260",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_blacklisted"] is False
    assert data["matched_entities"] == []
    assert data["checked_entities_count"] == 3


@pytest.mark.asyncio
async def test_check_explicit_entities_list(client: AsyncClient):
    """POST /api/v1/reputation/check accepts explicit entities list format."""
    response = await client.post(
        "/api/v1/reputation/check",
        json={
            "entities": [
                {"entity_type": "IP", "entity_val": "198.51.100.24"},
                {"entity_type": "MCC_MNC", "entity_val": "310260"},
            ]
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_blacklisted"] is True
    assert data["checked_entities_count"] == 2
    assert len(data["matched_entities"]) == 1
    assert data["matched_entities"][0]["value"] == "198.51.100.24"


@pytest.mark.asyncio
async def test_add_to_blacklist_and_check_match(client: AsyncClient):
    """POST /api/v1/reputation/blacklist adds a new entity which is then flagged on check."""
    add_payload = {
        "entity_type": "PHONE",
        "entity_val": "+24101234567",
        "reason": "High-cost Gabon premium AIT destination",
    }
    create_resp = await client.post("/api/v1/reputation/blacklist", json=add_payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["id"] is not None
    assert created["entity_type"] == "PHONE"
    assert created["entity_val"] == "+24101234567"
    assert created["reason"] == add_payload["reason"]
    assert "created_at" in created

    # Verify immediate match via check endpoint
    check_resp = await client.post(
        "/api/v1/reputation/check",
        json={"phone": "+24101234567"},
    )
    assert check_resp.status_code == 200
    check_data = check_resp.json()
    assert check_data["is_blacklisted"] is True
    assert len(check_data["matched_entities"]) == 1
    assert check_data["matched_entities"][0]["type"] == "PHONE"
    assert check_data["matched_entities"][0]["value"] == "+24101234567"

    # Verify listing filter
    list_resp = await client.get("/api/v1/reputation/blacklist", params={"entity_type": "PHONE"})
    assert list_resp.status_code == 200
    assert any(item["entity_val"] == "+24101234567" for item in list_resp.json())


@pytest.mark.asyncio
async def test_add_duplicate_blacklist_conflict(client: AsyncClient):
    """POST /api/v1/reputation/blacklist returns 409 Conflict for duplicate entities."""
    payload = {
        "entity_type": "IP",
        "entity_val": "198.51.100.24",
        "reason": "Duplicate test",
    }
    response = await client.post("/api/v1/reputation/blacklist", json=payload)
    assert response.status_code == 409
    err = response.json()
    assert err["error_code"] == "HTTP_ERROR"
    assert "already blacklisted" in err["message"]


@pytest.mark.asyncio
async def test_blacklist_and_check_validation_errors(client: AsyncClient):
    """Invalid IP format or empty check payload returns standardized 422 envelope."""
    bad_ip_resp = await client.post(
        "/api/v1/reputation/blacklist",
        headers={"X-Request-ID": "val-err-1"},
        json={
            "entity_type": "IP",
            "entity_val": "999.999.999.999",
            "reason": "Invalid IP test",
        },
    )
    assert bad_ip_resp.status_code == 422
    err = bad_ip_resp.json()
    assert err["error_code"] == "VALIDATION_ERROR"
    assert err["request_id"] == "val-err-1"

    empty_check_resp = await client.post("/api/v1/reputation/check", json={})
    assert empty_check_resp.status_code == 422
    assert empty_check_resp.json()["error_code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_ready_endpoint_healthy(client: AsyncClient, monkeypatch):
    """GET /ready returns 200 ready when database is reachable."""
    async def mock_ready():
        return True, 2, None

    monkeypatch.setattr("reputation_src.main.check_database_ready", mock_ready)
    response = await client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert data["blacklisted_count"] == 2


@pytest.mark.asyncio
async def test_ready_endpoint_unhealthy(client: AsyncClient, monkeypatch):
    """GET /ready returns 503 when database connectivity check fails."""
    async def mock_unready():
        return False, 0, "Connection refused"

    monkeypatch.setattr("reputation_src.main.check_database_ready", mock_unready)
    response = await client.get("/ready")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "error"
    assert data["database"] == "disconnected"
