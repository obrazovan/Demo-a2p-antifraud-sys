"""
Unit and integration tests for Rule Engine Service.
Tests models, endpoints, auto-seeding, and validation.
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Setup python path
current_dir = Path(__file__).resolve().parent
service_root = current_dir.parent
project_root = service_root.parent.parent

if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from src.database import get_db
from src.main import app
from src.models import Base, MetricType, Rule
from src.crud import seed_default_rules_if_empty

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
async def test_session():
    """Provides an isolated in-memory SQLite database session for testing."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        # Pre-seed default rules to verify startup behavior
        await seed_default_rules_if_empty(session)
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def client(test_session: AsyncSession):
    """Async test HTTP client with overridden get_db dependency."""
    async def override_get_db():
        yield test_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    """GET /health must return 200 with status 'ok' immediately."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "service-rule-engine"
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_auto_seed_and_get_rules(client: AsyncClient):
    """GET /api/v1/rules should return the 3 auto-seeded default rules."""
    response = await client.get("/api/v1/rules")
    assert response.status_code == 200
    rules = response.json()
    assert len(rules) == 3

    rule_names = [r["name"] for r in rules]
    assert "High velocity IP (>10 req/min)" in rule_names
    assert "High velocity Destination (>30 req/min)" in rule_names
    assert "Blacklisted prefix/IP" in rule_names

    # Check rule weights
    rule_map = {r["name"]: r for r in rules}
    assert rule_map["High velocity IP (>10 req/min)"]["weight"] == 40.0
    assert rule_map["High velocity IP (>10 req/min)"]["threshold_val"] == 10.0
    assert rule_map["High velocity IP (>10 req/min)"]["metric_type"] == "VELOCITY"

    assert rule_map["High velocity Destination (>30 req/min)"]["weight"] == 50.0
    assert rule_map["High velocity Destination (>30 req/min)"]["threshold_val"] == 30.0
    assert rule_map["High velocity Destination (>30 req/min)"]["metric_type"] == "VELOCITY"

    assert rule_map["Blacklisted prefix/IP"]["weight"] == 100.0
    assert rule_map["Blacklisted prefix/IP"]["metric_type"] == "REPUTATION"


@pytest.mark.asyncio
async def test_create_rule_success(client: AsyncClient):
    """POST /api/v1/rules should successfully create a new scoring rule."""
    payload = {
        "name": "RULE_SUSPICIOUS_GEO_COUNTRY",
        "metric_type": "GEO",
        "threshold_val": 0.0,
        "weight": 35.0,
        "is_active": True,
    }
    response = await client.post("/api/v1/rules", json=payload)
    assert response.status_code == 201
    created = response.json()
    assert created["id"] is not None
    assert created["name"] == payload["name"]
    assert created["metric_type"] == payload["metric_type"]
    assert created["weight"] == 35.0

    # Ensure rule is now in active list
    list_resp = await client.get("/api/v1/rules")
    assert any(r["name"] == "RULE_SUSPICIOUS_GEO_COUNTRY" for r in list_resp.json())


@pytest.mark.asyncio
async def test_create_duplicate_rule_conflict(client: AsyncClient):
    """POST /api/v1/rules should return 409 Conflict if rule name already exists."""
    payload = {
        "name": "High velocity IP (>10 req/min)",
        "metric_type": "VELOCITY",
        "threshold_val": 10.0,
        "weight": 40.0,
        "is_active": True,
    }
    response = await client.post("/api/v1/rules", json=payload)
    assert response.status_code == 409
    err = response.json()
    assert err["error_code"] == "HTTP_ERROR"
    assert "already exists" in err["message"]


@pytest.mark.asyncio
async def test_create_rule_invalid_validation(client: AsyncClient):
    """POST /api/v1/rules should return 422 for invalid payloads."""
    payload = {
        "name": "X",  # Too short (min length 2)
        "metric_type": "UNKNOWN_TYPE",  # Invalid enum value
        "weight": 150.0,  # Exceeds max 100.0
    }
    response = await client.post("/api/v1/rules", json=payload)
    assert response.status_code == 422
    err = response.json()
    assert err["error_code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_ready_endpoint_healthy(client: AsyncClient, monkeypatch):
    """GET /ready should return 200 when database connection is verified."""
    async def mock_ready():
        return True, 3, None

    monkeypatch.setattr("src.main.check_database_ready", mock_ready)
    response = await client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert data["rules_count"] == 3


@pytest.mark.asyncio
async def test_ready_endpoint_unhealthy(client: AsyncClient, monkeypatch):
    """GET /ready should return 503 when database is unreachable."""
    async def mock_unready():
        return False, 0, "Connection refused"

    monkeypatch.setattr("src.main.check_database_ready", mock_unready)
    response = await client.get("/ready")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "error"
    assert data["database"] == "disconnected"

