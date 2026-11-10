# Demo A2P Anti-Fraud System (`Demo-a2p-antifraud-sys`)

A distributed microservice platform for preventive A2P SMS authentication traffic inspection, designed to detect and mitigate SMS Pumping / Artificial Inflation of Traffic (AIT) and Denial of Wallet attacks.

See [`system_architecture_specification.md`](./system_architecture_specification.md) for the complete technical architecture and service boundaries.

---

## Architecture & Tech Stack

- **Language & API:** Python 3.11+, FastAPI, Pydantic v2
- **Databases & Storage (Database-per-Service):**
  - **PostgreSQL 15** (`rules_db` on port `5432`, `reputation_db` on port `5433`) via SQLAlchemy 2.0 + `asyncpg`
  - **Redis 7** (port `6379`) for high-speed sliding-window velocity counters
  - **ClickHouse 23.8** (ports `8123`, `9000`) for OLAP inspection analytics (`analytics_db`)
- **Message Broker:** RabbitMQ 3 Management (AMQP `5672`, UI `15672`)
- **Observability:** Structured single-line JSON logs with `X-Request-ID` correlation (`shared/logger.py`), dedicated `/health` and `/ready` probes on every service.

---

## Implementation Progress

| Stage | Component | Status | Port | Notes |
| :---: | :--- | :---: | :---: | :--- |
| 1 | Infrastructure & Shared DTOs | Implemented | — | `docker-compose.yml`, `antifraud-net`, SQL init scripts, `shared/schemas.py`, `shared/logger.py` |
| 2 | **Rule Engine Service** | Implemented | `8001` | FastAPI, asyncpg (`rules_db`), startup seed rules, `/api/v1/rules`, multi-stage Dockerfile, tests |
| 3 | Reputation Service | Planned | `8002` | Blacklist management & fast lookup (`reputation_db`) |
| 4 | Velocity Service | Planned | `8003` | Redis sliding-window rate counters |
| 5 | Scoring Engine Service | Planned | `8004` | Parallel orchestration + RabbitMQ event publishing |
| 6 | Analytics & Alerting Services | Planned | `8005` / `8006` | RabbitMQ consumers, ClickHouse bulk ingest, CEF audit alerts |
| 7 | API Gateway & E2E Tests | Planned | `8080` | Ingress auth, `X-Request-ID` injection, routing |

---

## Repository Structure

```text
.
├── .github/workflows/          # CI pipelines (Compose validation & pytest)
├── gateway/                    # API Gateway (planned)
├── infrastructure/             # Database initialization SQL scripts
│   ├── clickhouse/
│   ├── postgres-reputation/
│   └── postgres-rules/
├── services/
│   ├── rule-engine/            # Rule Engine microservice (FastAPI + PostgreSQL)
│   ├── reputation/             # Reputation microservice (planned)
│   ├── velocity/               # Velocity microservice (planned)
│   ├── scoring/                # Scoring Engine microservice (planned)
│   ├── analytics/              # Analytics consumer & reporting (planned)
│   └── alerting/               # Security Alerting consumer (planned)
├── shared/                     # Shared Pydantic DTOs & structured JSON logger
├── tests/                      # Cross-service unit & integration tests
├── docker-compose.yml          # Local & container orchestration
├── Makefile                    # Common dev/test shortcuts
└── system_architecture_specification.md
```

---

## Quick Start

### 1. Configure Environment
```bash
cp .env.example .env
```

### 2. Start Infrastructure & Implemented Services
```bash
docker compose up -d --build
docker compose ps
```

### 3. Verify Rule Engine Service
- Liveness check: `GET http://localhost:8001/health`
- Readiness check (verifies PostgreSQL `rules_db`): `GET http://localhost:8001/ready`
- Swagger UI: `http://localhost:8001/docs`
- Active scoring rules: `GET http://localhost:8001/api/v1/rules`

---

## Running Tests

Install Rule Engine dependencies and run the test suite:

```bash
pip install -r services/rule-engine/requirements.txt
python -m pytest -v
```

Validate Docker Compose configuration:

```bash
docker compose config -q
```

---

## Git Workflow

This repository follows **Conventional Commits** (`feat(...)`, `fix(...)`, `chore(...)`, `docs(...)`, `test(...)`) with each implementation stage committed cleanly as atomic milestones on `main`.
