# Architecture & Technical Specification: A2P Anti-Fraud Platform

This document serves as the **Single Source of Truth (SSOT)** for the distributed microservice system designed for preventive SMS authentication traffic inspection, mitigating Denial of Wallet (AIT / SMS Pumping) attacks.

---

## 1. System Overview & Topology

The platform acts as an in-line security proxy between client authentication forms (e-commerce, banking, services) and upstream telecommunication SMS gateways.

```
                                [ Client / API Consumer ]
                                           │
                                           │ HTTP POST /api/v1/verify
                                           ▼
                                 ┌───────────────────┐
                                 │    API Gateway    │ (Port 8080)
                                 └─────────┬─────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        │ REST (Internal)                     │
                        ▼                                     ▼
             ┌─────────────────────┐               ┌─────────────────────┐
             │   Scoring Engine    │ (Port 8004)   │  Analytics Service  │ (Port 8005)
             └──────────┬──────────┘               └─────────────────────┘
                        │
       ┌────────────────┴────────────────┬────────────────────────────────┐
       │ Synchronous REST                │ Synchronous REST               │ Synchronous REST
       ▼                                 ▼                                ▼
┌──────────────┐                  ┌──────────────┐                 ┌──────────────┐
│ Rule Engine  │ (Port 8001)      │  Reputation  │ (Port 8002)     │   Velocity   │ (Port 8003)
│   Service    │                  │   Service    │                 │   Service    │
└──────┬───────┘                  └──────┬───────┘                 └──────┬───────┘
       │                                 │                                │
       ▼                                 ▼                                ▼
[rules_db:5432]                 [reputation_db:5433]                 [redis:6379]
 (PostgreSQL)                       (PostgreSQL)                        (In-Memory)

                        │
                        │ Async Event: inspection.completed
                        ▼
            ┌─────────────────────────────────────────┐
            │        RabbitMQ Exchange: antifraud     │ (AMQP: 5672, UI: 15672)
            └───────────┬─────────────────┬───────────┘
                        │                 │
     Queue: analytics.events              │ Queue: security.alerts
                        │                 │
                        ▼                 ▼
             ┌─────────────────────┐   ┌─────────────────────┐
             │  Analytics Ingest   │   │  Alerting & Audit   │ (Port 8006)
             │       Service       │   │       Service       │
             └──────────┬──────────┘   └─────────────────────┘
                        │
                        ▼
             [analytics_db:8123/9000]
                   (ClickHouse)
```

---

## 2. Port Allocation & Network Matrix

All containers communicate over an internal Docker network named `antifraud-net`.

| Component / Service | Type | Container Name | Internal Port | Exposed Host Port | Protocol |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **API Gateway** | Gateway / Proxy | `antifraud-gateway` | `8080` | `8080` | HTTP / REST |
| **Rule Engine Service** | Business Microservice 1 | `service-rule-engine` | `8001` | `8001` | HTTP / REST |
| **Reputation Service** | Business Microservice 2 | `service-reputation` | `8002` | `8002` | HTTP / REST |
| **Velocity Service** | Business Microservice 3 | `service-velocity` | `8003` | `8003` | HTTP / REST |
| **Scoring Engine** | Business Microservice 4 | `service-scoring` | `8004` | `8004` | HTTP / REST |
| **Analytics Service** | Business Microservice 5 | `service-analytics` | `8005` | `8005` | HTTP / REST |
| **Alerting Service** | Business Microservice 6 | `service-alerting` | `8006` | `8006` | HTTP / REST |
| **PostgreSQL (Rules)** | Storage | `db-postgres-rules` | `5432` | `5432` | TCP (SQL) |
| **PostgreSQL (Reputation)**| Storage | `db-postgres-reputation`| `5432` | `5433` | TCP (SQL) |
| **Redis** | In-Memory Cache | `cache-redis` | `6379` | `6379` | TCP (RESP) |
| **ClickHouse** | Analytics OLAP | `db-clickhouse` | `8123`, `9000`| `8123`, `9000` | HTTP / Native |
| **RabbitMQ** | Message Broker | `broker-rabbitmq` | `5672`, `15672`| `5672`, `15672` | AMQP / HTTP |

---

## 3. Microservice Boundaries & Responsibilities

### Infrastructure: API Gateway (`gateway/`)
* **Role:** Single ingress entrypoint.
* **Responsibilities:**
  * Injects `X-Request-ID` (UUID4) into all incoming request headers if not provided.
  * Validates Client API-Keys / Bearer tokens.
  * Routes external requests:
    * `POST /api/v1/verify` $\to$ `service-scoring:8004/api/v1/score`
    * `GET /api/v1/analytics/*` $\to$ `service-analytics:8005/api/v1/*`
    * `GET,POST /api/v1/rules/*` $\to$ `service-rule-engine:8001/api/v1/*`
    * `GET /api/v1/alerts` $\to$ `service-alerting:8006/api/v1/alerts`

### 1. Rule Engine Service (`services/rule-engine/`)
* **Dedicated Database:** `rules_db` on `db-postgres-rules:5432`.
* **Responsibilities:**
  * Stores scoring policies, rule definitions, and weights.
  * Exposes CRUD endpoints for fraud thresholds and weight calibration.
  * Seeds default heuristics on initial boot:
    * `RULE_IP_VELOCITY_HIGH` (threshold: 10 req/min, weight: 35.0).
    * `RULE_PHONE_VELOCITY_HIGH` (threshold: 3 req/5min, weight: 45.0).
    * `RULE_BLACKLISTED_ENTITY` (weight: 100.0).
    * `RULE_SUSPICIOUS_MCC` (weight: 40.0).

### 2. Reputation Service (`services/reputation/`)
* **Dedicated Database:** `reputation_db` on `db-postgres-reputation:5432`.
* **Responsibilities:**
  * Manages blacklists and threat feeds (malicious IPs, automated ASN proxies, high-risk destination MCC/MNC ranges).
  * Exposes high-speed lookup endpoint `POST /api/v1/reputation/check` returning entity match flags.

### 3. Velocity Service (`services/velocity/`)
* **Dedicated Database:** In-memory `cache-redis:6379`.
* **Responsibilities:**
  * High-speed sliding-window frequency counting.
  * Tracks hits in two primary scopes:
    * `ip:{client_ip}` (window: 60 seconds).
    * `phone:{destination_phone}` (window: 300 seconds).
  * Uses atomic Redis commands (`INCR`, `EXPIRE` or `ZADD`/`ZREMRANGEBYSCORE`).

### 4. Scoring Engine Service (`services/scoring/`)
* **Persistence:** Stateless computational service.
* **Responsibilities:**
  * Orchestrates the verification pipeline synchronously:
    1. Fetches active weights from Rule Engine (cached with 30s TTL).
    2. Queries Velocity Service and Reputation Service in parallel.
    3. Calculates aggregate Risk Score ($0.0 \dots 100.0$).
    4. Evaluates decision: `DENY` if $\text{RiskScore} \ge 60.0$, else `ALLOW`.
  * Publishes `InspectionCompletedEvent` to RabbitMQ exchange `antifraud`.

### 5. Analytics Service (`services/analytics/`)
* **Dedicated Database:** `analytics_db` on `db-clickhouse:8123`.
* **Responsibilities:**
  * Consumes events from RabbitMQ queue `analytics.events`.
  * Batches incoming inspections (buffer size: 100 items or 2s timeout) and performs bulk inserts into ClickHouse table `sms_inspections`.
  * Exposes reporting endpoints for traffic distribution, block rates, and median processing latency.

### 6. Alerting Service (`services/alerting/`)
* **Dedicated Database:** Local SQLite / Audit storage.
* **Responsibilities:**
  * Consumes events from RabbitMQ queue `security.alerts`.
  * Triggers on any inspection resulting in `DENY` or $\text{RiskScore} \ge 80.0$.
  * Formats security audit log in Common Event Format (CEF) and maintains the last 100 in-memory/persistent alert records.

---

## 4. Shared Data Contracts (DTO Schemas)

### Ingress Verification Request (`SMSCheckRequest`)
Used at Gateway and Scoring Service:
```json
{
  "client_ip": "198.51.100.24",
  "phone_number": "+24101234567",
  "mcc_mnc": "62801",
  "sender_id": "AUTH_VERIFY",
  "message_length": 24,
  "timestamp": "2026-11-09T20:15:30.123Z"
}
```

### Ingress Verification Response (`InspectionResponse`)
```json
{
  "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "verdict": "DENY",
  "risk_score": 85.0,
  "reasons": [
    "REPUTATION_BLACKLIST_MATCH: IP 198.51.100.24",
    "VELOCITY_LIMIT_EXCEEDED: IP frequency > 10/min"
  ],
  "latency_ms": 4.12
}
```

### Inter-Service Reputation Payload
* Request to `POST /api/v1/reputation/check`:
```json
{
  "ip": "198.51.100.24",
  "phone": "+24101234567",
  "mcc_mnc": "62801"
}
```
* Response:
```json
{
  "is_blacklisted": true,
  "matched_entities": [
    {"type": "IP", "value": "198.51.100.24", "reason": "Known Tor exit node"}
  ]
}
```

### Inter-Service Velocity Payload
* Request to `POST /api/v1/velocity/hit`:
```json
{
  "ip": "198.51.100.24",
  "phone": "+24101234567"
}
```
* Response:
```json
{
  "ip_count_1m": 14,
  "phone_count_5m": 1
}
```

---

## 5. Message Broker Specification (RabbitMQ)

* **Exchange Name:** `antifraud` (Type: `topic`, Durable: `true`)
* **Routing Keys:**
  * `inspection.completed` (all evaluations)
  * `alert.critical` (high-risk events, $\ge 80.0$)

### Queues and Bindings
1. **Queue:** `analytics.events`
   * Bound to: `antifraud` with key `inspection.*`
   * Consumer: `service-analytics`
2. **Queue:** `security.alerts`
   * Bound to: `antifraud` with key `inspection.completed` (filters for DENY) and `alert.#`
   * Consumer: `service-alerting`

### Event Schema (`InspectionCompletedEvent`)
```json
{
  "event_id": "1d8b746a-72ef-4c6e-8ff5-cf1f09bb2a91",
  "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "timestamp": "2026-11-09T20:15:30.128Z",
  "client_ip": "198.51.100.24",
  "phone_number": "+24101234567",
  "mcc_mnc": "62801",
  "verdict": "DENY",
  "risk_score": 85.0,
  "reasons": ["REPUTATION_BLACKLIST_MATCH", "VELOCITY_LIMIT_EXCEEDED"],
  "latency_ms": 4.12
}
```

---

## 6. Storage Schemas

### PostgreSQL: `rules_db`
```sql
CREATE TABLE rules (
    id SERIAL PRIMARY KEY,
    rule_code VARCHAR(64) UNIQUE NOT NULL,
    description TEXT,
    threshold_value DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    weight DOUBLE PRECISION NOT NULL DEFAULT 10.0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### PostgreSQL: `reputation_db`
```sql
CREATE TABLE blacklisted_entities (
    id SERIAL PRIMARY KEY,
    entity_type VARCHAR(16) NOT NULL, -- 'IP', 'PHONE', 'MCC_MNC'
    entity_value VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_entity UNIQUE (entity_type, entity_value)
);
CREATE INDEX idx_entity_lookup ON blacklisted_entities (entity_type, entity_value);
```

### ClickHouse: `analytics_db`
```sql
CREATE TABLE IF NOT EXISTS sms_inspections (
    event_time DateTime DEFAULT now(),
    request_id UUID,
    client_ip String,
    destination_phone String,
    mcc_mnc LowCardinality(String),
    verdict LowCardinality(String), -- 'ALLOW', 'DENY'
    risk_score Float32,
    latency_ms Float32,
    reasons Array(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_time, verdict, mcc_mnc, request_id);
```

---

## 7. Cross-Cutting Standards

### A. Health Checks
Every service must implement:
* `GET /health` (Liveness): Returns `{"status": "ok"}` with HTTP 200 immediately if server process is running.
* `GET /ready` (Readiness): Pings local database/cache/broker. Returns `{"status": "ready"}` with HTTP 200 only if all dependencies respond within 500ms; otherwise returns HTTP 503.

### B. Structured Logging
Every service emits single-line JSON logs to `stdout`:
```json
{
  "timestamp": "2026-11-09T20:15:30.125Z",
  "service": "service-scoring",
  "level": "INFO",
  "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "message": "Scoring completed with verdict DENY"
}
```

### C. Standardized Error Envelope
Stack traces must never leak to HTTP clients. Responses for 4xx/5xx must strictly adhere to:
```json
{
  "error_code": "RESOURCE_NOT_FOUND",
  "message": "Entity does not exist",
  "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "details": null
}
```

---

## 8. Repository Layout

```text
.
├── ARCHITECTURE.md             # This specification (SSOT)
├── docker-compose.yml          # Top-level composition
├── Makefile                    # dev/test/seed automation
├── gateway/                    # API Gateway service
│   ├── Dockerfile
│   ├── requirements.txt
│   └── src/
├── services/
│   ├── rule-engine/            # Microservice 1 (Postgres rules_db)
│   ├── reputation/             # Microservice 2 (Postgres reputation_db)
│   ├── velocity/               # Microservice 3 (Redis)
│   ├── scoring/                # Microservice 4 (Stateless decision engine)
│   ├── analytics/              # Microservice 5 (ClickHouse consumer)
│   └── alerting/               # Microservice 6 (RabbitMQ audit consumer)
├── shared/                     # Shared DTO definitions & logger utility
│   ├── __init__.py
│   ├── schemas.py
│   └── logger.py
├── infrastructure/             # Initial SQL scripts & seed configs
│   ├── postgres-rules/
│   ├── postgres-reputation/
│   └── clickhouse/
└── tests/                      # Automated test suite
    ├── unit/
    └── integration/
```