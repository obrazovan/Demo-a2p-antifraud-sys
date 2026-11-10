-- Schema for analytics_db (ClickHouse 23.8)
-- Microservice: Analytics Ingest & Reporting Service

CREATE DATABASE IF NOT EXISTS analytics_db;

CREATE TABLE IF NOT EXISTS analytics_db.sms_inspections (
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

