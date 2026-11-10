-- Schema for rules_db (PostgreSQL 15)
-- Microservice: Rule Engine Service

CREATE TABLE IF NOT EXISTS rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    metric_type VARCHAR(32) NOT NULL,
    threshold_val DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    weight DOUBLE PRECISION NOT NULL DEFAULT 10.0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rules_name ON rules (name);
CREATE INDEX IF NOT EXISTS idx_rules_metric_type ON rules (metric_type);
CREATE INDEX IF NOT EXISTS idx_rules_is_active ON rules (is_active);

-- Seed default heuristic scoring rules
INSERT INTO rules (name, metric_type, threshold_val, weight, is_active)
VALUES
    ('High velocity IP (>10 req/min)', 'VELOCITY', 10.0, 40.0, true),
    ('High velocity Destination (>30 req/min)', 'VELOCITY', 30.0, 50.0, true),
    ('Blacklisted prefix/IP', 'REPUTATION', 0.0, 100.0, true)
ON CONFLICT (name) DO NOTHING;
