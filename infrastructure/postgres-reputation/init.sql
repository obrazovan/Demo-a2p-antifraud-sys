-- Schema for reputation_db (PostgreSQL 15)
-- Microservice: Reputation Service

CREATE TABLE IF NOT EXISTS blacklisted_entities (
    id SERIAL PRIMARY KEY,
    entity_type VARCHAR(16) NOT NULL, -- 'IP', 'PHONE', 'MCC_MNC'
    entity_value VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_entity UNIQUE (entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_entity_lookup ON blacklisted_entities (entity_type, entity_value);

-- Seed initial known malicious entities for testing and fraud mitigation
INSERT INTO blacklisted_entities (entity_type, entity_value, reason)
VALUES
    ('IP', '198.51.100.24', 'Known Tor exit node / automated SMS pumping proxy'),
    ('PHONE', '+24101234567', 'High-cost premium rate phone destination'),
    ('MCC_MNC', '62801', 'High-risk AIT destination network range')
ON CONFLICT (entity_type, entity_value) DO NOTHING;

