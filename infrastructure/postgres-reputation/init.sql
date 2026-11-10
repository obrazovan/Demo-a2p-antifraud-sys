-- Schema for reputation_db (PostgreSQL 15)
-- Microservice: Reputation Service

CREATE TABLE IF NOT EXISTS blacklisted_entities (
    id SERIAL PRIMARY KEY,
    entity_type VARCHAR(16) NOT NULL, -- 'IP', 'PHONE', 'MCC_MNC'
    entity_val VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_entity UNIQUE (entity_type, entity_val)
);

CREATE INDEX IF NOT EXISTS idx_entity_lookup ON blacklisted_entities (entity_type, entity_val);

-- Seed initial mock bad actors for testing and fraud mitigation
INSERT INTO blacklisted_entities (entity_type, entity_val, reason)
VALUES
    ('IP', '198.51.100.24', 'Known Tor exit node / automated SMS pumping proxy'),
    ('MCC_MNC', '62801', 'Gabon test range - high-risk AIT destination')
ON CONFLICT (entity_type, entity_val) DO NOTHING;
