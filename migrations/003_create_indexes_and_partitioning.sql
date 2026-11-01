-- Migration 003: High-Volume Partitioning & Performance Tuning Guide
--
-- For enterprise installations with millions of events/day, audit_events can be partitioned
-- by monthly or daily range on the `timestamp` column:
--
-- Example partitioned table definition:
-- CREATE TABLE audit_events_partitioned (
--   audit_id UUID NOT NULL,
--   tenant_id VARCHAR(128) NOT NULL,
--   timestamp TIMESTAMPTZ NOT NULL,
--   principal_id VARCHAR(256) NOT NULL,
--   principal_type VARCHAR(64) NOT NULL,
--   action VARCHAR(128) NOT NULL,
--   resource_type VARCHAR(128) NOT NULL,
--   resource_id VARCHAR(256),
--   decision VARCHAR(32) NOT NULL,
--   policy_id VARCHAR(128),
--   policy_version INT,
--   request_context JSONB NOT NULL DEFAULT '{}'::jsonb,
--   masked_payload JSONB,
--   previous_hash VARCHAR(64) NOT NULL,
--   event_hash VARCHAR(64) NOT NULL,
--   schema_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
--   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
--   PRIMARY KEY (audit_id, timestamp)
-- ) PARTITION BY RANGE (timestamp);
--
-- CREATE TABLE audit_events_y2026m10 PARTITION OF audit_events_partitioned
--   FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');

-- Retention Policy helper view
CREATE OR REPLACE VIEW v_audit_chain_summary AS
SELECT
  h.tenant_id,
  h.last_audit_id,
  h.last_hash,
  h.event_count,
  h.updated_at AS last_activity,
  COUNT(e.audit_id) AS stored_event_count,
  MIN(e.timestamp) AS oldest_event,
  MAX(e.timestamp) AS newest_event
FROM audit_chain_heads h
LEFT JOIN audit_events e ON e.tenant_id = h.tenant_id
GROUP BY h.tenant_id, h.last_audit_id, h.last_hash, h.event_count, h.updated_at;
