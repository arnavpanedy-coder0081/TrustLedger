-- Migration 001: Create Audit Tables and Chain Heads
CREATE TABLE IF NOT EXISTS audit_chain_heads (
  tenant_id VARCHAR(128) PRIMARY KEY,
  last_audit_id UUID NOT NULL,
  last_hash VARCHAR(64) NOT NULL,
  event_count BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_events (
  audit_id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  principal_id VARCHAR(256) NOT NULL,
  principal_type VARCHAR(64) NOT NULL,
  action VARCHAR(128) NOT NULL,
  resource_type VARCHAR(128) NOT NULL,
  resource_id VARCHAR(256),
  decision VARCHAR(32) NOT NULL,
  policy_id VARCHAR(128),
  policy_version INT,
  request_context JSONB NOT NULL DEFAULT '{}'::jsonb,
  masked_payload JSONB,
  previous_hash VARCHAR(64) NOT NULL,
  event_hash VARCHAR(64) NOT NULL,
  schema_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compound index for fast chronological sequential audit replay per tenant
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_timestamp ON audit_events (tenant_id, timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_principal ON audit_events (tenant_id, principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_action ON audit_events (tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_decision ON audit_events (tenant_id, decision);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation ON audit_events ((request_context->>'correlationId'));

CREATE TABLE IF NOT EXISTS audit_checkpoints (
  checkpoint_id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  event_count BIGINT NOT NULL,
  last_audit_id UUID NOT NULL,
  last_hash VARCHAR(64) NOT NULL,
  signature VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_tenant ON audit_checkpoints (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS verification_runs (
  run_id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  verified BOOLEAN NOT NULL,
  total_events BIGINT NOT NULL,
  genesis_hash VARCHAR(64) NOT NULL,
  head_hash VARCHAR(64),
  first_broken_link JSONB,
  duration_ms DOUBLE PRECISION NOT NULL,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verification_runs_tenant ON verification_runs (tenant_id, checked_at DESC);
