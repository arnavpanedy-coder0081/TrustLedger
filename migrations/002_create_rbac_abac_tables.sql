-- Migration 002: Create RBAC and ABAC Tables
CREATE TABLE IF NOT EXISTS roles (
  role_name VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(128) NOT NULL DEFAULT '*',
  description TEXT,
  inherits TEXT[] DEFAULT ARRAY[]::TEXT[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (role_name, tenant_id)
);

CREATE TABLE IF NOT EXISTS permissions (
  permission_id UUID PRIMARY KEY,
  role_name VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(128) NOT NULL DEFAULT '*',
  resource VARCHAR(128) NOT NULL,
  action VARCHAR(128) NOT NULL,
  effect VARCHAR(16) NOT NULL DEFAULT 'ALLOW',
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_permissions_role ON permissions (role_name, tenant_id);

CREATE TABLE IF NOT EXISTS role_bindings (
  binding_id UUID PRIMARY KEY,
  principal_id VARCHAR(256) NOT NULL,
  role_name VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_role_bindings_principal ON role_bindings (principal_id, tenant_id);

CREATE TABLE IF NOT EXISTS policies (
  policy_id VARCHAR(128) NOT NULL,
  version INT NOT NULL DEFAULT 1,
  tenant_id VARCHAR(128) NOT NULL DEFAULT '*',
  effect VARCHAR(16) NOT NULL DEFAULT 'allow',
  roles TEXT[] DEFAULT ARRAY[]::TEXT[],
  actions TEXT[] NOT NULL,
  resources TEXT[] DEFAULT ARRAY[]::TEXT[],
  priority INT NOT NULL DEFAULT 0,
  conditions JSONB DEFAULT '[]'::jsonb,
  obligations JSONB DEFAULT '{}'::jsonb,
  description TEXT,
  disabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (policy_id, version, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);

CREATE TABLE IF NOT EXISTS masking_rules (
  rule_id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL DEFAULT '*',
  field_pattern VARCHAR(128) NOT NULL,
  mask_strategy VARCHAR(32) NOT NULL DEFAULT 'REDACT',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_masking_rules_tenant ON masking_rules (tenant_id);
