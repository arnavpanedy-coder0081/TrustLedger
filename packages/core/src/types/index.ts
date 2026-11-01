/**
 * Core types for Role-Based Identity & Audit Log Middleware Engine
 */

export type PrincipalType = 'human' | 'service' | 'system' | 'anonymous';

export interface Principal {
  id: string;
  type: PrincipalType;
  roles: string[];
  tenantId?: string;
  attributes?: Record<string, unknown>;
  email?: string;
  name?: string;
}

export type TenantStatus = 'active' | 'suspended' | 'pending';

export interface TenantContext {
  tenantId: string;
  status?: TenantStatus;
  attributes?: Record<string, unknown>;
}

export interface SecurityContext {
  principal: Principal;
  tenant: TenantContext;
  requestId: string;
  correlationId: string;
  ip?: string;
  userAgent?: string;
  timestamp: string;
}

export interface ResourceContext {
  type: string;
  id?: string;
  tenantId?: string;
  attributes?: Record<string, unknown>;
}

export type DecisionEffect = 'ALLOW' | 'DENY';

export interface DecisionTrace {
  ruleId?: string;
  policyId?: string;
  policyVersion?: number;
  effect: DecisionEffect;
  reason?: string;
  matchedConditions?: string[];
}

export interface Decision {
  effect: DecisionEffect;
  policyId?: string;
  policyVersion?: number;
  reason?: string;
  matchedConditions?: string[];
  timestamp: string;
  traces?: DecisionTrace[];
}

export type AuditEventType =
  | 'AUTHENTICATION_SUCCESS'
  | 'AUTHENTICATION_FAILURE'
  | 'AUTHORIZATION_ALLOWED'
  | 'AUTHORIZATION_DENIED'
  | 'RESOURCE_CREATED'
  | 'RESOURCE_READ'
  | 'RESOURCE_UPDATED'
  | 'RESOURCE_DELETED'
  | 'DATA_EXPORT_REQUESTED'
  | 'DATA_EXPORT_COMPLETED'
  | 'ROLE_ASSIGNED'
  | 'ROLE_REVOKED'
  | 'POLICY_CREATED'
  | 'POLICY_UPDATED'
  | 'POLICY_DISABLED'
  | 'TENANT_CREATED'
  | 'TENANT_SUSPENDED'
  | 'TENANT_CONFIGURATION_CHANGED'
  | 'ADMINISTRATIVE_ACTION'
  | 'AUDIT_CHAIN_VERIFICATION_STARTED'
  | 'AUDIT_CHAIN_VERIFICATION_PASSED'
  | 'AUDIT_CHAIN_VERIFICATION_FAILED';

export interface RequestContextMetadata {
  ip?: string;
  userAgent?: string;
  correlationId: string;
  requestId?: string;
  httpMethod?: string;
  httpPath?: string;
  statusCode?: number;
  [key: string]: unknown;
}

export interface AuditEvent {
  audit_id: string;
  tenant_id: string;
  timestamp: string;
  principal_id: string;
  principal_type: PrincipalType;
  action: string;
  resource_type: string;
  resource_id: string | null;
  decision: DecisionEffect;
  policy_id: string | null;
  policy_version: number | null;
  request_context: RequestContextMetadata;
  masked_payload: Record<string, unknown> | null;
  previous_hash: string;
  event_hash: string;
  schema_version: string;
}

export interface AuditEventInput {
  audit_id?: string;
  tenant_id: string;
  timestamp?: string;
  principal_id: string;
  principal_type: PrincipalType;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  decision: DecisionEffect;
  policy_id?: string | null;
  policy_version?: number | null;
  request_context: RequestContextMetadata;
  payload?: Record<string, unknown> | null;
  schema_version?: string;
}

export interface AuditChainHead {
  tenant_id: string;
  last_audit_id: string;
  last_hash: string;
  event_count: number;
  updated_at: string;
}

export interface VerificationBrokenLink {
  index: number;
  audit_id: string;
  expected_previous_hash: string;
  actual_previous_hash: string;
  expected_event_hash: string;
  actual_event_hash: string;
  reason: 'PREVIOUS_HASH_MISMATCH' | 'EVENT_HASH_MISMATCH' | 'MISSING_LINK' | 'OUT_OF_ORDER' | 'GENESIS_MISMATCH';
  details?: string;
}

export interface VerificationResult {
  tenant_id: string;
  verified: boolean;
  total_events: number;
  genesis_hash: string;
  head_hash: string | null;
  first_broken_link?: VerificationBrokenLink;
  duration_ms: number;
  checked_at: string;
}

export interface AuditCheckpoint {
  checkpoint_id: string;
  tenant_id: string;
  event_count: number;
  last_audit_id: string;
  last_hash: string;
  created_at: string;
  signature?: string;
}

export interface AuditStore {
  appendEvent(event: AuditEvent): Promise<void>;
  getChainHead(tenantId: string): Promise<AuditChainHead | null>;
  getEvents(tenantId: string, options?: { fromTimestamp?: string; toTimestamp?: string; limit?: number; offset?: number; ascending?: boolean }): Promise<AuditEvent[]>;
  getEventById(auditId: string): Promise<AuditEvent | null>;
  countEvents(tenantId: string): Promise<number>;
  saveCheckpoint?(checkpoint: AuditCheckpoint): Promise<void>;
  getLatestCheckpoint?(tenantId: string): Promise<AuditCheckpoint | null>;
  recordVerificationRun?(run: VerificationResult): Promise<void>;
}
