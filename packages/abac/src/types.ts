import type { Principal, TenantContext, ResourceContext, RequestContextMetadata, DecisionEffect } from '@role-audit/core';

export type ConditionOperator =
  | 'equals'
  | 'eq'
  | 'notEquals'
  | 'neq'
  | 'in'
  | 'notIn'
  | 'contains'
  | 'greaterThan'
  | 'gt'
  | 'greaterThanOrEqual'
  | 'gte'
  | 'lessThan'
  | 'lt'
  | 'lessThanOrEqual'
  | 'lte'
  | 'matches'
  | 'exists'
  | 'timeWindow'
  | 'cidrMatches';

export interface PolicyCondition {
  attribute: string;
  operator: ConditionOperator;
  value: unknown;
  description?: string;
}

export interface Policy {
  policyId: string;
  version: number;
  effect: 'allow' | 'deny' | DecisionEffect;
  tenantId?: string; // If omitted, applies globally
  roles?: string[]; // Optional role restriction (bridges RBAC and ABAC)
  actions: string[]; // e.g. ['invoice:read', 'invoice:update'] or ['*']
  resources?: string[]; // e.g. ['invoice', 'patient_record'] or ['*']
  priority?: number; // Higher numbers evaluated first. Default: 0
  conditions?: PolicyCondition[];
  obligations?: Record<string, unknown>;
  description?: string;
  disabled?: boolean;
}

export interface EvaluationContext {
  subject: Principal;
  tenant: TenantContext;
  action: string;
  resource?: ResourceContext;
  request?: RequestContextMetadata;
  environment?: Record<string, unknown>;
  device?: Record<string, unknown>;
}
