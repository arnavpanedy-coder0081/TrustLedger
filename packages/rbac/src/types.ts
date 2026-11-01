import type { DecisionEffect } from '@role-audit/core';

export interface Permission {
  id?: string;
  resource: string;
  action: string;
  effect?: DecisionEffect; // Default is 'ALLOW'. Can be 'DENY' for explicit deny rules.
  description?: string;
}

export interface Role {
  name: string;
  description?: string;
  permissions: (string | Permission)[];
  inherits?: string[];
  tenantId?: string; // If undefined, applies globally as a system role
}

export interface RoleBinding {
  principalId: string;
  roleName: string;
  tenantId: string;
  expiresAt?: string;
}
