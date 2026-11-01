import type { VerificationBrokenLink } from '../types/index.js';

export class RoleAuditError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(message: string, code = 'ROLE_AUDIT_ERROR', statusCode = 500) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AuthorizationDeniedError extends RoleAuditError {
  public readonly principalId?: string;
  public readonly action?: string;
  public readonly resourceType?: string;
  public readonly resourceId?: string | null;
  public readonly tenantId?: string;
  public readonly matchedConditions?: string[];

  constructor(
    message = 'Access denied by authorization policy',
    details?: {
      principalId?: string;
      action?: string;
      resourceType?: string;
      resourceId?: string | null;
      tenantId?: string;
      matchedConditions?: string[];
    }
  ) {
    super(message, 'AUTHORIZATION_DENIED', 403);
    this.principalId = details?.principalId;
    this.action = details?.action;
    this.resourceType = details?.resourceType;
    this.resourceId = details?.resourceId;
    this.tenantId = details?.tenantId;
    this.matchedConditions = details?.matchedConditions;
  }
}

export class TenantIsolationError extends RoleAuditError {
  public readonly requestedTenantId?: string;
  public readonly actualTenantId?: string;

  constructor(
    message = 'Cross-tenant access violation',
    details?: { requestedTenantId?: string; actualTenantId?: string }
  ) {
    super(message, 'TENANT_ISOLATION_VIOLATION', 403);
    this.requestedTenantId = details?.requestedTenantId;
    this.actualTenantId = details?.actualTenantId;
  }
}

export class AuditPersistenceError extends RoleAuditError {
  public readonly causeError?: unknown;

  constructor(message = 'Failed to persist audit event', cause?: unknown) {
    super(message, 'AUDIT_PERSISTENCE_FAILURE', 500);
    this.causeError = cause;
  }
}

export class ChainIntegrityError extends RoleAuditError {
  public readonly brokenLink?: VerificationBrokenLink;

  constructor(message = 'Audit chain integrity verification failed', brokenLink?: VerificationBrokenLink) {
    super(message, 'CHAIN_INTEGRITY_TAMPERED', 500);
    this.brokenLink = brokenLink;
  }
}

export class MaskingError extends RoleAuditError {
  constructor(message = 'Masking failed in fail-closed mode') {
    super(message, 'MASKING_FAILURE', 500);
  }
}

export class PolicyValidationError extends RoleAuditError {
  constructor(message: string) {
    super(message, 'POLICY_VALIDATION_ERROR', 400);
  }
}
