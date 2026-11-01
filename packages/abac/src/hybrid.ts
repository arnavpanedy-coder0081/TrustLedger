import type { Decision, DecisionTrace } from '@role-audit/core';
import { RbacEngine, defaultRbacEngine } from '@role-audit/rbac';
import { AbacEngine, defaultAbacEngine } from './abac.js';
import type { EvaluationContext } from './types.js';

export type AuthzStrategy = 'RBAC_AND_ABAC' | 'RBAC_OR_ABAC' | 'ABAC_ONLY' | 'RBAC_ONLY';

export interface HybridAuthzOptions {
  rbac?: RbacEngine;
  abac?: AbacEngine;
  strategy?: AuthzStrategy;
  enforceTenantIsolation?: boolean;
}

export class AuthorizationEngine {
  private rbac: RbacEngine;
  private abac: AbacEngine;
  private strategy: AuthzStrategy;
  private enforceTenantIsolation: boolean;

  constructor(options: HybridAuthzOptions = {}) {
    this.rbac = options.rbac || defaultRbacEngine;
    this.abac = options.abac || defaultAbacEngine;
    this.strategy = options.strategy || 'RBAC_AND_ABAC';
    this.enforceTenantIsolation = options.enforceTenantIsolation ?? true;
  }

  public getRbac(): RbacEngine {
    return this.rbac;
  }

  public getAbac(): AbacEngine {
    return this.abac;
  }

  /**
   * Evaluates comprehensive authorization for a request context.
   */
  public async check(context: EvaluationContext): Promise<Decision> {
    const timestamp = new Date().toISOString();
    const traces: DecisionTrace[] = [];

    // 1. Multi-Tenant Isolation Enforcement (PRD Section 6.5)
    if (this.enforceTenantIsolation && context.resource?.tenantId) {
      if (
        context.resource.tenantId !== context.tenant.tenantId &&
        context.tenant.tenantId !== '*'
      ) {
        return {
          effect: 'DENY',
          reason: `Cross-tenant access denied: resource belongs to tenant "${context.resource.tenantId}", caller tenant is "${context.tenant.tenantId}"`,
          traces: [
            {
              effect: 'DENY',
              reason: 'Cross-tenant boundary enforcement'
            }
          ],
          timestamp
        };
      }
    }

    // 2. Tenant Status Check
    if (context.tenant.status === 'suspended') {
      return {
        effect: 'DENY',
        reason: `Access denied: tenant "${context.tenant.tenantId}" is currently suspended`,
        traces: [
          {
            effect: 'DENY',
            reason: 'Tenant account suspended'
          }
        ],
        timestamp
      };
    }

    const resourceType = context.resource?.type || '*';
    const action = context.action;

    // Evaluate based on chosen strategy
    if (this.strategy === 'RBAC_ONLY') {
      return this.rbac.evaluate(context.subject, context.tenant.tenantId, resourceType, action);
    }

    if (this.strategy === 'ABAC_ONLY') {
      return this.abac.evaluate(context);
    }

    const rbacDecision = this.rbac.evaluate(
      context.subject,
      context.tenant.tenantId,
      resourceType,
      action
    );

    // Any explicit DENY from RBAC takes immediate effect
    if (rbacDecision.effect === 'DENY' && rbacDecision.reason?.startsWith('Explicit DENY')) {
      return rbacDecision;
    }

    const abacDecision = this.abac.evaluate(context);

    // Any explicit DENY from ABAC takes immediate effect
    if (abacDecision.effect === 'DENY' && abacDecision.reason?.startsWith('Explicit DENY')) {
      return abacDecision;
    }

    if (this.strategy === 'RBAC_AND_ABAC') {
      // Both must allow
      if (rbacDecision.effect === 'ALLOW' && abacDecision.effect === 'ALLOW') {
        return {
          effect: 'ALLOW',
          policyId: abacDecision.policyId,
          policyVersion: abacDecision.policyVersion,
          reason: `Granted by RBAC roles and ABAC policies: [${rbacDecision.reason}] + [${abacDecision.reason}]`,
          matchedConditions: [
            ...(rbacDecision.matchedConditions || []),
            ...(abacDecision.matchedConditions || [])
          ],
          traces: [...(rbacDecision.traces || []), ...(abacDecision.traces || [])],
          timestamp
        };
      }

      const failureReason =
        rbacDecision.effect === 'DENY'
          ? `RBAC denied: ${rbacDecision.reason}`
          : `ABAC denied: ${abacDecision.reason}`;

      return {
        effect: 'DENY',
        reason: failureReason,
        matchedConditions: [
          ...(rbacDecision.matchedConditions || []),
          ...(abacDecision.matchedConditions || [])
        ],
        traces: [...(rbacDecision.traces || []), ...(abacDecision.traces || [])],
        timestamp
      };
    }

    if (this.strategy === 'RBAC_OR_ABAC') {
      // Either can allow
      if (rbacDecision.effect === 'ALLOW') {
        return rbacDecision;
      }
      if (abacDecision.effect === 'ALLOW') {
        return abacDecision;
      }
      return {
        effect: 'DENY',
        reason: `Denied by both RBAC (${rbacDecision.reason}) and ABAC (${abacDecision.reason})`,
        traces: [...(rbacDecision.traces || []), ...(abacDecision.traces || [])],
        timestamp
      };
    }

    return {
      effect: 'DENY',
      reason: 'Unknown authorization strategy',
      timestamp
    };
  }
}
