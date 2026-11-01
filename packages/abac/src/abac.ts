import type { Decision, DecisionEffect, DecisionTrace } from '@role-audit/core';
import { matchesWildcard } from '@role-audit/rbac';
import type { Policy, PolicyCondition, EvaluationContext, ConditionOperator } from './types.js';

export function resolvePath(path: string, obj: unknown): unknown {
  if (!obj || typeof obj !== 'object' || !path) {
    return undefined;
  }
  const parts = path.split('.');
  let current: any = obj;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

export function resolveConditionValue(val: unknown, context: EvaluationContext): unknown {
  if (typeof val === 'string') {
    const prefixes = ['subject.', 'resource.', 'tenant.', 'request.', 'environment.', 'device.'];
    if (prefixes.some((p) => val.startsWith(p))) {
      return resolvePath(val, context);
    }
  }
  return val;
}

export function evaluateCondition(
  condition: PolicyCondition,
  context: EvaluationContext
): boolean {
  const actualVal = resolvePath(condition.attribute, context);
  const targetVal = resolveConditionValue(condition.value, context);
  const op = condition.operator;

  switch (op) {
    case 'equals':
    case 'eq':
      if (typeof actualVal === 'object' && typeof targetVal === 'object') {
        return JSON.stringify(actualVal) === JSON.stringify(targetVal);
      }
      return actualVal === targetVal;

    case 'notEquals':
    case 'neq':
      return actualVal !== targetVal;

    case 'in':
      if (Array.isArray(targetVal)) {
        return targetVal.includes(actualVal);
      }
      if (typeof targetVal === 'string' && typeof actualVal === 'string') {
        return targetVal.includes(actualVal);
      }
      return false;

    case 'notIn':
      if (Array.isArray(targetVal)) {
        return !targetVal.includes(actualVal);
      }
      return true;

    case 'contains':
      if (Array.isArray(actualVal)) {
        return actualVal.includes(targetVal);
      }
      if (typeof actualVal === 'string' && typeof targetVal === 'string') {
        return actualVal.includes(targetVal);
      }
      return false;

    case 'greaterThan':
    case 'gt':
      return typeof actualVal === 'number' && typeof targetVal === 'number' && actualVal > targetVal;

    case 'greaterThanOrEqual':
    case 'gte':
      return typeof actualVal === 'number' && typeof targetVal === 'number' && actualVal >= targetVal;

    case 'lessThan':
    case 'lt':
      return typeof actualVal === 'number' && typeof targetVal === 'number' && actualVal < targetVal;

    case 'lessThanOrEqual':
    case 'lte':
      return typeof actualVal === 'number' && typeof targetVal === 'number' && actualVal <= targetVal;

    case 'matches':
      if (typeof actualVal !== 'string' || typeof targetVal !== 'string') {
        return false;
      }
      try {
        const regex = new RegExp(targetVal);
        return regex.test(actualVal);
      } catch {
        return false;
      }

    case 'exists':
      return actualVal !== undefined && actualVal !== null && actualVal !== '';

    case 'timeWindow': {
      if (typeof targetVal !== 'string') return false;
      const [startStr, endStr] = targetVal.split('-');
      if (!startStr || !endStr) return false;

      const date = context.request?.timestamp ? new Date(context.request.timestamp as string) : new Date();
      const currentMinutes = date.getUTCHours() * 60 + date.getUTCMinutes();

      const [startH, startM] = startStr.split(':').map(Number);
      const [endH, endM] = endStr.split(':').map(Number);
      const startMinutes = (startH ?? 0) * 60 + (startM ?? 0);
      const endMinutes = (endH ?? 0) * 60 + (endM ?? 0);

      if (startMinutes <= endMinutes) {
        return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
      } else {
        return currentMinutes >= startMinutes || currentMinutes <= endMinutes;
      }
    }

    case 'cidrMatches': {
      if (typeof actualVal !== 'string' || typeof targetVal !== 'string') {
        return false;
      }
      if (targetVal === '*' || actualVal === targetVal) {
        return true;
      }
      if (targetVal.endsWith('.*')) {
        const prefix = targetVal.slice(0, -1);
        return actualVal.startsWith(prefix);
      }
      return actualVal === targetVal;
    }

    default:
      return false;
  }
}

export class AbacEngine {
  private policies = new Map<string, Policy>();
  private cache = new Map<string, { decision: Decision; expiresAt: number }>();
  private cacheTtlMs = 60000;

  constructor(options?: { cacheTtlMs?: number }) {
    if (options?.cacheTtlMs !== undefined) {
      this.cacheTtlMs = options.cacheTtlMs;
    }
  }

  public registerPolicy(policy: Policy): void {
    if (!policy.policyId.trim()) {
      throw new TypeError('Policy ID must not be empty');
    }
    if (!Number.isInteger(policy.version) || policy.version < 1) {
      throw new TypeError('Policy version must be a positive integer');
    }
    if (!Array.isArray(policy.actions) || policy.actions.length === 0 || policy.actions.some((action) => !action.trim())) {
      throw new TypeError('Policy must define at least one non-empty action');
    }
    if (policy.resources?.some((resource) => !resource.trim())) {
      throw new TypeError('Policy resources must not contain empty values');
    }
    if (policy.conditions?.some((condition) => !condition.attribute.trim())) {
      throw new TypeError('Policy condition attributes must not be empty');
    }

    this.policies.set(`${policy.policyId}:v${policy.version}`, policy);
    this.clearCache();
  }

  public registerPolicies(policies: Policy[]): void {
    for (const p of policies) {
      this.registerPolicy(p);
    }
  }

  public getPolicies(): Policy[] {
    return Array.from(this.policies.values());
  }

  public clearCache(): void {
    this.cache.clear();
  }

  public evaluate(context: EvaluationContext): Decision {
    const tenantId = context.tenant.tenantId;
    const action = context.action;
    const resourceType = context.resource?.type || '*';
    const resourceId = context.resource?.id || '*';
    // Policies can inspect any context field (including IP, device, and custom
    // attributes), so key the cache on the complete evaluation context.
    const cacheKey = JSON.stringify(context);
    const cached = this.cache.get(cacheKey);
    const now = Date.now();
    if (cached && cached.expiresAt > now) {
      return { ...cached.decision, timestamp: new Date(now).toISOString() };
    }

    // Filter relevant policies
    const candidatePolicies = Array.from(this.policies.values()).filter((policy) => {
      if (policy.disabled) return false;

      if (policy.tenantId && policy.tenantId !== '*' && policy.tenantId !== tenantId) {
        return false;
      }

      const matchesAction = policy.actions.some((a) => matchesWildcard(a, action));
      if (!matchesAction) return false;

      if (policy.resources && policy.resources.length > 0) {
        const matchesResource = policy.resources.some((r) => matchesWildcard(r, resourceType));
        if (!matchesResource) return false;
      }

      if (policy.roles && policy.roles.length > 0) {
        const hasRole = policy.roles.some((r) => context.subject.roles?.includes(r));
        if (!hasRole) return false;
      }

      return true;
    });

    candidatePolicies.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));

    const traces: DecisionTrace[] = [];
    const matchedConditions: string[] = [];
    let hasAllow = false;
    let allowedPolicy: Policy | undefined;
    let explicitDenyReason: string | undefined;

    for (const policy of candidatePolicies) {
      const normalizedEffect: DecisionEffect = policy.effect.toUpperCase() === 'ALLOW' ? 'ALLOW' : 'DENY';
      let conditionsMet = true;
      const policyMatchedConditions: string[] = [];

      if (policy.conditions && policy.conditions.length > 0) {
        for (const cond of policy.conditions) {
          const pass = evaluateCondition(cond, context);
          if (!pass) {
            conditionsMet = false;
            break;
          }
          policyMatchedConditions.push(
            `${cond.attribute} ${cond.operator} ${JSON.stringify(cond.value)}`
          );
        }
      }

      if (conditionsMet) {
        traces.push({
          policyId: policy.policyId,
          policyVersion: policy.version,
          effect: normalizedEffect,
          reason: policy.description || `Policy ${policy.policyId} conditions satisfied`,
          matchedConditions: policyMatchedConditions
        });

        matchedConditions.push(...policyMatchedConditions);

        if (normalizedEffect === 'DENY') {
          explicitDenyReason = `Explicit DENY triggered by ABAC policy "${policy.policyId}" (v${policy.version})`;
          break;
        } else {
          hasAllow = true;
          if (!allowedPolicy) {
            allowedPolicy = policy;
          }
        }
      }
    }

    let result: Decision;

    if (explicitDenyReason) {
      result = {
        effect: 'DENY',
        reason: explicitDenyReason,
        matchedConditions,
        traces,
        timestamp: new Date().toISOString()
      };
    } else if (hasAllow && allowedPolicy) {
      result = {
        effect: 'ALLOW',
        policyId: allowedPolicy.policyId,
        policyVersion: allowedPolicy.version,
        reason: `Access granted by ABAC policy "${allowedPolicy.policyId}" (v${allowedPolicy.version})`,
        matchedConditions,
        traces,
        timestamp: new Date().toISOString()
      };
    } else {
      result = {
        effect: 'DENY',
        reason: `No matching ABAC allow policy found for action "${action}" on resource "${resourceType}"`,
        matchedConditions: [],
        traces,
        timestamp: new Date().toISOString()
      };
    }

    if (this.cacheTtlMs > 0) {
      this.cache.set(cacheKey, {
        decision: result,
        expiresAt: now + this.cacheTtlMs
      });
    }

    return result;
  }
}

export const defaultAbacEngine = new AbacEngine();
