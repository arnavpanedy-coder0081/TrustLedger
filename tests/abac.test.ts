import { describe, it, expect } from 'vitest';
import {
  AbacEngine,
  AuthorizationEngine,
  resolvePath,
  evaluateCondition
} from '../packages/abac/src/index.js';
import type { EvaluationContext } from '../packages/abac/src/types.js';

describe('ABAC Engine', () => {
  const sampleContext: EvaluationContext = {
    subject: {
      id: 'alice',
      type: 'human',
      roles: ['finance_manager'],
      tenantId: 'tenant-1',
      attributes: {
        department: 'finance',
        clearance: 3
      }
    },
    tenant: {
      tenantId: 'tenant-1',
      status: 'active'
    },
    action: 'invoice:read',
    resource: {
      type: 'invoice',
      id: 'inv-101',
      tenantId: 'tenant-1',
      attributes: {
        department: 'finance',
        classification: 2,
        amount: 500
      }
    },
    request: {
      correlationId: 'req-001',
      ip: '192.168.1.50',
      timestamp: '2026-10-07T14:30:00Z'
    }
  };

  it('correctly resolves nested dot paths', () => {
    expect(resolvePath('subject.attributes.department', sampleContext)).toBe('finance');
    expect(resolvePath('resource.attributes.amount', sampleContext)).toBe(500);
    expect(resolvePath('non.existent.path', sampleContext)).toBeUndefined();
  });

  it('evaluates comparison operators', () => {
    expect(
      evaluateCondition(
        { attribute: 'resource.attributes.amount', operator: 'greaterThan', value: 100 },
        sampleContext
      )
    ).toBe(true);

    expect(
      evaluateCondition(
        { attribute: 'resource.attributes.amount', operator: 'lessThan', value: 100 },
        sampleContext
      )
    ).toBe(false);

    expect(
      evaluateCondition(
        { attribute: 'subject.attributes.department', operator: 'in', value: ['finance', 'legal'] },
        sampleContext
      )
    ).toBe(true);

    expect(
      evaluateCondition(
        { attribute: 'request.ip', operator: 'cidrMatches', value: '192.168.1.*' },
        sampleContext
      )
    ).toBe(true);
  });

  it('evaluates dynamic attribute matching (subject.tenantId == resource.tenantId)', () => {
    expect(
      evaluateCondition(
        { attribute: 'resource.tenantId', operator: 'equals', value: 'subject.tenantId' },
        sampleContext
      )
    ).toBe(true);
  });

  it('evaluates time window condition', () => {
    // 14:30 UTC is within 09:00-17:00
    expect(
      evaluateCondition(
        { attribute: 'request.timestamp', operator: 'timeWindow', value: '09:00-17:00' },
        sampleContext
      )
    ).toBe(true);

    // 14:30 UTC is outside 18:00-22:00
    expect(
      evaluateCondition(
        { attribute: 'request.timestamp', operator: 'timeWindow', value: '18:00-22:00' },
        sampleContext
      )
    ).toBe(false);
  });

  it('evaluates ABAC policy priority and explicit deny semantics', () => {
    const engine = new AbacEngine();

    // Normal allow policy
    engine.registerPolicy({
      policyId: 'policy-allow',
      version: 1,
      effect: 'ALLOW',
      priority: 10,
      actions: ['invoice:read'],
      resources: ['invoice'],
      conditions: [
        { attribute: 'resource.tenantId', operator: 'equals', value: 'subject.tenantId' }
      ]
    });

    // High-priority deny policy
    engine.registerPolicy({
      policyId: 'policy-deny-blacklisted',
      version: 1,
      effect: 'DENY',
      priority: 100,
      actions: ['invoice:read'],
      resources: ['invoice'],
      conditions: [
        { attribute: 'resource.attributes.department', operator: 'equals', value: 'finance' }
      ]
    });

    const decision = engine.evaluate(sampleContext);
    expect(decision.effect).toBe('DENY');
    expect(decision.reason).toContain('Explicit DENY');
  });

  it('hybrid authorization denies cross-tenant access by default', async () => {
    const hybrid = new AuthorizationEngine({ enforceTenantIsolation: true });

    const crossTenantContext: EvaluationContext = {
      ...sampleContext,
      tenant: { tenantId: 'tenant-1' },
      resource: {
        type: 'invoice',
        id: 'inv-999',
        tenantId: 'tenant-2' // Different tenant!
      }
    };

    const decision = await hybrid.check(crossTenantContext);
    expect(decision.effect).toBe('DENY');
    expect(decision.reason).toContain('Cross-tenant access denied');
  });
});
