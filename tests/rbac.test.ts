import { describe, it, expect } from 'vitest';
import { RbacEngine, parsePermissionString, matchesWildcard } from '../packages/rbac/src/index.js';
import type { Principal } from '../packages/core/src/index.js';

describe('RBAC Engine', () => {
  it('correctly parses permission strings', () => {
    expect(parsePermissionString('invoice:read')).toEqual({
      resource: 'invoice',
      action: 'read',
      effect: 'ALLOW'
    });

    expect(parsePermissionString('!invoice:delete')).toEqual({
      resource: 'invoice',
      action: 'delete',
      effect: 'DENY'
    });

    expect(parsePermissionString('*')).toEqual({
      resource: '*',
      action: '*',
      effect: 'ALLOW'
    });
  });

  it('matches wildcards appropriately', () => {
    expect(matchesWildcard('*', 'invoice')).toBe(true);
    expect(matchesWildcard('invoice:*', 'invoice:read')).toBe(true);
    expect(matchesWildcard('invoice', 'invoice')).toBe(true);
    expect(matchesWildcard('invoice', 'user')).toBe(false);
  });

  it('evaluates standard viewer permissions (read-only)', () => {
    const engine = new RbacEngine();
    const principal: Principal = {
      id: 'bob',
      type: 'human',
      roles: ['viewer']
    };

    const allowDecision = engine.evaluate(principal, 'tenant-1', 'invoice', 'read');
    expect(allowDecision.effect).toBe('ALLOW');

    const denyDecision = engine.evaluate(principal, 'tenant-1', 'invoice', 'delete');
    expect(denyDecision.effect).toBe('DENY');
  });

  it('evaluates role inheritance (manager inherits analyst, which inherits viewer)', () => {
    const engine = new RbacEngine();
    const principal: Principal = {
      id: 'carol',
      type: 'human',
      roles: ['manager']
    };

    // From viewer
    expect(engine.evaluate(principal, 'tenant-1', 'invoice', 'read').effect).toBe('ALLOW');
    // From analyst
    expect(engine.evaluate(principal, 'tenant-1', 'invoice', 'export').effect).toBe('ALLOW');
    // From manager
    expect(engine.evaluate(principal, 'tenant-1', 'invoice', 'update').effect).toBe('ALLOW');
  });

  it('handles inheritance cycles safely without infinite recursion', () => {
    const engine = new RbacEngine();
    engine.registerRole({
      name: 'cycle-A',
      permissions: ['doc:read'],
      inherits: ['cycle-B']
    });
    engine.registerRole({
      name: 'cycle-B',
      permissions: ['doc:write'],
      inherits: ['cycle-A']
    });

    const perms = engine.getEffectivePermissions('cycle-A');
    expect(perms.length).toBe(2);
  });

  it('enforces explicit DENY taking precedence over ALLOW', () => {
    const engine = new RbacEngine();
    engine.registerRole({
      name: 'restricted-manager',
      permissions: ['*:*', '!invoice:delete']
    });

    const principal: Principal = {
      id: 'david',
      type: 'human',
      roles: ['restricted-manager']
    };

    // Can create
    expect(engine.evaluate(principal, 'tenant-1', 'invoice', 'create').effect).toBe('ALLOW');
    // Cannot delete due to explicit deny
    const deleteDecision = engine.evaluate(principal, 'tenant-1', 'invoice', 'delete');
    expect(deleteDecision.effect).toBe('DENY');
    expect(deleteDecision.reason).toContain('Explicit DENY');
  });

  it('supports tenant-scoped role bindings', () => {
    const engine = new RbacEngine();
    engine.registerRoleBinding({
      principalId: 'eve',
      roleName: 'admin',
      tenantId: 'tenant-vip'
    });

    const principal: Principal = {
      id: 'eve',
      type: 'human',
      roles: ['viewer'] // default viewer
    };

    // In tenant-standard, eve is only viewer
    expect(engine.evaluate(principal, 'tenant-standard', 'system', 'modify').effect).toBe('DENY');

    // In tenant-vip, eve has admin binding
    expect(engine.evaluate(principal, 'tenant-vip', 'system', 'modify').effect).toBe('ALLOW');
  });
});
