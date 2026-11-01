import type { Principal, Decision, DecisionEffect, DecisionTrace } from '@role-audit/core';
import type { Permission, Role, RoleBinding } from './types.js';

export function parsePermissionString(permStr: string): Permission {
  const isExplicitDeny = permStr.startsWith('!');
  const cleanStr = isExplicitDeny ? permStr.slice(1) : permStr;

  const colonIdx = cleanStr.indexOf(':');
  if (colonIdx === -1) {
    return {
      resource: cleanStr,
      action: '*',
      effect: isExplicitDeny ? 'DENY' : 'ALLOW'
    };
  }

  const resource = cleanStr.slice(0, colonIdx);
  const action = cleanStr.slice(colonIdx + 1);

  return {
    resource,
    action,
    effect: isExplicitDeny ? 'DENY' : 'ALLOW'
  };
}

export function matchesWildcard(pattern: string, actual: string): boolean {
  if (pattern === '*' || pattern === actual) {
    return true;
  }
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return actual.startsWith(prefix);
  }
  return false;
}

export class RbacEngine {
  private roles = new Map<string, Role>();
  private roleBindings: RoleBinding[] = [];

  constructor() {
    this.registerDefaultRoles();
  }

  private registerDefaultRoles(): void {
    this.registerRole({
      name: 'viewer',
      description: 'Read-only access across domain resources',
      permissions: ['*:read']
    });

    this.registerRole({
      name: 'analyst',
      description: 'Read, export, and report capabilities',
      permissions: ['*:read', '*:export', '*:analyze'],
      inherits: ['viewer']
    });

    this.registerRole({
      name: 'manager',
      description: 'Management operations over tenant resources, reads, creates, and updates',
      permissions: ['*:read', '*:create', '*:update', '*:export'],
      inherits: ['analyst']
    });

    this.registerRole({
      name: 'admin',
      description: 'Full administrative access across all tenant resources',
      permissions: ['*:*'],
      inherits: ['manager']
    });

    this.registerRole({
      name: 'auditor',
      description: 'Read access to audit logs, security policies, and verification tooling',
      permissions: [
        'audit:read',
        'audit:verify',
        'policy:read',
        'report:read',
        '*:read'
      ]
    });
  }

  public registerRole(role: Role): void {
    const key = role.tenantId ? `${role.tenantId}:${role.name}` : role.name;
    this.roles.set(key, role);
  }

  public registerRoleBinding(binding: RoleBinding): void {
    this.roleBindings.push(binding);
  }

  public getRole(roleName: string, tenantId?: string): Role | undefined {
    if (tenantId) {
      const tenantKey = `${tenantId}:${roleName}`;
      if (this.roles.has(tenantKey)) {
        return this.roles.get(tenantKey);
      }
    }
    return this.roles.get(roleName);
  }

  public getEffectivePermissions(roleName: string, tenantId?: string): Permission[] {
    const visited = new Set<string>();
    const permissions: Permission[] = [];

    const resolve = (currentName: string) => {
      if (visited.has(currentName)) {
        return;
      }
      visited.add(currentName);

      const role = this.getRole(currentName, tenantId);
      if (!role) {
        return;
      }

      for (const p of role.permissions) {
        if (typeof p === 'string') {
          permissions.push(parsePermissionString(p));
        } else {
          permissions.push({
            ...p,
            effect: p.effect ?? 'ALLOW'
          });
        }
      }

      if (role.inherits) {
        for (const inherited of role.inherits) {
          resolve(inherited);
        }
      }
    };

    resolve(roleName);
    return permissions;
  }

  public getRolesForPrincipal(principal: Principal, tenantId: string): string[] {
    const activeRoles = new Set<string>(principal.roles || []);

    const now = new Date().toISOString();
    for (const b of this.roleBindings) {
      if (b.principalId === principal.id && (b.tenantId === tenantId || b.tenantId === '*')) {
        if (!b.expiresAt || b.expiresAt > now) {
          activeRoles.add(b.roleName);
        }
      }
    }

    return Array.from(activeRoles);
  }

  public evaluate(
    principal: Principal,
    tenantId: string,
    resource: string,
    action: string
  ): Decision {
    const traces: DecisionTrace[] = [];
    const matchedConditions: string[] = [];
    const userRoles = this.getRolesForPrincipal(principal, tenantId);

    if (userRoles.length === 0) {
      return {
        effect: 'DENY',
        reason: 'Principal has no assigned roles',
        timestamp: new Date().toISOString(),
        traces: []
      };
    }

    const actionBare = action.includes(':') ? action.split(':')[1]! : action;
    const resourcePrefix = action.includes(':') ? action.split(':')[0]! : resource;

    let hasAllow = false;
    let explicitDenyReason: string | undefined;

    for (const roleName of userRoles) {
      const perms = this.getEffectivePermissions(roleName, tenantId);

      for (const perm of perms) {
        const resourceMatch =
          matchesWildcard(perm.resource, resource) ||
          matchesWildcard(perm.resource, resourcePrefix);

        const actionMatch =
          matchesWildcard(perm.action, action) ||
          matchesWildcard(perm.action, actionBare);

        if (resourceMatch && actionMatch) {
          const matchDesc = `Role "${roleName}" permission "${perm.resource}:${perm.action}" -> ${perm.effect}`;
          matchedConditions.push(matchDesc);

          traces.push({
            ruleId: perm.id || `${perm.resource}:${perm.action}`,
            effect: perm.effect ?? 'ALLOW',
            reason: matchDesc
          });

          if (perm.effect === 'DENY') {
            explicitDenyReason = `Explicit DENY triggered by role "${roleName}" on "${perm.resource}:${perm.action}"`;
            break;
          } else {
            hasAllow = true;
          }
        }
      }

      if (explicitDenyReason) {
        break;
      }
    }

    if (explicitDenyReason) {
      return {
        effect: 'DENY',
        reason: explicitDenyReason,
        matchedConditions,
        traces,
        timestamp: new Date().toISOString()
      };
    }

    if (hasAllow) {
      return {
        effect: 'ALLOW',
        reason: `Access granted by matching role permissions: ${matchedConditions.join(', ')}`,
        matchedConditions,
        traces,
        timestamp: new Date().toISOString()
      };
    }

    return {
      effect: 'DENY',
      reason: `No matching role permissions found for action "${action}" on resource "${resource}"`,
      matchedConditions: [],
      traces,
      timestamp: new Date().toISOString()
    };
  }
}

export const defaultRbacEngine = new RbacEngine();
