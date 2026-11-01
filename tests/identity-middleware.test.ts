import { describe, expect, it, vi } from 'vitest';
import { identityMiddleware } from '../packages/audit/src/middleware/express.js';

describe('identityMiddleware', () => {
  it('ignores caller-controlled identity and tenant headers without trusted resolvers', async () => {
    const req = {
      headers: {
        'x-user-id': 'attacker',
        'x-user-roles': 'admin',
        'x-tenant-id': 'victim-tenant',
      },
      method: 'GET',
      ip: '127.0.0.1',
      socket: { remoteAddress: '127.0.0.1' },
    } as any;
    const res = { setHeader: vi.fn() } as any;
    const next = vi.fn();

    await identityMiddleware()(req, res, next);

    expect(req.securityContext.principal).toMatchObject({
      id: 'anonymous',
      type: 'anonymous',
      roles: [],
    });
    expect(req.securityContext.tenant.tenantId).toBe('default-tenant');
    expect(next).toHaveBeenCalledOnce();
  });

  it('uses identity and tenant values supplied by trusted resolvers', async () => {
    const req = {
      headers: {},
      method: 'GET',
      ip: '127.0.0.1',
      socket: { remoteAddress: '127.0.0.1' },
    } as any;
    const res = { setHeader: vi.fn() } as any;

    await identityMiddleware({
      resolvePrincipal: () => ({ id: 'alice', type: 'human', roles: ['auditor'] }),
      resolveTenant: () => ({ tenantId: 'tenant-a', status: 'active' }),
    })(req, res, vi.fn());

    expect(req.securityContext.principal).toMatchObject({ id: 'alice', roles: ['auditor'] });
    expect(req.securityContext.tenant.tenantId).toBe('tenant-a');
  });
});
