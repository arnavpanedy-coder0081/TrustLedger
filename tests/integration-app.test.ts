import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import { createApp } from '../examples/express-reference-app/src/app.js';
import { MemoryAuditStore } from '../packages/audit/src/index.js';

describe('Express Reference App Integration Tests', () => {
  let server: Server;
  let baseUrl: string;
  let store: MemoryAuditStore;

  beforeAll(async () => {
    store = new MemoryAuditStore();
    const { app } = createApp({ store, allowInsecureDemoIdentity: true });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const address = server.address() as any;
        baseUrl = `http://localhost:${address.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('GET /health returns 200 and metrics snapshot', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.status).toBe('UP');
    expect(body.metrics).toBeDefined();
  });

  it('GET /api/invoices allows authorized manager role', async () => {
    const res = await fetch(`${baseUrl}/api/invoices`, {
      headers: {
        'x-tenant-id': 'tenant-alpha',
        'x-user-id': 'alice-mgr',
        'x-user-roles': 'manager'
      }
    });

    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.invoices).toHaveLength(2);
  });

  it('GET /api/invoices denies unprivileged user', async () => {
    const res = await fetch(`${baseUrl}/api/invoices`, {
      headers: {
        'x-tenant-id': 'tenant-alpha',
        'x-user-id': 'bob-guest',
        'x-user-roles': 'unassigned_role'
      }
    });

    expect(res.status).toBe(403);
    const err = await res.json() as any;
    expect(err.error).toBe('FORBIDDEN');
  });

  it('POST /api/invoices masks sensitive credit card and pseudonymizes email in audit log', async () => {
    const res = await fetch(`${baseUrl}/api/invoices`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-tenant-id': 'tenant-alpha',
        'x-user-id': 'alice-mgr',
        'x-user-roles': 'manager'
      },
      body: JSON.stringify({
        invoiceId: 'inv-888',
        amount: 199.99,
        customerEmail: 'customer@company.com',
        creditCard: '4111 2222 3333 4444',
        cvv: '987',
        billingAddress: '123 Market St'
      })
    });

    expect(res.status).toBe(201);

    // Wait 50ms for audit interceptor finish event
    await new Promise((r) => setTimeout(r, 50));

    const events = await store.getEvents('tenant-alpha');
    const invoiceEvent = events.find((e) => e.action === 'invoice:create');

    expect(invoiceEvent).toBeDefined();
    expect(invoiceEvent?.masked_payload).toBeDefined();

    const masked = invoiceEvent?.masked_payload as any;
    // Credit card masked
    expect(masked.creditCard).toBe('****-****-****-4444');
    // CVV redacted
    expect(masked.cvv).toBe('[REDACTED]');
    // Customer email pseudonymized
    expect(masked.customerEmail).toContain('[PSEUDO:');
    expect(masked.customerEmail).not.toBe('customer@company.com');
  });

  it('GET /api/patients/:id enforces ABAC department match', async () => {
    // 1. Allowed when user department matches resource department (oncology)
    const allowedRes = await fetch(`${baseUrl}/api/patients/p-101?department=oncology`, {
      headers: {
        'x-tenant-id': 'tenant-healthcare',
        'x-user-id': 'dr-smith',
        'x-user-roles': 'manager',
        'x-user-department': 'oncology'
      }
    });
    expect(allowedRes.status).toBe(200);

    // 2. Denied when department differs (radiology vs oncology)
    const deniedRes = await fetch(`${baseUrl}/api/patients/p-101?department=radiology`, {
      headers: {
        'x-tenant-id': 'tenant-healthcare',
        'x-user-id': 'dr-smith',
        'x-user-roles': 'manager',
        'x-user-department': 'oncology'
      }
    });
    expect(deniedRes.status).toBe(403);
  });

  it('GET /api/audit/verify validates audit chain integrity via API', async () => {
    const res = await fetch(`${baseUrl}/api/audit/verify`, {
      headers: {
        'x-tenant-id': 'tenant-alpha',
        'x-user-id': 'auditor-eve',
        'x-user-roles': 'auditor'
      }
    });

    expect(res.status).toBe(200);
    const result = await res.json() as any;
    expect(result.verified).toBe(true);
    expect(result.total_events).toBeGreaterThan(0);
    expect(result.genesis_hash).toBeDefined();
  });
});
