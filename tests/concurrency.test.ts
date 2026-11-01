import { describe, it, expect } from 'vitest';
import { AuditChainEngine, AuditChainVerifier, MemoryAuditStore } from '../packages/audit/src/index.js';

describe('Concurrency & Serialization Tests', () => {
  it('preserves hash chain ordering and integrity across 50 concurrent writers', async () => {
    const store = new MemoryAuditStore();
    const engine = new AuditChainEngine({ store });
    const verifier = new AuditChainVerifier(store);

    const tenantId = 'tenant-concurrent';
    const totalWriters = 50;

    // Launch 50 simultaneous writers without awaiting them sequentially
    const promises = Array.from({ length: totalWriters }).map((_, i) =>
      engine.log({
        tenant_id: tenantId,
        principal_id: `worker-${i}`,
        principal_type: 'service',
        action: 'job:process',
        resource_type: 'task',
        resource_id: `task-${i}`,
        decision: 'ALLOW',
        request_context: { correlationId: `corr-${i}` },
        payload: { sequence: i }
      })
    );

    await Promise.all(promises);

    const totalStored = await store.countEvents(tenantId);
    expect(totalStored).toBe(totalWriters);

    // Verify entire chain integrity
    const verification = await verifier.verifyTenantChain(tenantId);
    expect(verification.verified).toBe(true);
    expect(verification.total_events).toBe(totalWriters);
    expect(verification.first_broken_link).toBeUndefined();
  });
});
