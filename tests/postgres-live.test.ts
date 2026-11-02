import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { AuditChainEngine, AuditChainVerifier } from '../packages/audit/src/index.js';
import { AuditPersistenceError } from '../packages/core/src/index.js';
import { PostgresAuditStore } from '../packages/postgres/src/index.js';

const connectionString = process.env.DATABASE_URL;
const liveDatabaseSuite = connectionString ? describe : describe.skip;
const tenantPrefix = `postgres-live-${randomUUID()}`;
const integrityTenant = `${tenantPrefix}-integrity`;
const concurrencyTenant = `${tenantPrefix}-concurrency`;

liveDatabaseSuite('Live PostgreSQL audit verification', () => {
  let storeA: PostgresAuditStore;
  let storeB: PostgresAuditStore;

  beforeAll(async () => {
    storeA = new PostgresAuditStore({ connectionString });
    storeB = new PostgresAuditStore({ connectionString });
    await storeA.runMigrations();
  });

  afterAll(async () => {
    if (!storeA) return;
    const pool = storeA.getPool();
    for (const tenantId of [integrityTenant, concurrencyTenant]) {
      await pool.query('DELETE FROM audit_events WHERE tenant_id = $1', [tenantId]);
      await pool.query('DELETE FROM audit_chain_heads WHERE tenant_id = $1', [tenantId]);
      await pool.query('DELETE FROM audit_checkpoints WHERE tenant_id = $1', [tenantId]);
      await pool.query('DELETE FROM verification_runs WHERE tenant_id = $1', [tenantId]);
    }
    await Promise.all([storeA.close(), storeB.close()]);
  });

  it('persists and verifies a real chain, then detects a database row change', async () => {
    const engine = new AuditChainEngine({ store: storeA, strictMode: true });
    const verifier = new AuditChainVerifier(storeA);

    for (let sequence = 0; sequence < 3; sequence++) {
      await engine.log({
        tenant_id: integrityTenant,
        principal_id: 'postgres-integration-test',
        principal_type: 'system',
        action: `integration:event-${sequence}`,
        resource_type: 'test-record',
        resource_id: `record-${sequence}`,
        decision: 'ALLOW',
        request_context: { correlationId: `${tenantPrefix}-${sequence}` },
        payload: { sequence }
      });
    }

    const cleanResult = await verifier.verifyTenantChain(integrityTenant);
    expect(cleanResult.verified).toBe(true);
    expect(cleanResult.total_events).toBe(3);

    const events = await storeA.getEvents(integrityTenant);
    await storeA.getPool().query(
      'UPDATE audit_events SET masked_payload = $1::jsonb WHERE audit_id = $2',
      [JSON.stringify({ tampered: true }), events[1]!.audit_id]
    );

    const tamperedResult = await verifier.verifyTenantChain(integrityTenant);
    expect(tamperedResult.verified).toBe(false);
    expect(tamperedResult.first_broken_link?.reason).toBe('EVENT_HASH_MISMATCH');
  });

  it('serializes concurrent writers across independent pools without losing chain integrity', async () => {
    let initialHeadReads = 0;
    let releaseInitialReads!: () => void;
    const initialReadsComplete = new Promise<void>((resolve) => {
      releaseInitialReads = resolve;
    });
    const synchronizeFirstHeadRead = (store: PostgresAuditStore) => new Proxy(store, {
      get(target, property, receiver) {
        if (property === 'getChainHead') {
          return async (tenantId: string) => {
            const head = await target.getChainHead(tenantId);
            if (tenantId === concurrencyTenant && initialHeadReads < 2) {
              initialHeadReads++;
              if (initialHeadReads === 2) releaseInitialReads();
              await initialReadsComplete;
            }
            return head;
          };
        }
        const value = Reflect.get(target, property, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      }
    });

    const engineA = new AuditChainEngine({ store: synchronizeFirstHeadRead(storeA), strictMode: true });
    const engineB = new AuditChainEngine({ store: synchronizeFirstHeadRead(storeB), strictMode: true });
    const writesPerWriter = 12;
    let staleRetries = 0;

    const writeBatch = async (engine: AuditChainEngine, writer: string) => {
      for (let sequence = 0; sequence < writesPerWriter; sequence++) {
        let retries = 0;
        while (true) {
          try {
            await engine.log({
              tenant_id: concurrencyTenant,
              principal_id: writer,
              principal_type: 'system',
              action: 'integration:concurrent-write',
              resource_type: 'test-record',
              resource_id: `${writer}-${sequence}`,
              decision: 'ALLOW',
              request_context: { correlationId: `${tenantPrefix}-${writer}-${sequence}` },
              payload: { writer, sequence }
            });
            break;
          } catch (error) {
            const cause = error instanceof AuditPersistenceError ? error.causeError : error;
            if (!(cause instanceof Error) || !cause.message.includes('Stale audit chain head') || retries++ >= 50) {
              throw error;
            }
            staleRetries++;
            await new Promise((resolve) => setTimeout(resolve, 5));
          }
        }
      }
    };

    await Promise.all([writeBatch(engineA, 'writer-a'), writeBatch(engineB, 'writer-b')]);

    const events = await storeA.getEvents(concurrencyTenant);
    const result = await new AuditChainVerifier(storeA).verifyTenantChain(concurrencyTenant);
    expect(events).toHaveLength(writesPerWriter * 2);
    expect(result.verified).toBe(true);
    expect(result.total_events).toBe(writesPerWriter * 2);
    expect(staleRetries).toBeGreaterThan(0);
  });
});
