import { describe, it, expect, beforeEach } from 'vitest';
import {
  AuditChainEngine,
  AuditChainVerifier,
  CheckpointManager,
  MemoryAuditStore
} from '../packages/audit/src/index.js';
import { GENESIS_HASH, generateUuid } from '../packages/core/src/index.js';

describe('Tamper-Evident Audit Chain & Verifier', () => {
  let store: MemoryAuditStore;
  let engine: AuditChainEngine;
  let verifier: AuditChainVerifier;

  beforeEach(() => {
    store = new MemoryAuditStore();
    engine = new AuditChainEngine({ store });
    verifier = new AuditChainVerifier(store);
  });

  it('builds an untampered hash chain starting from GENESIS_HASH', async () => {
    const ev1 = await engine.log({
      tenant_id: 'tenant-test',
      principal_id: 'user-1',
      principal_type: 'human',
      action: 'item:create',
      resource_type: 'item',
      decision: 'ALLOW',
      request_context: { correlationId: 'c1' }
    });

    expect(ev1.previous_hash).toBe(GENESIS_HASH);

    const ev2 = await engine.log({
      tenant_id: 'tenant-test',
      principal_id: 'user-1',
      principal_type: 'human',
      action: 'item:update',
      resource_type: 'item',
      decision: 'ALLOW',
      request_context: { correlationId: 'c2' }
    });

    expect(ev2.previous_hash).toBe(ev1.event_hash);

    const result = await verifier.verifyTenantChain('tenant-test');
    expect(result.verified).toBe(true);
    expect(result.total_events).toBe(2);
    expect(result.first_broken_link).toBeUndefined();
  });

  it('detects Modification Attack and pinpoints the first broken link', async () => {
    for (let i = 0; i < 4; i++) {
      await engine.log({
        tenant_id: 'tenant-tamper',
        principal_id: `user-${i}`,
        principal_type: 'human',
        action: 'doc:edit',
        resource_type: 'doc',
        decision: 'ALLOW',
        request_context: { correlationId: `c-${i}` },
        payload: { text: `original-${i}` }
      });
    }

    const events = await store.getEvents('tenant-tamper');
    // Tamper event at index 2
    store.tamperModifyEvent(events[2]!.audit_id, (ev) => {
      ev.masked_payload = { text: 'MALICIOUS_MODIFIED_TEXT' };
    });

    const result = await verifier.verifyTenantChain('tenant-tamper');
    expect(result.verified).toBe(false);
    expect(result.first_broken_link).toBeDefined();
    expect(result.first_broken_link?.index).toBe(2);
    expect(result.first_broken_link?.audit_id).toBe(events[2]!.audit_id);
    expect(result.first_broken_link?.reason).toBe('EVENT_HASH_MISMATCH');
  });

  it('detects Deletion Attack and pinpoints the missing predecessor', async () => {
    for (let i = 0; i < 5; i++) {
      await engine.log({
        tenant_id: 'tenant-tamper-delete',
        principal_id: `user-${i}`,
        principal_type: 'human',
        action: 'doc:edit',
        resource_type: 'doc',
        decision: 'ALLOW',
        request_context: { correlationId: `c-${i}` }
      });
    }

    const events = await store.getEvents('tenant-tamper-delete');
    // Delete event index 2
    store.tamperDeleteEvent(events[2]!.audit_id);

    const result = await verifier.verifyTenantChain('tenant-tamper-delete');
    expect(result.verified).toBe(false);
    expect(result.first_broken_link?.index).toBe(2);
    expect(result.first_broken_link?.reason).toBe('PREVIOUS_HASH_MISMATCH');
  });

  it('detects Insertion Attack and pinpoints rogue injection', async () => {
    for (let i = 0; i < 3; i++) {
      await engine.log({
        tenant_id: 'tenant-tamper-insert',
        principal_id: `user-${i}`,
        principal_type: 'human',
        action: 'doc:edit',
        resource_type: 'doc',
        decision: 'ALLOW',
        request_context: { correlationId: `c-${i}` }
      });
    }

    // Insert fake event at index 1
    store.tamperInsertEvent(1, {
      audit_id: generateUuid(),
      tenant_id: 'tenant-tamper-insert',
      timestamp: new Date().toISOString(),
      principal_id: 'hacker',
      principal_type: 'human',
      action: 'privilege:escalate',
      resource_type: 'admin',
      resource_id: null,
      decision: 'ALLOW',
      policy_id: null,
      policy_version: null,
      request_context: { correlationId: 'hacked' },
      masked_payload: null,
      previous_hash: 'bogus_hash',
      event_hash: 'bogus_hash',
      schema_version: '1.0.0'
    });

    const result = await verifier.verifyTenantChain('tenant-tamper-insert');
    expect(result.verified).toBe(false);
    expect(result.first_broken_link?.index).toBe(1);
  });

  it('detects Reordering Attack', async () => {
    for (let i = 0; i < 4; i++) {
      await engine.log({
        tenant_id: 'tenant-tamper-reorder',
        principal_id: `user-${i}`,
        principal_type: 'human',
        action: 'step:complete',
        resource_type: 'workflow',
        decision: 'ALLOW',
        request_context: { correlationId: `c-${i}` }
      });
    }

    // Swap index 1 and 2
    store.tamperReorderEvents(1, 2);

    const result = await verifier.verifyTenantChain('tenant-tamper-reorder');
    expect(result.verified).toBe(false);
    expect(result.first_broken_link).toBeDefined();
  });

  it('creates and verifies cryptographically signed checkpoints', async () => {
    for (let i = 0; i < 3; i++) {
      await engine.log({
        tenant_id: 'tenant-anchor',
        principal_id: 'user-anchor',
        principal_type: 'human',
        action: 'order:submit',
        resource_type: 'order',
        decision: 'ALLOW',
        request_context: { correlationId: `c-${i}` }
      });
    }

    const checkpointMgr = new CheckpointManager(store, 'super-secret-checkpoint-key-32-bytes');
    const checkpoint = await checkpointMgr.createCheckpoint('tenant-anchor');

    expect(checkpoint).not.toBeNull();
    expect(checkpoint?.event_count).toBe(3);
    expect(checkpointMgr.verifyCheckpointSignature(checkpoint!)).toBe(true);

    // Tampering with checkpoint signature should fail
    const tamperedCheckpoint = { ...checkpoint!, event_count: 999 };
    expect(checkpointMgr.verifyCheckpointSignature(tamperedCheckpoint)).toBe(false);
  });

  it('detects deletion of the final event using stored head and count', async () => {
    const event = await engine.log({ tenant_id: 'tail-delete', principal_id: 'u', principal_type: 'human', action: 'x', resource_type: 'x', decision: 'ALLOW', request_context: {} });
    store.tamperDeleteEvent(event.audit_id);
    const result = await verifier.verifyTenantChain('tail-delete');
    expect(result.verified).toBe(false);
    expect(result.first_broken_link?.reason).toBe('MISSING_LINK');
  });

  it('requires a strong checkpoint signing secret', () => {
    expect(() => new CheckpointManager(store)).toThrow(/at least 32 bytes/);
    expect(() => new CheckpointManager(store, 'short')).toThrow(/at least 32 bytes/);
  });

  it('masks sensitive request context fields before persistence', async () => {
    await engine.log({ tenant_id: 'context-mask', principal_id: 'u', principal_type: 'human', action: 'x', resource_type: 'x', decision: 'ALLOW', request_context: { token: 'raw-secret', correlationId: 'c1' } });
    const [event] = await store.getEvents('context-mask');
    expect(event?.request_context).toEqual({ token: '[REDACTED]', correlationId: 'c1' });
  });
});
