import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditChainEngine, AuditChainVerifier, FileAuditStore } from '../packages/audit/src/index.js';

const files: string[] = [];
afterEach(() => { for (const file of files.splice(0)) fs.rmSync(file, { force: true }); });

describe('durable desktop audit store', () => {
  it('persists events and stored heads across store instances', async () => {
    const file = path.join(os.tmpdir(), `trustledger-${Date.now()}-${Math.random()}.json`);
    files.push(file);
    const firstStore = new FileAuditStore(file);
    const engine = new AuditChainEngine({ store: firstStore });
    await engine.log({ tenant_id: 'persisted', principal_id: 'user', principal_type: 'human', action: 'read', resource_type: 'record', decision: 'ALLOW', request_context: {} });
    const reopened = new FileAuditStore(file);
    const verify = await new AuditChainVerifier(reopened).verifyTenantChain('persisted');
    expect(verify.verified).toBe(true);
    expect(verify.total_events).toBe(1);
  });
});
