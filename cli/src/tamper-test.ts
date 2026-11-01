import { AuditChainEngine, AuditChainVerifier, MemoryAuditStore } from '@role-audit/audit';
import { generateUuid } from '@role-audit/core';

export async function runTamperAttackSuite(): Promise<boolean> {
  console.log('\n=============================================================');
  console.log(' ROLE-AUDIT TAMPER-EVIDENT VERIFICATION ATTACK SUITE');
  console.log(' Testing: Modification, Deletion, Insertion, Reordering');
  console.log('=============================================================\n');

  let allPassed = true;

  // Helper to generate a baseline valid chain with 5 events
  async function createBaselineChain(tenantId: string) {
    const store = new MemoryAuditStore();
    const engine = new AuditChainEngine({ store });
    const verifier = new AuditChainVerifier(store);

    for (let i = 1; i <= 5; i++) {
      await engine.log({
        tenant_id: tenantId,
        principal_id: `user-${i}`,
        principal_type: 'human',
        action: `record:action-${i}`,
        resource_type: 'document',
        resource_id: `doc-${i}`,
        decision: 'ALLOW',
        request_context: { correlationId: `corr-${i}` },
        payload: { field: `value-${i}` }
      });
    }

    return { store, engine, verifier };
  }

  // --- Attack 1: Baseline Clean Chain Verification ---
  {
    process.stdout.write('Scenario 0: Untampered baseline chain verification... ');
    const { verifier } = await createBaselineChain('tenant-baseline');
    const result = await verifier.verifyTenantChain('tenant-baseline');
    if (result.verified && result.total_events === 5) {
      console.log('PASSED (100% Valid Chain Verified)');
    } else {
      console.log('FAILED (Unexpected error)');
      allPassed = false;
    }
  }

  // --- Attack 1: Modification Attack ---
  {
    process.stdout.write('Scenario 1: Modification Attack (tampering payload of event #2)... ');
    const { store, verifier } = await createBaselineChain('tenant-modify');
    const events = await store.getEvents('tenant-modify');
    const targetEvent = events[2]!;

    // Tamper: alter payload in place
    store.tamperModifyEvent(targetEvent.audit_id, (ev) => {
      ev.masked_payload = { ...ev.masked_payload, field: 'MALICIOUS_TAMPERED_DATA' };
    });

    const result = await verifier.verifyTenantChain('tenant-modify');
    if (!result.verified && result.first_broken_link?.reason === 'EVENT_HASH_MISMATCH' && result.first_broken_link.index === 2) {
      console.log(`DETECTED! Broken link flagged at index ${result.first_broken_link.index} (Reason: ${result.first_broken_link.reason})`);
    } else {
      console.log('FAILED: Tamper went undetected!');
      allPassed = false;
    }
  }

  // --- Attack 2: Deletion Attack ---
  {
    process.stdout.write('Scenario 2: Deletion Attack (deleting event #3 from chain)... ');
    const { store, verifier } = await createBaselineChain('tenant-delete');
    const events = await store.getEvents('tenant-delete');
    const targetEvent = events[2]!;

    store.tamperDeleteEvent(targetEvent.audit_id);

    const result = await verifier.verifyTenantChain('tenant-delete');
    if (!result.verified && result.first_broken_link?.reason === 'PREVIOUS_HASH_MISMATCH' && result.first_broken_link.index === 2) {
      console.log(`DETECTED! Missing predecessor link flagged at index ${result.first_broken_link.index}`);
    } else {
      console.log('FAILED: Deletion went undetected!');
      allPassed = false;
    }
  }

  // --- Attack 3: Insertion Attack ---
  {
    process.stdout.write('Scenario 3: Insertion Attack (injecting unauthorized rogue event)... ');
    const { store, verifier } = await createBaselineChain('tenant-insert');

    // Tamper: forge an injected event
    store.tamperInsertEvent(2, {
      audit_id: generateUuid(),
      tenant_id: 'tenant-insert',
      timestamp: new Date().toISOString(),
      principal_id: 'attacker',
      principal_type: 'human',
      action: 'admin:backdoor',
      resource_type: 'system',
      resource_id: 'root',
      decision: 'ALLOW',
      policy_id: null,
      policy_version: null,
      request_context: { correlationId: 'rogue-1' },
      masked_payload: null,
      previous_hash: 'fake_previous_hash',
      event_hash: 'fake_event_hash',
      schema_version: '1.0.0'
    });

    const result = await verifier.verifyTenantChain('tenant-insert');
    if (!result.verified && (result.first_broken_link?.reason === 'PREVIOUS_HASH_MISMATCH' || result.first_broken_link?.reason === 'EVENT_HASH_MISMATCH')) {
      console.log(`DETECTED! Injection broke linkage at index ${result.first_broken_link.index}`);
    } else {
      console.log('FAILED: Insertion went undetected!');
      allPassed = false;
    }
  }

  // --- Attack 4: Reordering Attack ---
  {
    process.stdout.write('Scenario 4: Reordering Attack (swapping event #1 and event #2)... ');
    const { store, verifier } = await createBaselineChain('tenant-reorder');

    store.tamperReorderEvents(1, 2);

    const result = await verifier.verifyTenantChain('tenant-reorder');
    if (!result.verified) {
      console.log(`DETECTED! Reordering broke linkage at index ${result.first_broken_link?.index} (Reason: ${result.first_broken_link?.reason})`);
    } else {
      console.log('FAILED: Reordering went undetected!');
      allPassed = false;
    }
  }

  console.log('\n=============================================================');
  console.log(allPassed ? '>>> ALL TAMPERING ATTACK FIXTURES SUCCESSFULLY DETECTED <<<' : '>>> SOME TAMPERING DETECTIONS FAILED <<<');
  console.log('=============================================================\n');
  return allPassed;
}

if (process.argv[1]?.includes('tamper-test')) {
  runTamperAttackSuite().catch(console.error);
}
