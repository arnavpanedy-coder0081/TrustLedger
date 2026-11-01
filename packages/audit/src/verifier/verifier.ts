import {
  type AuditStore,
  type VerificationResult,
  type VerificationBrokenLink,
  computeEventHash,
  GENESIS_HASH,
  defaultMetrics
} from '@role-audit/core';

export class AuditChainVerifier {
  private store: AuditStore;

  constructor(store: AuditStore) {
    this.store = store;
  }

  /**
   * Verifies the tamper-evident hash chain for a specific tenant or all streams.
   * Recalculates hashes and detects modification, deletion, insertion, or reordering.
   */
  public async verifyTenantChain(
    tenantId: string,
    options?: { limit?: number; offset?: number }
  ): Promise<VerificationResult> {
    const startTime = performance.now();
    const checkedAt = new Date().toISOString();

    const events = await this.store.getEvents(tenantId, {
      ascending: true,
      limit: options?.limit,
      offset: options?.offset
    });

    const isFullScan = options?.limit === undefined && (options?.offset === undefined || options.offset === 0);
    const storedHead = isFullScan ? await this.store.getChainHead(tenantId) : null;
    const storedCount = isFullScan ? await this.store.countEvents(tenantId) : null;

    if (events.length === 0) {
      const result: VerificationResult = {
        tenant_id: tenantId,
        verified: !storedHead && (storedCount === null || storedCount === 0),
        total_events: 0,
        genesis_hash: GENESIS_HASH,
        head_hash: null,
        duration_ms: performance.now() - startTime,
        checked_at: checkedAt,
        first_broken_link: storedHead || (storedCount ?? 0) > 0 ? {
          index: 0, audit_id: storedHead?.last_audit_id ?? 'missing',
          expected_previous_hash: GENESIS_HASH, actual_previous_hash: 'MISSING_EVENTS',
          expected_event_hash: storedHead?.last_hash ?? 'MISSING_EVENTS', actual_event_hash: 'MISSING_EVENTS',
          reason: 'MISSING_LINK', details: 'Stored chain head/count references events that are missing.'
        } : undefined
      };
      if (this.store.recordVerificationRun) {
        await this.store.recordVerificationRun(result);
      }
      return result;
    }

    let firstBrokenLink: VerificationBrokenLink | undefined;

    for (let i = 0; i < events.length; i++) {
      const event = events[i]!;

      // 1. Check Genesis Block
      if (i === 0) {
        if (event.previous_hash !== GENESIS_HASH) {
          firstBrokenLink = {
            index: 0,
            audit_id: event.audit_id,
            expected_previous_hash: GENESIS_HASH,
            actual_previous_hash: event.previous_hash,
            expected_event_hash: event.event_hash,
            actual_event_hash: event.event_hash,
            reason: 'GENESIS_MISMATCH',
            details: `Root audit event previous_hash does not match the GENESIS_HASH (${GENESIS_HASH})`
          };
          break;
        }
      } else {
        const prevEvent = events[i - 1]!;

        // 2. Check Chain Predecessor Linkage
        if (event.previous_hash !== prevEvent.event_hash) {
          // Check if timestamp is inverted
          const isOutOfOrder = event.timestamp < prevEvent.timestamp;
          firstBrokenLink = {
            index: i,
            audit_id: event.audit_id,
            expected_previous_hash: prevEvent.event_hash,
            actual_previous_hash: event.previous_hash,
            expected_event_hash: event.event_hash,
            actual_event_hash: event.event_hash,
            reason: isOutOfOrder ? 'OUT_OF_ORDER' : 'PREVIOUS_HASH_MISMATCH',
            details: isOutOfOrder
              ? `Event out of chronological order at index ${i} (${event.timestamp} preceded by ${prevEvent.timestamp})`
              : `Broken link at index ${i}: event previous_hash does not point to predecessor's event_hash (detected deletion or insertion)`
          };
          break;
        }
      }

      // 3. Recalculate and Verify Canonical SHA-256 Event Hash
      const expectedEventHash = computeEventHash(
        event as unknown as Record<string, unknown>,
        event.previous_hash
      );

      if (expectedEventHash !== event.event_hash) {
        firstBrokenLink = {
          index: i,
          audit_id: event.audit_id,
          expected_previous_hash: event.previous_hash,
          actual_previous_hash: event.previous_hash,
          expected_event_hash: expectedEventHash,
          actual_event_hash: event.event_hash,
          reason: 'EVENT_HASH_MISMATCH',
          details: `Payload or metadata modification detected for audit_id "${event.audit_id}" at index ${i}. Computed hash differs from stored event_hash.`
        };
        break;
      }
    }

    const durationMs = performance.now() - startTime;
    const lastEvent = events[events.length - 1];
    if (!firstBrokenLink && isFullScan && (events.length !== storedCount || !storedHead ||
        lastEvent?.event_hash !== storedHead.last_hash || lastEvent?.audit_id !== storedHead.last_audit_id)) {
      firstBrokenLink = {
        index: events.length, audit_id: storedHead?.last_audit_id ?? 'missing',
        expected_previous_hash: lastEvent?.event_hash ?? GENESIS_HASH,
        actual_previous_hash: storedHead?.last_hash ?? 'MISSING_HEAD',
        expected_event_hash: storedHead?.last_hash ?? 'MISSING_HEAD',
        actual_event_hash: lastEvent?.event_hash ?? 'MISSING_EVENTS',
        reason: 'MISSING_LINK', details: `Stored chain head/count mismatch (stored count ${storedCount}, observed ${events.length}).`
      };
    }
    const verified = !firstBrokenLink;

    const result: VerificationResult = {
      tenant_id: tenantId,
      verified,
      total_events: events.length,
      genesis_hash: GENESIS_HASH,
      head_hash: lastEvent ? lastEvent.event_hash : null,
      first_broken_link: firstBrokenLink,
      duration_ms: durationMs,
      checked_at: checkedAt
    };

    defaultMetrics.recordTiming('audit.verification_duration_ms', durationMs);
    defaultMetrics.incrementCounter(
      verified ? 'audit.verification_passed_total' : 'audit.verification_failed_total'
    );

    if (this.store.recordVerificationRun) {
      await this.store.recordVerificationRun(result);
    }

    return result;
  }
}
