import {
  type AuditEvent,
  type AuditEventInput,
  type AuditStore,
  computeEventHash,
  generateUuid,
  GENESIS_HASH,
  AuditPersistenceError,
  defaultMetrics
} from '@role-audit/core';
import { DataMasker, defaultMasker } from '@role-audit/masking';
import { MemoryAuditStore } from '../store/memory.js';

export interface AuditChainEngineOptions {
  store?: AuditStore;
  masker?: DataMasker;
  strictMode?: boolean;
  asyncBatching?: boolean;
  batchSize?: number;
  flushIntervalMs?: number;
  schemaVersion?: string;
  onError?: (err: unknown, eventInput: AuditEventInput) => void;
}

export class AuditChainEngine {
  private store: AuditStore;
  private masker: DataMasker;
  private strictMode: boolean;
  private asyncBatching: boolean;
  private batchSize: number;
  private flushIntervalMs: number;
  private schemaVersion: string;
  private onError?: (err: unknown, eventInput: AuditEventInput) => void;

  private queue: AuditEventInput[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private isFlushing = false;
  private tenantLocks = new Map<string, Promise<void>>();

  constructor(options: AuditChainEngineOptions = {}) {
    this.store = options.store || new MemoryAuditStore();
    this.masker = options.masker || defaultMasker;
    this.strictMode = options.strictMode ?? false;
    this.asyncBatching = options.asyncBatching ?? false;
    this.batchSize = options.batchSize ?? 50;
    this.flushIntervalMs = options.flushIntervalMs ?? 200;
    this.schemaVersion = options.schemaVersion ?? '1.0.0';
    this.onError = options.onError;

    if (this.asyncBatching) {
      this.flushTimer = setInterval(() => {
        this.flushQueue().catch((err) => {
          if (this.onError) this.onError(err, null as any);
        });
      }, this.flushIntervalMs);
    }
  }

  public getStore(): AuditStore {
    return this.store;
  }

  /**
   * Acquire per-tenant serialization lock to preserve strict hash chain ordering
   */
  private async acquireTenantLock(tenantId: string): Promise<() => void> {
    while (this.tenantLocks.has(tenantId)) {
      await this.tenantLocks.get(tenantId);
    }
    let releaseLock: () => void = () => {};
    const lockPromise = new Promise<void>((resolve) => {
      releaseLock = () => {
        this.tenantLocks.delete(tenantId);
        resolve();
      };
    });
    this.tenantLocks.set(tenantId, lockPromise);
    return releaseLock;
  }

  /**
   * Logs a structured audit event. In synchronous mode, it guarantees immediate
   * hash computation and persistent storage. In batch mode, it enqueues the event.
   */
  public async log(input: AuditEventInput): Promise<AuditEvent> {
    if (this.asyncBatching) {
      this.queue.push(input);
      defaultMetrics.setGauge('audit.queue_depth', this.queue.length);
      if (this.queue.length >= this.batchSize) {
        setImmediate(() => {
          this.flushQueue().catch((err) => {
            if (this.onError) this.onError(err, input);
          });
        });
      }
      // Return optimistic event representation
      return this.constructEventOptimistic(input);
    }

    return this.processAndPersistEvent(input);
  }

  private constructEventOptimistic(input: AuditEventInput): AuditEvent {
    const auditId = input.audit_id || generateUuid();
    const timestamp = input.timestamp || new Date().toISOString();
    const maskedPayload = input.payload ? this.masker.mask(input.payload) : null;

    return {
      audit_id: auditId,
      tenant_id: input.tenant_id,
      timestamp,
      principal_id: input.principal_id,
      principal_type: input.principal_type,
      action: input.action,
      resource_type: input.resource_type,
      resource_id: input.resource_id ?? null,
      decision: input.decision,
      policy_id: input.policy_id ?? null,
      policy_version: input.policy_version ?? null,
      request_context: this.masker.mask(input.request_context),
      masked_payload: maskedPayload,
      previous_hash: 'PENDING_ASYNC_FLUSH',
      event_hash: 'PENDING_ASYNC_FLUSH',
      schema_version: input.schema_version || this.schemaVersion
    };
  }

  private async processAndPersistEvent(input: AuditEventInput): Promise<AuditEvent> {
    const releaseLock = await this.acquireTenantLock(input.tenant_id);

    try {
      return await defaultMetrics.timeAsync('audit.persist_duration_ms', async () => {
        const auditId = input.audit_id || generateUuid();
        const timestamp = input.timestamp || new Date().toISOString();

        // 1. Mask sensitive PII & secrets before audit serialization (PRD Section 6.4)
        const maskedPayload = input.payload ? this.masker.mask(input.payload) : null;

        // 2. Retrieve previous chain head
        const currentHead = await this.store.getChainHead(input.tenant_id);
        const previousHash = currentHead ? currentHead.last_hash : GENESIS_HASH;

        // 3. Build canonical event representation without hash fields
        const eventWithoutHash = {
          audit_id: auditId,
          tenant_id: input.tenant_id,
          timestamp,
          principal_id: input.principal_id,
          principal_type: input.principal_type,
          action: input.action,
          resource_type: input.resource_type,
          resource_id: input.resource_id ?? null,
          decision: input.decision,
          policy_id: input.policy_id ?? null,
          policy_version: input.policy_version ?? null,
          request_context: this.masker.mask(input.request_context),
          masked_payload: maskedPayload,
          schema_version: input.schema_version || this.schemaVersion
        };

        // 4. Compute SHA-256 event hash (PRD Section 11)
        const eventHash = computeEventHash(eventWithoutHash, previousHash);

        const auditEvent: AuditEvent = {
          ...eventWithoutHash,
          previous_hash: previousHash,
          event_hash: eventHash
        };

        // 5. Append event to persistent store
        await this.store.appendEvent(auditEvent);

        defaultMetrics.incrementCounter('audit.events_logged_total');
        defaultMetrics.incrementCounter(`audit.events_by_decision.${input.decision}`);
        return auditEvent;
      });
    } catch (err) {
      defaultMetrics.incrementCounter('audit.persist_failures_total');
      if (this.onError) {
        this.onError(err, input);
      }
      if (this.strictMode) {
        throw new AuditPersistenceError('Strict audit logging failed: could not persist audit event', err);
      }
      throw err;
    } finally {
      releaseLock();
    }
  }

  public async flushQueue(): Promise<void> {
    if (this.isFlushing || this.queue.length === 0) return;
    this.isFlushing = true;

    try {
      const itemsToProcess = [...this.queue];
      this.queue = [];
      defaultMetrics.setGauge('audit.queue_depth', 0);

      // Group by tenant to preserve sequential ordering per stream
      const byTenant = new Map<string, AuditEventInput[]>();
      for (const item of itemsToProcess) {
        let list = byTenant.get(item.tenant_id);
        if (!list) {
          list = [];
          byTenant.set(item.tenant_id, list);
        }
        list.push(item);
      }

      for (const [tenantId, tenantItems] of byTenant.entries()) {
        for (const item of tenantItems) {
          try {
            await this.processAndPersistEvent(item);
          } catch (err) {
            if (this.onError) this.onError(err, item);
          }
        }
      }
    } finally {
      this.isFlushing = false;
    }
  }

  public async close(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flushQueue();
  }
}
