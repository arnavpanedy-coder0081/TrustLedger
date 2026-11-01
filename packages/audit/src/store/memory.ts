import type {
  AuditEvent,
  AuditChainHead,
  AuditCheckpoint,
  AuditStore,
  VerificationResult
} from '@role-audit/core';

export class MemoryAuditStore implements AuditStore {
  private events: AuditEvent[] = [];
  private chainHeads = new Map<string, AuditChainHead>();
  private checkpoints = new Map<string, AuditCheckpoint[]>();
  private verificationRuns: VerificationResult[] = [];
  private tenantLocks = new Map<string, Promise<void>>();

  public async acquireTenantLock(tenantId: string): Promise<() => void> {
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

  public async appendEvent(event: AuditEvent): Promise<void> {
    this.events.push(event);

    const currentHead = this.chainHeads.get(event.tenant_id);
    const newHead: AuditChainHead = {
      tenant_id: event.tenant_id,
      last_audit_id: event.audit_id,
      last_hash: event.event_hash,
      event_count: (currentHead ? currentHead.event_count : 0) + 1,
      updated_at: event.timestamp
    };
    this.chainHeads.set(event.tenant_id, newHead);
  }

  public async getChainHead(tenantId: string): Promise<AuditChainHead | null> {
    return this.chainHeads.get(tenantId) || null;
  }

  public async getEvents(
    tenantId: string,
    options?: {
      fromTimestamp?: string;
      toTimestamp?: string;
      limit?: number;
      offset?: number;
      ascending?: boolean;
      sortByTimestamp?: boolean;
    }
  ): Promise<AuditEvent[]> {
    let list = this.events.filter((e) => e.tenant_id === tenantId || tenantId === '*');

    if (options?.fromTimestamp) {
      list = list.filter((e) => e.timestamp >= options.fromTimestamp!);
    }
    if (options?.toTimestamp) {
      list = list.filter((e) => e.timestamp <= options.toTimestamp!);
    }

    // By default, preserves append / storage sequence to detect tampering
    if (options?.sortByTimestamp) {
      const ascending = options?.ascending ?? true;
      list = [...list].sort((a, b) => {
        if (a.timestamp === b.timestamp) return 0;
        return ascending ? (a.timestamp < b.timestamp ? -1 : 1) : a.timestamp > b.timestamp ? -1 : 1;
      });
    }

    const offset = options?.offset ?? 0;
    const limit = options?.limit ?? list.length;
    return list.slice(offset, offset + limit);
  }

  public async getEventById(auditId: string): Promise<AuditEvent | null> {
    return this.events.find((e) => e.audit_id === auditId) || null;
  }

  public async countEvents(tenantId: string): Promise<number> {
    return this.events.filter((e) => e.tenant_id === tenantId || tenantId === '*').length;
  }

  public async saveCheckpoint(checkpoint: AuditCheckpoint): Promise<void> {
    let list = this.checkpoints.get(checkpoint.tenant_id);
    if (!list) {
      list = [];
      this.checkpoints.set(checkpoint.tenant_id, list);
    }
    list.push(checkpoint);
  }

  public async getLatestCheckpoint(tenantId: string): Promise<AuditCheckpoint | null> {
    const list = this.checkpoints.get(tenantId);
    if (!list || list.length === 0) return null;
    return list[list.length - 1];
  }

  public async recordVerificationRun(run: VerificationResult): Promise<void> {
    this.verificationRuns.push(run);
  }

  public getRawEvents(): AuditEvent[] {
    return this.events;
  }

  public tamperModifyEvent(auditId: string, mutator: (event: AuditEvent) => void): boolean {
    const ev = this.events.find((e) => e.audit_id === auditId);
    if (!ev) return false;
    mutator(ev);
    return true;
  }

  public tamperDeleteEvent(auditId: string): boolean {
    const idx = this.events.findIndex((e) => e.audit_id === auditId);
    if (idx === -1) return false;
    this.events.splice(idx, 1);
    return true;
  }

  public tamperInsertEvent(index: number, event: AuditEvent): void {
    this.events.splice(index, 0, event);
  }

  public tamperReorderEvents(indexA: number, indexB: number): boolean {
    if (indexA < 0 || indexA >= this.events.length || indexB < 0 || indexB >= this.events.length) {
      return false;
    }
    const temp = this.events[indexA]!;
    this.events[indexA] = this.events[indexB]!;
    this.events[indexB] = temp;
    return true;
  }

  public clear(): void {
    this.events = [];
    this.chainHeads.clear();
    this.checkpoints.clear();
    this.verificationRuns = [];
  }
}
