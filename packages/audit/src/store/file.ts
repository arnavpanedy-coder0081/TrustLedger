import fs from 'node:fs';
import path from 'node:path';
import { GENESIS_HASH, type AuditEvent, type AuditChainHead, type AuditCheckpoint, type AuditStore, type VerificationResult } from '@role-audit/core';

type Snapshot = { events: AuditEvent[]; heads: AuditChainHead[]; checkpoints: AuditCheckpoint[]; verifications: VerificationResult[] };

/** Local durable store for the single-user desktop app. Writes snapshots via atomic rename. */
export class FileAuditStore implements AuditStore {
  private events: AuditEvent[] = [];
  private heads = new Map<string, AuditChainHead>();
  private checkpoints: AuditCheckpoint[] = [];
  private verifications: VerificationResult[] = [];

  constructor(private readonly filename = path.join(process.env.LOCALAPPDATA || process.env.HOME || process.cwd(), 'TrustLedger', 'audit-events.json')) {
    try {
      const data = JSON.parse(fs.readFileSync(filename, 'utf8')) as Snapshot;
      this.events = Array.isArray(data.events) ? data.events : [];
      this.heads = new Map((data.heads || []).map((head) => [head.tenant_id, head]));
      this.checkpoints = data.checkpoints || [];
      this.verifications = data.verifications || [];
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filename), { recursive: true });
    const temp = `${this.filename}.${process.pid}.tmp`;
    fs.writeFileSync(temp, JSON.stringify({ events: this.events, heads: [...this.heads.values()], checkpoints: this.checkpoints, verifications: this.verifications } satisfies Snapshot), { mode: 0o600 });
    fs.renameSync(temp, this.filename);
  }

  async appendEvent(event: AuditEvent): Promise<void> {
    const head = this.heads.get(event.tenant_id);
    if (event.previous_hash !== (head?.last_hash ?? GENESIS_HASH)) throw new Error('Stale local audit chain head');
    this.events.push(event);
    this.heads.set(event.tenant_id, { tenant_id: event.tenant_id, last_audit_id: event.audit_id, last_hash: event.event_hash, event_count: (head?.event_count || 0) + 1, updated_at: event.timestamp });
    this.persist();
  }

  async getChainHead(tenantId: string): Promise<AuditChainHead | null> { return this.heads.get(tenantId) || null; }
  async getEvents(tenantId: string, options: { fromTimestamp?: string; toTimestamp?: string; limit?: number; offset?: number; ascending?: boolean } = {}): Promise<AuditEvent[]> {
    let result = this.events.filter((e) => (tenantId === '*' || e.tenant_id === tenantId) && (!options.fromTimestamp || e.timestamp >= options.fromTimestamp) && (!options.toTimestamp || e.timestamp <= options.toTimestamp));
    if (options.ascending === false) result = [...result].reverse();
    return result.slice(options.offset || 0, (options.offset || 0) + (options.limit ?? result.length));
  }
  async getEventById(auditId: string): Promise<AuditEvent | null> { return this.events.find((e) => e.audit_id === auditId) || null; }
  async countEvents(tenantId: string): Promise<number> { return this.events.filter((e) => tenantId === '*' || e.tenant_id === tenantId).length; }
  async saveCheckpoint(checkpoint: AuditCheckpoint): Promise<void> { this.checkpoints.push(checkpoint); this.persist(); }
  async getLatestCheckpoint(tenantId: string): Promise<AuditCheckpoint | null> { return [...this.checkpoints].reverse().find((c) => c.tenant_id === tenantId) || null; }
  async recordVerificationRun(run: VerificationResult): Promise<void> { this.verifications.push(run); this.persist(); }

  tamperModifyEvent(id: string, mutator: (event: AuditEvent) => void): boolean { const event = this.events.find((e) => e.audit_id === id); if (!event) return false; mutator(event); this.persist(); return true; }
  tamperDeleteEvent(id: string): boolean { const index = this.events.findIndex((e) => e.audit_id === id); if (index < 0) return false; this.events.splice(index, 1); this.persist(); return true; }
  tamperInsertEvent(index: number, event: AuditEvent): void { this.events.splice(index, 0, event); this.persist(); }
  tamperReorderEvents(a: number, b: number): boolean { if (!this.events[a] || !this.events[b]) return false; [this.events[a], this.events[b]] = [this.events[b]!, this.events[a]!]; this.persist(); return true; }
  clear(): void { this.events = []; this.heads.clear(); this.checkpoints = []; this.verifications = []; this.persist(); }
}
