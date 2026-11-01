import {
  type AuditCheckpoint,
  type AuditStore,
  generateUuid,
  hmacSha256
} from '@role-audit/core';

export class CheckpointManager {
  private store: AuditStore;
  private signingSecret?: string;

  constructor(store: AuditStore, signingSecret?: string) {
    if (!signingSecret || Buffer.byteLength(signingSecret, 'utf8') < 32) {
      throw new Error('Checkpoint signing secret must be configured and at least 32 bytes long');
    }
    this.store = store;
    this.signingSecret = signingSecret;
  }

  /**
   * Generates a tamper-evident checkpoint anchor for a tenant's audit chain.
   */
  public async createCheckpoint(tenantId: string): Promise<AuditCheckpoint | null> {
    const head = await this.store.getChainHead(tenantId);
    if (!head) {
      return null;
    }

    const checkpointId = generateUuid();
    const createdAt = new Date().toISOString();

    const signaturePayload = `${checkpointId}|${tenantId}|${head.event_count}|${head.last_audit_id}|${head.last_hash}|${createdAt}`;
    const signature = hmacSha256(this.signingSecret!, signaturePayload);

    const checkpoint: AuditCheckpoint = {
      checkpoint_id: checkpointId,
      tenant_id: tenantId,
      event_count: head.event_count,
      last_audit_id: head.last_audit_id,
      last_hash: head.last_hash,
      created_at: createdAt,
      signature
    };

    if (this.store.saveCheckpoint) {
      await this.store.saveCheckpoint(checkpoint);
    }

    return checkpoint;
  }

  /**
   * Validates if a checkpoint signature is mathematically authentic.
   */
  public verifyCheckpointSignature(checkpoint: AuditCheckpoint): boolean {
    const signaturePayload = `${checkpoint.checkpoint_id}|${checkpoint.tenant_id}|${checkpoint.event_count}|${checkpoint.last_audit_id}|${checkpoint.last_hash}|${checkpoint.created_at}`;
    const expectedSig = hmacSha256(this.signingSecret!, signaturePayload);

    return checkpoint.signature === expectedSig;
  }
}
