import pg from 'pg';
import type {
  AuditEvent,
  AuditChainHead,
  AuditCheckpoint,
  AuditStore,
  VerificationResult
} from '@role-audit/core';
import { GENESIS_HASH } from '@role-audit/core';

export interface PostgresStoreOptions {
  connectionString?: string;
  pool?: pg.Pool;
  schema?: string;
}

export class PostgresAuditStore implements AuditStore {
  private pool: pg.Pool;
  private isOwnedPool = false;

  constructor(options: PostgresStoreOptions = {}) {
    if (options.pool) {
      this.pool = options.pool;
    } else {
      this.pool = new pg.Pool({
        connectionString: options.connectionString || process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/role_audit_db'
      });
      this.isOwnedPool = true;
    }
  }

  public getPool(): pg.Pool {
    return this.pool;
  }

  /**
   * Runs database schema migrations to initialize audit, policy, and verification tables.
   */
  public async runMigrations(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_chain_heads (
          tenant_id VARCHAR(128) PRIMARY KEY,
          last_audit_id UUID NOT NULL,
          last_hash VARCHAR(64) NOT NULL,
          event_count BIGINT NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_events (
          event_seq BIGSERIAL UNIQUE NOT NULL,
          audit_id UUID PRIMARY KEY,
          tenant_id VARCHAR(128) NOT NULL,
          timestamp TIMESTAMPTZ NOT NULL,
          principal_id VARCHAR(256) NOT NULL,
          principal_type VARCHAR(64) NOT NULL,
          action VARCHAR(128) NOT NULL,
          resource_type VARCHAR(128) NOT NULL,
          resource_id VARCHAR(256),
          decision VARCHAR(32) NOT NULL,
          policy_id VARCHAR(128),
          policy_version INT,
          request_context JSONB NOT NULL DEFAULT '{}'::jsonb,
          masked_payload JSONB,
          previous_hash VARCHAR(64) NOT NULL,
          event_hash VARCHAR(64) NOT NULL,
          schema_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      await client.query('ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_seq BIGSERIAL');

      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_timestamp ON audit_events (tenant_id, timestamp ASC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_principal ON audit_events (tenant_id, principal_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_action ON audit_events (tenant_id, action);
        CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_decision ON audit_events (tenant_id, decision);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_checkpoints (
          checkpoint_id UUID PRIMARY KEY,
          tenant_id VARCHAR(128) NOT NULL,
          event_count BIGINT NOT NULL,
          last_audit_id UUID NOT NULL,
          last_hash VARCHAR(64) NOT NULL,
          signature VARCHAR(128) NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS verification_runs (
          run_id UUID PRIMARY KEY,
          tenant_id VARCHAR(128) NOT NULL,
          verified BOOLEAN NOT NULL,
          total_events BIGINT NOT NULL,
          genesis_hash VARCHAR(64) NOT NULL,
          head_hash VARCHAR(64),
          first_broken_link JSONB,
          duration_ms DOUBLE PRECISION NOT NULL,
          checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Appends an audit event inside a serialized transaction using advisory locking per tenant.
   */
  public async appendEvent(event: AuditEvent): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Advisory transaction lock by tenant to serialize concurrent writes to the same hash chain
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [event.tenant_id]);

      // The application computes a hash from the previous head. Reject stale
      // writers while holding the same database lock instead of corrupting the chain.
      const head = await client.query(
        'SELECT last_hash FROM audit_chain_heads WHERE tenant_id = $1 FOR UPDATE',
        [event.tenant_id]
      );
      const expectedPrevious = head.rows[0]?.last_hash ?? GENESIS_HASH;
      if (event.previous_hash !== expectedPrevious) {
        throw new Error('Stale audit chain head; retry the audit append');
      }

      // Insert audit record
      await client.query(
        `INSERT INTO audit_events (
          audit_id, tenant_id, timestamp, principal_id, principal_type,
          action, resource_type, resource_id, decision, policy_id, policy_version,
          request_context, masked_payload, previous_hash, event_hash, schema_version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
        [
          event.audit_id,
          event.tenant_id,
          event.timestamp,
          event.principal_id,
          event.principal_type,
          event.action,
          event.resource_type,
          event.resource_id,
          event.decision,
          event.policy_id,
          event.policy_version,
          JSON.stringify(event.request_context),
          event.masked_payload ? JSON.stringify(event.masked_payload) : null,
          event.previous_hash,
          event.event_hash,
          event.schema_version
        ]
      );

      // Update chain head
      await client.query(
        `INSERT INTO audit_chain_heads (tenant_id, last_audit_id, last_hash, event_count, updated_at)
         VALUES ($1, $2, $3, 1, $4)
         ON CONFLICT (tenant_id) DO UPDATE SET
           last_audit_id = EXCLUDED.last_audit_id,
           last_hash = EXCLUDED.last_hash,
           event_count = audit_chain_heads.event_count + 1,
           updated_at = EXCLUDED.updated_at`,
        [event.tenant_id, event.audit_id, event.event_hash, event.timestamp]
      );

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  public async getChainHead(tenantId: string): Promise<AuditChainHead | null> {
    const res = await this.pool.query(
      `SELECT tenant_id, last_audit_id, last_hash, event_count::text, updated_at
       FROM audit_chain_heads WHERE tenant_id = $1`,
      [tenantId]
    );

    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      tenant_id: row.tenant_id,
      last_audit_id: row.last_audit_id,
      last_hash: row.last_hash,
      event_count: parseInt(row.event_count, 10),
      updated_at: new Date(row.updated_at).toISOString()
    };
  }

  public async getEvents(
    tenantId: string,
    options?: {
      fromTimestamp?: string;
      toTimestamp?: string;
      limit?: number;
      offset?: number;
      ascending?: boolean;
    }
  ): Promise<AuditEvent[]> {
    const conditions: string[] = [];
    const values: any[] = [];
    let idx = 1;

    if (tenantId !== '*') {
      conditions.push(`tenant_id = $${idx++}`);
      values.push(tenantId);
    }

    if (options?.fromTimestamp) {
      conditions.push(`timestamp >= $${idx++}`);
      values.push(options.fromTimestamp);
    }

    if (options?.toTimestamp) {
      conditions.push(`timestamp <= $${idx++}`);
      values.push(options.toTimestamp);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const sortOrder = options?.ascending ?? true ? 'ASC' : 'DESC';

    let limitClause = '';
    if (options?.limit !== undefined) {
      limitClause = `LIMIT $${idx++}`;
      values.push(options.limit);
    }

    let offsetClause = '';
    if (options?.offset !== undefined) {
      offsetClause = `OFFSET $${idx++}`;
      values.push(options.offset);
    }

    const query = `
      SELECT audit_id, tenant_id, timestamp, principal_id, principal_type,
             action, resource_type, resource_id, decision, policy_id, policy_version,
             request_context, masked_payload, previous_hash, event_hash, schema_version
      FROM audit_events
      ${whereClause}
      ORDER BY event_seq ${sortOrder}
      ${limitClause} ${offsetClause}
    `;

    const res = await this.pool.query(query, values);

    return res.rows.map((row) => ({
      audit_id: row.audit_id,
      tenant_id: row.tenant_id,
      timestamp: new Date(row.timestamp).toISOString(),
      principal_id: row.principal_id,
      principal_type: row.principal_type,
      action: row.action,
      resource_type: row.resource_type,
      resource_id: row.resource_id,
      decision: row.decision,
      policy_id: row.policy_id,
      policy_version: row.policy_version,
      request_context: typeof row.request_context === 'string' ? JSON.parse(row.request_context) : row.request_context,
      masked_payload: row.masked_payload ? (typeof row.masked_payload === 'string' ? JSON.parse(row.masked_payload) : row.masked_payload) : null,
      previous_hash: row.previous_hash,
      event_hash: row.event_hash,
      schema_version: row.schema_version
    }));
  }

  public async getEventById(auditId: string): Promise<AuditEvent | null> {
    const res = await this.pool.query(
      `SELECT audit_id, tenant_id, timestamp, principal_id, principal_type,
             action, resource_type, resource_id, decision, policy_id, policy_version,
             request_context, masked_payload, previous_hash, event_hash, schema_version
      FROM audit_events WHERE audit_id = $1`,
      [auditId]
    );

    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      audit_id: row.audit_id,
      tenant_id: row.tenant_id,
      timestamp: new Date(row.timestamp).toISOString(),
      principal_id: row.principal_id,
      principal_type: row.principal_type,
      action: row.action,
      resource_type: row.resource_type,
      resource_id: row.resource_id,
      decision: row.decision,
      policy_id: row.policy_id,
      policy_version: row.policy_version,
      request_context: typeof row.request_context === 'string' ? JSON.parse(row.request_context) : row.request_context,
      masked_payload: row.masked_payload ? (typeof row.masked_payload === 'string' ? JSON.parse(row.masked_payload) : row.masked_payload) : null,
      previous_hash: row.previous_hash,
      event_hash: row.event_hash,
      schema_version: row.schema_version
    };
  }

  public async countEvents(tenantId: string): Promise<number> {
    const where = tenantId === '*' ? '' : 'WHERE tenant_id = $1';
    const params = tenantId === '*' ? [] : [tenantId];
    const res = await this.pool.query(`SELECT COUNT(*)::text AS count FROM audit_events ${where}`, params);
    return parseInt(res.rows[0].count, 10);
  }

  public async saveCheckpoint(checkpoint: AuditCheckpoint): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_checkpoints (checkpoint_id, tenant_id, event_count, last_audit_id, last_hash, signature, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        checkpoint.checkpoint_id,
        checkpoint.tenant_id,
        checkpoint.event_count,
        checkpoint.last_audit_id,
        checkpoint.last_hash,
        checkpoint.signature,
        checkpoint.created_at
      ]
    );
  }

  public async getLatestCheckpoint(tenantId: string): Promise<AuditCheckpoint | null> {
    const res = await this.pool.query(
      `SELECT checkpoint_id, tenant_id, event_count::text, last_audit_id, last_hash, signature, created_at
       FROM audit_checkpoints WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [tenantId]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      checkpoint_id: row.checkpoint_id,
      tenant_id: row.tenant_id,
      event_count: parseInt(row.event_count, 10),
      last_audit_id: row.last_audit_id,
      last_hash: row.last_hash,
      signature: row.signature,
      created_at: new Date(row.created_at).toISOString()
    };
  }

  public async recordVerificationRun(run: VerificationResult): Promise<void> {
    await this.pool.query(
      `INSERT INTO verification_runs (run_id, tenant_id, verified, total_events, genesis_hash, head_hash, first_broken_link, duration_ms, checked_at)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        run.tenant_id,
        run.verified,
        run.total_events,
        run.genesis_hash,
        run.head_hash,
        run.first_broken_link ? JSON.stringify(run.first_broken_link) : null,
        run.duration_ms,
        run.checked_at
      ]
    );
  }

  public async close(): Promise<void> {
    if (this.isOwnedPool) {
      await this.pool.end();
    }
  }
}
