import { describe, expect, it } from 'vitest';
import { PostgresAuditStore } from '../packages/postgres/src/index.js';

describe('Postgres stale writer protection', () => {
  it('holds a transaction advisory lock and rejects a stale previous hash', async () => {
    const statements: string[] = [];
    const client = {
      query: async (sql: string) => {
        statements.push(sql.trim());
        if (sql.includes('SELECT last_hash')) return { rows: [{ last_hash: 'current-head' }] };
        return { rows: [] };
      },
      release: () => undefined
    };
    const pool = { connect: async () => client } as any;
    const store = new PostgresAuditStore({ pool });
    await expect(store.appendEvent({ tenant_id: 't', previous_hash: 'stale-head' } as any)).rejects.toThrow(/Stale audit chain head/);
    expect(statements.some((sql) => sql.includes('pg_advisory_xact_lock'))).toBe(true);
    expect(statements).toContain('ROLLBACK');
  });
});
