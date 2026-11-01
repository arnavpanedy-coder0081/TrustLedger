import { describe, it, expect } from 'vitest';
import { canonicalJson, computeEventHash, GENESIS_HASH, sha256 } from '../packages/core/src/index.js';

describe('Deterministic Canonical JSON & Hash Chaining', () => {
  it('produces identical output regardless of object property order', () => {
    const objA = { z: 1, a: 2, m: { y: 'test', b: 'nested' } };
    const objB = { a: 2, m: { b: 'nested', y: 'test' }, z: 1 };

    expect(canonicalJson(objA)).toBe(canonicalJson(objB));
    expect(canonicalJson(objA)).toBe('{"a":2,"m":{"b":"nested","y":"test"},"z":1}');
  });

  it('handles null, numbers, booleans, and dates deterministically', () => {
    const testDate = new Date('2026-10-07T12:00:00.000Z');
    const data = {
      active: true,
      count: 100,
      empty: null,
      created: testDate
    };

    const serialized = canonicalJson(data);
    expect(serialized).toBe('{"active":true,"count":100,"created":"2026-10-07T12:00:00.000Z","empty":null}');
  });

  it('omits undefined properties in objects per standard JSON semantics', () => {
    const data = {
      kept: 'yes',
      omitted: undefined
    };

    expect(canonicalJson(data)).toBe('{"kept":"yes"}');
  });

  it('computes event_hash according to PRD Section 11', () => {
    const eventWithoutHash = {
      audit_id: 'test-uuid-1',
      tenant_id: 'tenant-alpha',
      principal_id: 'user-42',
      decision: 'ALLOW'
    };

    const previousHash = GENESIS_HASH;
    const computed = computeEventHash(eventWithoutHash, previousHash);

    // Verify manually
    const expectedCanonical = canonicalJson(eventWithoutHash);
    const expectedHash = sha256(`${expectedCanonical}|${previousHash}`);

    expect(computed).toBe(expectedHash);
    expect(computed).toHaveLength(64);
  });
});
