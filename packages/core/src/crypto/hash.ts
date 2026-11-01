import { createHash, createHmac, randomUUID } from 'node:crypto';
import { canonicalJson } from './canonical.js';
import type { AuditEvent } from '../types/index.js';

/**
 * Genesis hash representing the root of a tamper-evident audit stream (64 hex zeros).
 */
export const GENESIS_HASH = '0'.repeat(64);

/**
 * Computes a standard SHA-256 hash of a UTF-8 string, returning 64 lowercase hex characters.
 */
export function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

/**
 * Computes an HMAC-SHA256 signature or keyed hash.
 */
export function hmacSha256(key: string, data: string): string {
  return createHmac('sha256', key).update(data, 'utf8').digest('hex');
}

/**
 * Generates a standard UUID v4.
 */
export function generateUuid(): string {
  return randomUUID();
}

/**
 * Strips hash fields and variable transient properties from an audit event
 * to prepare it for canonical representation.
 */
export function stripHashFields(event: Record<string, unknown>): Record<string, unknown> {
  const { event_hash, previous_hash, ...canonicalFields } = event;
  return canonicalFields;
}

/**
 * Computes the event_hash according to PRD Section 11:
 * event_hash = SHA256(canonical_json(event_without_hash_fields) + "|" + previous_hash)
 */
export function computeEventHash(
  eventWithoutHashFields: Record<string, unknown>,
  previousHash: string
): string {
  const canonicalStr = canonicalJson(stripHashFields(eventWithoutHashFields));
  const hashInput = `${canonicalStr}|${previousHash}`;
  return sha256(hashInput);
}

/**
 * Verifies if an audit event's event_hash matches its content and previous_hash.
 */
export function verifyEventHash(event: AuditEvent): boolean {
  const expectedHash = computeEventHash(event as unknown as Record<string, unknown>, event.previous_hash);
  return expectedHash === event.event_hash;
}
