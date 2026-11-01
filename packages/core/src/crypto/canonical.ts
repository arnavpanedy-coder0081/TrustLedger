/**
 * Deterministic JSON Canonicalization Scheme (RFC-8785 compatible)
 *
 * Ensures deterministic stringification across platforms:
 * - Object properties sorted lexicographically by Unicode code point
 * - Dates normalized to ISO 8601 UTC strings
 * - Numbers serialized without trailing zeroes or floating point ambiguities
 * - undefined properties omitted from objects
 * - Arrays preserve element order with children canonicalized
 * - No whitespace between keys, colons, or values
 */

export function canonicalJson(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null) {
    return 'null';
  }

  const type = typeof value;

  if (type === 'string') {
    return JSON.stringify(value);
  }

  if (type === 'number') {
    if (!Number.isFinite(value)) {
      return 'null';
    }
    return JSON.stringify(value);
  }

  if (type === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (type === 'undefined' || type === 'symbol' || type === 'function') {
    return 'null';
  }

  if (type === 'bigint') {
    return (value as bigint).toString();
  }

  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }

  if (Array.isArray(value)) {
    const serializedItems = value.map((item) => {
      if (item === undefined || typeof item === 'symbol' || typeof item === 'function') {
        return 'null';
      }
      return canonicalJson(item, seen);
    });
    return `[${serializedItems.join(',')}]`;
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;

    if (seen.has(obj)) {
      throw new Error('Circular reference detected during canonical JSON serialization');
    }
    seen.add(obj);

    const sortedKeys = Object.keys(obj).sort((a, b) => {
      // Lexicographical UTF-16 code unit comparison
      return a < b ? -1 : a > b ? 1 : 0;
    });

    const entries: string[] = [];

    for (const key of sortedKeys) {
      const val = obj[key];
      // Skip undefined, functions, and symbols in objects as per standard JSON
      if (val === undefined || typeof val === 'function' || typeof val === 'symbol') {
        continue;
      }
      entries.push(`${JSON.stringify(key)}:${canonicalJson(val, seen)}`);
    }

    seen.delete(obj);
    return `{${entries.join(',')}}`;
  }

  return JSON.stringify(value);
}
