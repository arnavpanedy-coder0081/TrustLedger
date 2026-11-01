import { describe, expect, it } from 'vitest';
import { isAllowedDesktopRequest } from '../desktop-app/src/security.js';

describe('desktop local API origin protection', () => {
  it('accepts only the local host and local web origins', () => {
    expect(isAllowedDesktopRequest('127.0.0.1:4200', 'http://localhost:4200', 4200)).toBe(true);
    expect(isAllowedDesktopRequest('localhost:4200', undefined, 4200)).toBe(true);
  });
  it('rejects missing, remote, or mismatched host and origin values', () => {
    expect(isAllowedDesktopRequest(undefined, undefined, 4200)).toBe(false);
    expect(isAllowedDesktopRequest('evil.test:4200', 'http://evil.test:4200', 4200)).toBe(false);
    expect(isAllowedDesktopRequest('localhost:4200', 'http://evil.test', 4200)).toBe(false);
  });
});
