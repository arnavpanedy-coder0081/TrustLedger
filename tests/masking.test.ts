import { describe, it, expect } from 'vitest';
import { DataMasker } from '../packages/masking/src/index.js';

describe('Data Masking Engine', () => {
  it('masks sensitive key names completely', () => {
    const masker = new DataMasker();
    const payload = {
      username: 'john_doe',
      password: 'SuperSecretPassword123!',
      apiKey: 'sk-proj-999888777',
      accessToken: 'bearer_token_xyz',
      cookie: 'session_id=12345'
    };

    const masked = masker.mask(payload);
    expect(masked.username).toBe('john_doe');
    expect(masked.password).toBe('[REDACTED]');
    expect(masked.apiKey).toBe('[REDACTED]');
    expect(masked.accessToken).toBe('[REDACTED]');
    expect(masked.cookie).toBe('[REDACTED]');
  });

  it('masks inline patterns in strings (emails, credit cards, SSNs, JWTs)', () => {
    const masker = new DataMasker();
    const payload = {
      notes: 'Customer email is alice.smith@enterprise.org and card is 4111 2222 3333 4444. SSN: 123-45-6789.',
      header: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature'
    };

    const masked = masker.mask(payload);
    expect(masked.notes).toContain('a***h@enterprise.org');
    expect(masked.notes).toContain('****-****-****-4444');
    expect(masked.notes).toContain('***-**-****');
    expect(masked.header).toContain('Bearer [REDACTED_TOKEN]');
  });

  it('supports allowlists for non-sensitive fields while keeping sensitive fields masked', () => {
    const masker = new DataMasker({
      allowlistFields: ['tokenCount', 'status']
    });

    const payload = {
      tokenCount: 42,
      token: 'raw_secret_token',
      status: 'active'
    };

    const masked = masker.mask(payload);
    expect(masked.tokenCount).toBe('[REDACTED]');
    expect(masked.token).toBe('[REDACTED]');
    expect(masked.status).toBe('active');
  });

  it('never lets an allowlist expose sensitive names', () => {
    const masker = new DataMasker({ allowlistFields: ['token', 'password'] });
    expect(masker.mask({ token: 'secret', password: 'secret' })).toEqual({ token: '[REDACTED]', password: '[REDACTED]' });
  });

  it('supports deterministic pseudonymization with HMAC-SHA256', () => {
    const masker = new DataMasker({
      pseudonymizeFields: ['userId', 'email'],
      pseudonymizationKey: 'custom-salt-123'
    });

    const payload = {
      userId: 'user_12345',
      email: 'bob@example.com'
    };

    const masked1 = masker.mask(payload);
    const masked2 = masker.mask(payload);

    // Not the raw values
    expect(masked1.userId).not.toBe('user_12345');
    expect(masked1.email).not.toBe('bob@example.com');
    expect(masked1.userId).toContain('[PSEUDO:');

    // Deterministic: multiple runs produce identical pseudonyms
    expect(masked1.userId).toBe(masked2.userId);
    expect(masked1.email).toBe(masked2.email);
  });

  it('enforces payload size bounding to mitigate abuse', () => {
    const masker = new DataMasker({
      maxPayloadBytes: 200 // small limit for testing
    });

    const largePayload = {
      description: 'x'.repeat(1000)
    };

    const masked = masker.mask(largePayload) as any;
    expect(masked._truncated).toBe(true);
    expect(masked._reason).toContain('exceeded maximum allowed size');
  });

  it('fails closed when an unhandled exception occurs', () => {
    const masker = new DataMasker({ failClosed: true });
    // Circular structure
    const circular: any = { a: 1 };
    circular.self = circular;

    const masked = masker.mask(circular) as any;
    expect(masked._status).toBe('FAILED_CLOSED');
  });
});
