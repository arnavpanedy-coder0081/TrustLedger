import { sha256, hmacSha256 } from '@role-audit/core';

export interface MaskingConfig {
  sensitiveFieldNames?: string[];
  allowlistFields?: string[];
  pseudonymizeFields?: string[];
  pseudonymizationKey?: string;
  maxDepth?: number;
  maxStringLength?: number;
  maxPayloadBytes?: number;
  failClosed?: boolean;
}

export const DEFAULT_SENSITIVE_FIELD_NAMES = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'access_token',
  'refresh_token',
  'authorization',
  'auth',
  'bearer',
  'cookie',
  'set-cookie',
  'session',
  'apikey',
  'api_key',
  'privatekey',
  'private_key',
  'secretkey',
  'secret_key',
  'ssn',
  'cvv',
  'cvc',
  'creditcard',
  'credit_card',
  'cardnumber',
  'card_number',
  'pin'
];

const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const CREDIT_CARD_REGEX = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;
const SSN_REGEX = /\b\d{3}-\d{2}-\d{4}\b/g;
const JWT_REGEX = /ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g;
const BEARER_AUTH_REGEX = /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi;

export class DataMasker {
  private config: Required<MaskingConfig>;
  private sensitiveFieldLookup: Set<string>;
  private allowlistLookup: Set<string>;
  private pseudonymizeLookup: Set<string>;

  constructor(config: MaskingConfig = {}) {
    this.config = {
      sensitiveFieldNames: [
        ...new Set([...DEFAULT_SENSITIVE_FIELD_NAMES, ...(config.sensitiveFieldNames || [])])
      ],
      allowlistFields: config.allowlistFields || [],
      pseudonymizeFields: config.pseudonymizeFields || [],
      pseudonymizationKey: config.pseudonymizationKey || 'role-audit-salt-key-default',
      maxDepth: config.maxDepth ?? 8,
      maxStringLength: config.maxStringLength ?? 8192,
      maxPayloadBytes: config.maxPayloadBytes ?? 65536,
      failClosed: config.failClosed ?? true
    };

    this.sensitiveFieldLookup = new Set(
      this.config.sensitiveFieldNames.map((s) => s.toLowerCase())
    );
    this.allowlistLookup = new Set(
      this.config.allowlistFields.map((s) => s.toLowerCase())
    );
    this.pseudonymizeLookup = new Set(
      this.config.pseudonymizeFields.map((s) => s.toLowerCase())
    );
  }

  public mask<T>(input: T): T {
    try {
      if (input === null || input === undefined) {
        return input;
      }

      const seen = new WeakSet<object>();
      const masked = this.traverse(input, '', 0, seen);

      if (typeof masked === 'object' && masked !== null) {
        const serialized = JSON.stringify(masked);
        if (Buffer.byteLength(serialized, 'utf8') > this.config.maxPayloadBytes) {
          return {
            _truncated: true,
            _reason: `Payload exceeded maximum allowed size of ${this.config.maxPayloadBytes} bytes`,
            _summary: `Object with keys: ${Object.keys(masked as object).join(', ')}`
          } as unknown as T;
        }
      }

      return masked;
    } catch (err) {
      if (this.config.failClosed) {
        return {
          _masking_error: true,
          _status: 'FAILED_CLOSED',
          _message: 'Audit payload was completely redacted due to masking processing error'
        } as unknown as T;
      }
      throw err;
    }
  }

  private isSensitiveKey(key: string): boolean {
    const lowerKey = key.toLowerCase();
    if (this.sensitiveFieldLookup.has(lowerKey)) {
      return true;
    }
    for (const sensitive of this.sensitiveFieldLookup) {
      if (lowerKey.includes(sensitive)) {
        return true;
      }
    }
    return false;
  }

  private isAllowlisted(path: string, key: string): boolean {
    const lowerKey = key.toLowerCase();
    const lowerPath = path.toLowerCase();
    return this.allowlistLookup.has(lowerKey) || this.allowlistLookup.has(lowerPath);
  }

  private shouldPseudonymize(path: string, key: string): boolean {
    const lowerKey = key.toLowerCase();
    const lowerPath = path.toLowerCase();
    return this.pseudonymizeLookup.has(lowerKey) || this.pseudonymizeLookup.has(lowerPath);
  }

  private pseudonymizeValue(val: unknown): string {
    const str = String(val);
    const hash = hmacSha256(this.config.pseudonymizationKey, str);
    return `[PSEUDO:${hash.substring(0, 16)}]`;
  }

  private maskString(val: string): string {
    let result = val;

    if (result.length > this.config.maxStringLength) {
      result = result.substring(0, this.config.maxStringLength) + '...[TRUNCATED]';
    }

    result = result.replace(BEARER_AUTH_REGEX, 'Bearer [REDACTED_TOKEN]');
    result = result.replace(JWT_REGEX, '[REDACTED_JWT]');
    result = result.replace(CREDIT_CARD_REGEX, (match) => {
      const digits = match.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      return `****-****-****-${last4}`;
    });
    result = result.replace(SSN_REGEX, '***-**-****');
    result = result.replace(EMAIL_REGEX, (email) => {
      const parts = email.split('@');
      if (parts.length === 2 && parts[0] && parts[1]) {
        const username = parts[0];
        const domain = parts[1];
        const maskedUsername = username.length > 2 ? `${username[0]}***${username[username.length - 1]}` : `${username[0]}***`;
        return `${maskedUsername}@${domain}`;
      }
      return '[MASKED_EMAIL]';
    });

    return result;
  }

  private traverse(val: unknown, currentPath: string, depth: number, seen: WeakSet<object>): any {
    if (depth > this.config.maxDepth) {
      return '[MAX_DEPTH_EXCEEDED]';
    }

    if (val === null || val === undefined) {
      return val;
    }

    if (typeof val === 'string') {
      return this.maskString(val);
    }

    if (typeof val === 'number' || typeof val === 'boolean') {
      return val;
    }

    if (val instanceof Date) {
      return val.toISOString();
    }

    if (typeof val === 'object') {
      if (seen.has(val)) {
        throw new Error('Circular reference detected during payload masking');
      }
      seen.add(val);

      if (Array.isArray(val)) {
        return val.map((item, idx) =>
          this.traverse(item, currentPath ? `${currentPath}[${idx}]` : `[${idx}]`, depth + 1, seen)
        );
      }

      const obj = val as Record<string, unknown>;
      const result: Record<string, unknown> = {};

      for (const [k, v] of Object.entries(obj)) {
        const fieldPath = currentPath ? `${currentPath}.${k}` : k;
        const lowerK = k.toLowerCase();

        if (this.shouldPseudonymize(fieldPath, k)) {
          result[k] = this.pseudonymizeValue(v);
          continue;
        }

        // Sensitive names always win over the allowlist.
        if (this.isAllowlisted(fieldPath, k) && !this.isSensitiveKey(k)) {
          result[k] = this.traverse(v, fieldPath, depth + 1, seen);
          continue;
        }

        // Special handling for credit card fields: mask PAN while preserving last 4 digits
        if ((lowerK.includes('creditcard') || lowerK.includes('cardnumber') || lowerK.includes('credit_card')) && typeof v === 'string') {
          result[k] = this.maskString(v);
          continue;
        }

        if (this.isSensitiveKey(k)) {
          result[k] = '[REDACTED]';
          continue;
        }

        result[k] = this.traverse(v, fieldPath, depth + 1, seen);
      }

      return result;
    }

    return String(val);
  }
}

export const defaultMasker = new DataMasker();
