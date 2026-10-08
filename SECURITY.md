# Security Policy

## Scope & Trust Model

The **Role-Based Identity & Audit Log Middleware Engine** is designed to provide reusable, granular RBAC/ABAC authorization and tamper-evident audit logging with SHA-256 cryptographic chaining and privacy-aware data masking.

### Core Security Guarantees

1. **Deterministic Tenant Isolation**: Cross-tenant requests are denied by default. Policies and audit streams execute strictly inside tenant boundaries.
2. **Fail-Closed Authorization**: If an error or ambiguity occurs during identity resolution or policy evaluation, the engine denies access by default.
3. **Tamper-Evidence via SHA-256 Chaining**: Each audit record is linked to its predecessor via:
   ```
   event_hash = SHA256(canonical_json(event_without_hash_fields) + "|" + previous_hash)
   ```
   Any alteration (modification, deletion, insertion, or reordering of records) is mathematically detectable by the verifier, pinpointing the first corrupted index.
4. **Privacy-First Masking**: PII, passwords, authentication headers, cookies, API keys, and credit cards are scrubbed or pseudonymized before persistence.
5. **No Secret Ingestion**: The engine does not store raw passwords, tokens, or encryption private keys.

### Explicit Security Limitations (PRD Section 17 & 26)

- **Database-Level Immutability vs. Tamper-Evidence**:
  Hash chaining provides **tamper evidence**, not absolute physical immutability. If a malicious actor with privileged database administrator (DBA) access rewrites both database rows and updates hashes consistently, the internal database evidence alone cannot prove the original sequence without external anchoring.
  - *Mitigation*: Organizations should enable external checkpointing (`CheckpointManager`), replicate audit logs to write-once-read-many (WORM) storage (e.g., AWS S3 Object Lock, GCP Bucket Lock), and restrict operational DBA write access to `audit_events`.
- **Compliance Scope**:
  This engine produces audit evidence suitable for SOC 2, ISO 27001, and HIPAA audits, but integration of this library alone does not constitute certified compliance without an organization's full operational security controls.

## Reporting a Vulnerability

If you discover a security vulnerability within this engine, please do not file a public GitHub issue.

Instead, please send an encrypted or direct email to `security@role-audit-engine.org` or report via GitHub Private Vulnerability Reporting. Include:
1. Steps to reproduce the issue.
2. Proof-of-concept code or test fixture.
3. Affected versions.

We commit to acknowledging receipt within 24 hours and providing an initial assessment and patch timeline within 72 hours.
