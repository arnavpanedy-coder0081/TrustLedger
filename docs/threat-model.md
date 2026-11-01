# Threat Model & Security Analysis

This threat model outlines potential attack vectors, threat actors, security assumptions, and mitigations across the engine (PRD Section 17 & 26).

## Threat Actors

1. **External Attackers**: Attempting privilege escalation, SQL injection, cross-tenant data access, or resource theft.
2. **Malicious Insiders / Compromised Tenants**: Users attempting to forge credentials, bypass departmental restrictions, or access neighboring tenant data.
3. **Privileged Database Administrators (DBAs)**: Operators with direct PostgreSQL access attempting to tamper with historical evidence or delete incriminating audit events.

## Threat Analysis & Mitigations

### 1. Privilege Escalation & Cross-Tenant Access
- **Threat**: An attacker manipulates request headers (e.g. `x-tenant-id`, `x-user-roles`) to access records from another tenant.
- **Mitigation**:
  - `HybridAuthorizationEngine` enforces strict tenant isolation: if `resource.tenantId != tenant.tenantId`, request is immediately denied with 403.
  - Fail-closed evaluation: if role bindings or policies do not explicitly grant access, default decision is `DENY`.

### 2. SQL Injection in Audit Store
- **Threat**: Attackers supply malicious characters in correlation IDs, user IDs, or payloads to execute unauthorized SQL statements.
- **Mitigation**:
  - `PostgresAuditStore` exclusively utilizes parameterized queries (`$1, $2, ...`) for all statements.
  - No string concatenation is used in query building.

### 3. Log Tampering (Modification, Deletion, Reordering)
- **Threat**: An attacker modifies an audit log row (e.g. changing `decision: 'DENY'` to `'ALLOW'`) or removes a record of an unauthorized export.
- **Mitigation**:
  - Records are linked via SHA-256 cryptographic hashes:
    $$\text{event\_hash} = \text{SHA256}(\text{canonical\_json}(\text{event}) \parallel \text{"\|"} \parallel \text{previous\_hash})$$
  - Any modification produces a hash mismatch.
  - Any deletion breaks the successor's `previous_hash` pointer.
  - Any reordering breaks the chain.
  - `AuditChainVerifier` isolates and alerts on the exact first tampered record.

### 4. Privileged Database Administrator Threat
- **Threat**: A rogue DBA rewrites historical rows and recalculates the SHA-256 hashes sequentially to create an alternative consistent chain.
- **Mitigation**:
  - PRD Section 17 explicitly documents: *hash chaining provides tamper evidence, not absolute immutability against an attacker who controls the complete storage boundary*.
  - `CheckpointManager` generates periodic signed checkpoints that are exported outside PostgreSQL to external WORM storage (e.g., S3 Object Lock, GCP Bucket Lock, KMS-signed ledgers).
  - A DBA cannot alter external checkpoints without alerting security monitors.

### 5. Sensitive Data & Credential Leakage in Audit Trails
- **Threat**: Audit records accidentally store passwords, bearer tokens, API keys, or patient PII.
- **Mitigation**:
  - `DataMasker` runs recursively before event serialization.
  - Automatic scrubbing of passwords, authorization headers, JWTs, and credit card PANs.
  - Deterministic pseudonymization with HMAC-SHA256 allows correlation without storing raw identifiers.
  - Fail-closed mode: if an unhandled masking exception occurs, payload is completely redacted.

### 6. Concurrent Writer Race Conditions on Chain Heads
- **Threat**: Simultaneous incoming requests for the same tenant result in competing chain heads and orphaned branches.
- **Mitigation**:
  - `PostgresAuditStore` acquires PostgreSQL advisory transaction locks (`pg_advisory_xact_lock(hashtext(tenant_id))`) during append.
  - `MemoryAuditStore` implements per-tenant promise mutex locks.
  - High concurrency test verifies 100% linear integrity across 50 simultaneous writers.
