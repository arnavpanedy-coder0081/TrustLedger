# Role-Based Identity & Audit Log Middleware Engine

[![CI](https://github.com/organization/role-audit-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/organization/role-audit-engine/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20.x-green.svg)](https://nodejs.org/)

An open-source, production-oriented security and compliance middleware engine for multi-tenant applications. It combines **granular RBAC/ABAC authorization**, **SHA-256 tamper-evident linked audit records**, and **privacy-aware data masking**.

Designed to strengthen security evidence for programs such as **SOC 2**, **ISO 27001**, and **HIPAA**.

---

## Key Features

- **Granular RBAC**: Enterprise roles (`admin`, `auditor`, `manager`, `analyst`, `viewer`), role inheritance with cycle detection, explicit deny semantics, and tenant-scoped role bindings.
- **Context-Aware ABAC**: Evaluates subject, resource, action, environment, and tenant attributes with comprehensive operators (`equals`, `in`, `greaterThan`, `matches`, `timeWindow`, `cidrMatches`).
- **Tamper-Evident SHA-256 Audit Chains**: Every audit record is cryptographically chained to its predecessor using deterministic RFC-8785 canonical JSON.
- **Automated Tamper Verification**: CLI and programmatic verifiers detect modifications, deletions, rogue insertions, and reorderings, pinpointing the exact broken link.
- **Privacy-Aware Data Masking**: Automatically redacts passwords, session tokens, authorization headers, and cookies, masks credit cards/SSNs, and supports deterministic HMAC pseudonymization.
- **Strict Multi-Tenant Isolation**: Enforces tenant boundaries by default, preventing cross-tenant privilege escalation.
- **High Performance**: Sub-millisecond latency (< 0.3ms avg) tested at 100, 500, and 1,000 events/second.

---

## Desktop Application (.EXE)

The engine can be executed as a standalone native Windows desktop application with a minimal, dark-mode dashboard:

- **Desktop File**: `C:\Users\arnav pandey\OneDrive\Desktop\role-audit-engine.exe`
- **Workspace File**: [`role-audit-engine.exe`](file:///c:/Users/arnav%20pandey/OneDrive/Desktop/Role-Based%20Identity%20&%20Audit%20Log%20Middleware%20Engine/role-audit-engine.exe)
- **Rebuild Anytime**: `npm run build:exe`

Simply double-click `role-audit-engine.exe` on your desktop to automatically launch the minimal UI:
1. **Policy Sandbox**: Test RBAC and ABAC evaluations with real-time decision traces.
2. **Audit Stream**: Inspect live SHA-256 chained audit logs and previous/event hashes.
3. **Tamper Lab**: Trigger payload modifications, record deletions, rogue injections, or reorderings, then run the verifier to see 100% detection in real time.
4. **Data Masker**: Interactive PII, secrets scrubber, and HMAC pseudonymizer.
5. **Benchmark**: Live throughput and latency test runner.

---

```
role-audit-engine/
├── packages/
│   ├── core/              # Shared types, canonical JSON, crypto hash, errors, metrics
│   ├── masking/           # Privacy-aware PII, secrets scrubber, pseudonymization
│   ├── rbac/              # Role-Based Access Control engine with inheritance & explicit deny
│   ├── abac/              # Attribute-Based Access Control engine & hybrid evaluator
│   ├── audit/             # SHA-256 tamper-evident chain engine, verifier, Express middleware
│   └── postgres/          # PostgreSQL storage adapter with advisory transaction locks
├── cli/                   # CLI verifier, inspection tool, attack suite, and benchmark runner
├── examples/
│   └── express-reference-app/  # Complete multi-tenant reference Express application
├── migrations/            # Production PostgreSQL SQL migrations (001, 002, 003)
├── tests/                 # Comprehensive unit, concurrency, security, and E2E tests
├── docs/                  # Architecture, verification guide, policy specs, threat model
├── docker-compose.yml     # PostgreSQL 16 + Reference app container deployment
├── SECURITY.md            # Trust model, boundaries, and vulnerability disclosure policy
└── README.md
```

---

## Quick Start (Under 10 Minutes)

### 1. Installation

```bash
npm install
```

### 2. Basic Express Integration

```typescript
import express from 'express';
import {
  identityMiddleware,
  authorize,
  auditMiddleware,
  AuditChainEngine,
  MemoryAuditStore
} from '@role-audit/audit';
import { AuthorizationEngine, AbacEngine } from '@role-audit/abac';
import { RbacEngine } from '@role-audit/rbac';

const app = express();
app.use(express.json());

// Initialize engines
const store = new MemoryAuditStore(); // Or PostgresAuditStore
const auditEngine = new AuditChainEngine({ store, strictMode: true });
const rbac = new RbacEngine();
const abac = new AbacEngine();

const authzEngine = new AuthorizationEngine({
  rbac,
  abac,
  strategy: 'RBAC_AND_ABAC'
});

// 1. Identity Middleware: resolves caller principal & tenant
app.use(identityMiddleware({
  resolvePrincipal: (req) => ({
    id: req.headers['x-user-id'] as string || 'anonymous',
    type: 'human',
    roles: (req.headers['x-user-roles'] as string)?.split(',') || ['viewer']
  }),
  resolveTenant: (req) => ({
    tenantId: (req.headers['x-tenant-id'] as string) || 'default-tenant'
  })
}));

// 2. Audit Interceptor: captures outcomes and masks sensitive fields
app.use(auditMiddleware({ auditEngine, includeRequestBody: true }));

// 3. Protected Route
app.get(
  '/api/invoices',
  authorize({ action: 'invoice:read', resource: 'invoice', authzEngine, auditEngine }),
  (req, res) => {
    res.json({ invoices: [{ id: 'inv-1', amount: 250.0 }] });
  }
);

app.listen(3000, () => console.log('Server running on port 3000'));
```

---

## Tamper-Evidence & Verification

Each audit record is linked via:
$$\text{event\_hash} = \text{SHA256}(\text{canonical\_json}(\text{event\_without\_hashes}) \parallel \text{"\|"} \parallel \text{previous\_hash})$$

### Verify Tenant Chain with CLI
```bash
npm run cli -- verify --tenant tenant-alpha
```

### Run Automated Tampering Attack Suite
Simulates modification, deletion, rogue insertion, and reordering attacks to verify that 100% of tampering attempts are caught:
```bash
npm run tamper-test
```

Output:
```
=============================================================
 ROLE-AUDIT TAMPER-EVIDENT VERIFICATION ATTACK SUITE
 Testing: Modification, Deletion, Insertion, Reordering
=============================================================

Scenario 0: Untampered baseline chain verification... PASSED (100% Valid Chain Verified)
Scenario 1: Modification Attack (tampering payload)... DETECTED! Broken link flagged at index 2 (Reason: EVENT_HASH_MISMATCH)
Scenario 2: Deletion Attack (deleting event #3)... DETECTED! Missing predecessor link flagged at index 2
Scenario 3: Insertion Attack (injecting unauthorized event)... DETECTED! Injection broke linkage at index 2
Scenario 4: Reordering Attack (swapping events)... DETECTED! Reordering broke linkage at index 1 (Reason: PREVIOUS_HASH_MISMATCH)

=============================================================
>>> ALL TAMPERING ATTACK FIXTURES SUCCESSFULLY DETECTED <<<
=============================================================
```

---

## Performance Benchmarks (PRD Section 18)

Run the benchmark suite:
```bash
npm run benchmark
```

Results across representative workloads:

| Workload | Throughput | Avg Latency | p95 Latency | Status |
|---|---|---|---|---|
| **100 events/sec** | 100 eps | **0.256 ms** | **0.481 ms** | **PASSED** |
| **500 events/sec** | 499 eps | **0.085 ms** | **0.279 ms** | **PASSED** |
| **1,000 events/sec** | 995 eps | **0.057 ms** | **0.215 ms** | **PASSED** |

---

## Local Deployment with PostgreSQL & Docker Compose

Deploy the reference application connected to PostgreSQL 16:
```bash
docker compose up -d
```

Test endpoints:
- **Healthcheck & Observability**: `http://localhost:3000/health`
- **Protected Invoices**: `http://localhost:3000/api/invoices`
- **Audit Log Inspection**: `http://localhost:3000/api/audit/events`
- **Cryptographic Verification**: `http://localhost:3000/api/audit/verify`

---

## Testing

Run all unit, security, and integration tests:
```bash
npm test
```

---

## Security Model & Limitations (PRD Section 17 & 26)

- **Tamper-Evidence vs Immutability**: Hash chaining provides mathematical tamper-evidence, not absolute physical immutability if an attacker controls the complete database storage boundary.
- **External Anchoring**: Use `CheckpointManager` to anchor periodic signed checkpoint summaries to external WORM storage (e.g. AWS S3 Object Lock, GCP Bucket Lock).
- **Compliance Scope**: The engine provides tamper-evident audit evidence for SOC 2, ISO 27001, and HIPAA compliance programs, but does not itself certify compliance.

See [SECURITY.md](file:///c:/Users/arnav%20pandey/OneDrive/Desktop/Role-Based%20Identity%20&%20Audit%20Log%20Middleware%20Engine/SECURITY.md) for full trust model and vulnerability reporting.

---

## License

Licensed under the [Apache License, Version 2.0](file:///c:/Users/arnav%20pandey/OneDrive/Desktop/Role-Based%20Identity%20&%20Audit%20Log%20Middleware%20Engine/LICENSE).
