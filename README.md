# Role-Based Identity & Audit Log Middleware Engine

![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)
![Node.js](https://img.shields.io/badge/Node.js-20%2B-green)
![License](https://img.shields.io/badge/License-Apache--2.0-blue)

A modular TypeScript security engine for multi-tenant Express services. It combines identity integration, RBAC and ABAC policy evaluation, privacy-aware audit payload handling, and SHA-256 hash-chained audit records with PostgreSQL persistence and verification tools.

> This repository is a security engineering project and reference implementation. It does not provide a complete identity provider or certify an application against SOC 2, ISO 27001, HIPAA, or other standards.

## What it demonstrates

- **Identity integration:** Express middleware accepts trusted principal and tenant resolvers supplied by the host application. Without a resolver, identity fails closed to an anonymous principal with no roles.
- **RBAC and ABAC:** role inheritance, explicit deny rules, attribute conditions, hybrid authorization, and tenant isolation.
- **Tamper-evident audit trails:** deterministic canonical JSON and SHA-256 predecessor links, plus verification for modified, missing, inserted, or reordered records.
- **Privacy-aware logging:** recursive masking and pseudonymization of sensitive audit payload fields.
- **Storage adapters:** in-memory storage for development and PostgreSQL storage with parameterized SQL and per-tenant advisory locks.
- **Operational tooling:** verifier and tamper-scenario CLI commands, a reference Express app, Docker Compose configuration, and CI workflow.

## Architecture

```text
Express request
  -> trusted identity and tenant resolver
  -> RBAC + ABAC decision (fail closed)
  -> application handler
  -> masked audit event
  -> canonical serialization + SHA-256 chain
  -> memory or PostgreSQL store
  -> chain verifier / CLI
```

Code is split into focused workspaces under `packages/`: `core`, `rbac`, `abac`, `masking`, `audit`, and `postgres`. See [architecture](docs/architecture.md), [policy specification](docs/policy-specification.md), and [threat model](docs/threat-model.md).

## Quick start

Requirements: Node.js 20 or later and npm. PostgreSQL is optional for the in-memory example.

```bash
npm ci
npm run build
npm test
npm run tamper-test
```

Run the reference app with in-memory audit storage:

```bash
npm run start:example
```

The sample app uses a fixed anonymous identity by default. Its header-based demo identities can be enabled for local experimentation:

```bash
ALLOW_INSECURE_DEMO_IDENTITY=true npm run start:example
```

**Never enable this demo option in a deployed environment.** The `x-user-*` and `x-tenant-*` headers are caller-controlled and are not authentication credentials. In a real service, configure `identityMiddleware` with resolvers backed by a verified session, JWT issuer, API gateway, or identity provider.

## PostgreSQL

Set `DATABASE_URL` to a PostgreSQL connection string; the reference server applies its schema migrations at startup.

```bash
# Example only: use your own local credentials and database
$env:DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/role_audit_db'
docker compose up -d
npm run start:example
```

The PostgreSQL adapter uses bound parameters and transactions. Hash chaining makes unauthorized changes detectable when a trusted chain head or external checkpoint is available; a database administrator who can rewrite the entire chain can recompute hashes. Export signed checkpoints to independently controlled storage for stronger assurance. See [SECURITY.md](SECURITY.md).

## Verification and security checks

```bash
npm test                 # Unit, integration, and concurrency suites
npm run tamper-test      # Modification, deletion, insertion, and reordering scenarios
npm run benchmark        # Local performance measurement
```

The test suite includes RBAC/ABAC decisions, tenant boundaries, masking, hash verification, concurrent writers, and Express integration. Benchmark figures vary by machine; use the included runner and [benchmark notes](docs/benchmark-report.md) to reproduce measurements in your environment.

## Project layout

```text
packages/                 Core, policy, middleware, masking, and storage workspaces
examples/                 Express reference application
cli/                      Verification, tamper, and benchmark commands
migrations/               PostgreSQL schema migrations
tests/                    Unit, integration, concurrency, and security scenarios
docs/                     Architecture, threat model, policy, and verification guides
```

## License

Apache-2.0. See [LICENSE](LICENSE).
