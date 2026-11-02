# TrustLedger

![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)
![Node.js](https://img.shields.io/badge/Node.js-20%2B-green)
![License](https://img.shields.io/badge/License-Apache--2.0-blue)

TrustLedger is a TypeScript security reference project for multi-tenant Express services, with a small local desktop audit demo. It combines identity integration, role- and attribute-based authorization, privacy-aware audit payload handling, and SHA-256 hash-chained audit records. Storage options include in-memory, local file snapshots, and PostgreSQL.

> TrustLedger is a reference implementation. It is not a complete identity provider, a production security certification, or a compliance guarantee. Integrating it does not by itself establish SOC 2, ISO 27001, HIPAA, or other compliance.

## Features

- **Identity integration:** Express middleware accepts principal and tenant resolvers from the host service. Missing identity configuration fails closed to an anonymous principal with no roles.
- **RBAC and ABAC:** role inheritance, explicit deny rules, attribute conditions, hybrid authorization, and tenant isolation.
- **Tamper-evident audit trails:** deterministic canonical JSON and SHA-256 predecessor links, with verification for modified, missing, inserted, or reordered events.
- **Privacy-aware logging:** recursive masking and pseudonymization of sensitive audit payload fields.
- **Storage adapters:** in-memory and PostgreSQL stores for the middleware, plus an atomic local file snapshot store for the desktop demo.
- **Developer tools:** a reference Express app, audit verification and tamper commands, benchmarks, tests, and Docker Compose configuration.

## Requirements

- Node.js 20 or later
- npm
- Docker Compose only if you want to run the bundled PostgreSQL and reference-app services

## Install and verify

```bash
git clone https://github.com/arnavpanedy-coder0081/TrustLedger.git
cd TrustLedger
npm ci
npm run typecheck
npm run build
npm test
npm run tamper-test
```

Run the local benchmark with `npm run benchmark`. It measures the in-memory store; results depend on the machine and are not PostgreSQL performance claims.

The reference Express app runs with in-memory audit storage by default:

```bash
npm run start:example
```

Its sample header identities are disabled by default. For local experimentation only, enable them with `ALLOW_INSECURE_DEMO_IDENTITY=true`. **Never enable this option in a deployed environment.** The `x-user-*` and `x-tenant-*` headers are caller-controlled and are not authentication credentials. Production integrations must provide identity and tenant resolvers backed by verified credentials.

## Desktop demo

The desktop demo uses a loopback-only HTTP server and stores its audit snapshot locally. On Windows, the default file is `%LOCALAPPDATA%\TrustLedger\audit-events.json`; `TRUSTLEDGER_DATA_FILE` overrides the location.

Build the standalone Windows executable with:

```bash
npm run build:exe
```

This is a separate packaging path. The regular `npm run build` and `npm run typecheck` configurations do **not** include `desktop-app`. The packaging script also attempts to copy the executable to a fixed OneDrive Desktop path belonging to its original author. Review or edit `scripts/build-exe.js` before running it on another machine. The desktop snapshot is local storage, not an independently protected or immutable backup.

## PostgreSQL and Docker

The PostgreSQL adapter uses parameterized queries and transactions, with transaction-level advisory locks to serialize writes per tenant. To build the image and start PostgreSQL plus the reference Express app:

```bash
docker compose up --build
```

The Compose setup exposes PostgreSQL on port 5432 and the app on port 3000. It uses the example database credentials `postgres/postgres`, which are for local development only. Replace them and review network exposure before using a similar setup beyond a local machine. The named PostgreSQL volume persists data; `docker compose down` stops the services and preserves that volume.

For a local app run, set `DATABASE_URL` to a PostgreSQL connection string and start the reference server. It applies the schema migrations at startup. Example PowerShell syntax:

```powershell
$env:DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/role_audit_db'
npm run start:example
```

Hash chaining provides tamper evidence, not absolute immutability. A database administrator who can rewrite the full chain and its stored head can recompute hashes. For stronger assurance, export signed checkpoints to independently controlled storage and restrict database write access. See [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md).

## Verification coverage and limitations

GitHub Actions runs the build, unit and integration tests, tamper scenarios, and benchmarks on Node.js 20 and 22. It provisions a PostgreSQL service, but the current PostgreSQL stale-writer regression test uses a mocked client; it checks locking and stale-head rejection logic without exercising a live database. Run live PostgreSQL tests before relying on database behavior in a deployment. Docker image build and startup also require a host with Docker available.

The desktop UI is a demonstration, not a multi-user or remote-access service. Keep it local. Anyone who can modify its local files can rewrite the file snapshot. Hash chains without an independently retained checkpoint cannot prove the original data after a complete database rewrite. The Express example's optional header identity mode is insecure and must not be deployed.

## Project layout

```text
desktop-app/              Local audit viewer and demo server
packages/                 Core, policy, middleware, masking, and storage workspaces
examples/                 Express reference application
cli/                      Verification, tamper, and benchmark commands
migrations/               PostgreSQL schema migrations
tests/                    Unit, integration, and regression tests
docs/                     Architecture, policy, threat model, and verification guides
```

## License

Apache-2.0. See [LICENSE](LICENSE).
