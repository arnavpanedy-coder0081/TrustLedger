# Contributing to Role-Based Identity & Audit Log Middleware Engine

Thank you for your interest in contributing to the project! We welcome pull requests for bug fixes, performance improvements, documentation, and new adapters.

## Development Setup

### Prerequisites
- Node.js >= 20.x
- npm >= 10.x
- Docker & Docker Compose (optional, for local PostgreSQL testing)

### Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/organization/role-audit-engine.git
cd role-audit-engine
npm install
```

### Running Tests
Run the comprehensive test suite:
```bash
npm test
```

Run the tampering attack fixture suite:
```bash
npm run tamper-test
```

Run performance benchmarks:
```bash
npm run benchmark
```

### Starting the Reference Application
Start the reference application with in-memory storage:
```bash
npm run start:example
```

Or run with PostgreSQL using Docker Compose:
```bash
docker compose up -d
```

## Pull Request Guidelines

1. **Test Coverage**: All new features or bug fixes must include unit or integration tests in `tests/`.
2. **Security Integrity**: Ensure no changes weaken fail-closed authorization semantics or leak unmasked sensitive data.
3. **Deterministic Canonicalization**: Any modifications to event formatting must preserve deterministic RFC-8785 JSON canonicalization.
4. **Code Quality**: Ensure strict TypeScript types and zero lint warnings.
