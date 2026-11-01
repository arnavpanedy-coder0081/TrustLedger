# Performance Benchmark Report

**Evaluation Requirements (PRD Section 18)**:
*Benchmark reference deployments at 100, 500, and 1,000 audit events/second and document results.*

## Test Environment
- **Node.js**: v24.21.0 (V8 Engine)
- **Architecture**: Windows x64 / Multi-core CPU
- **Workload**: End-to-end audit logging including UUID generation, ISO timestamp generation, PII & secrets masking, RFC-8785 canonical JSON serialization, SHA-256 hash chaining, and append-oriented storage.

## Benchmark Results

| Target Throughput | Achieved Throughput | Duration | Total Events | Avg Latency | Min Latency | Max Latency | p95 Latency | Pass Status |
|---|---|---|---|---|---|---|---|---|
| **100 events/sec** | **100 eps** | 2.00 s | 200 | **0.256 ms** | 0.044 ms | 2.988 ms | **0.481 ms** | **PASSED** |
| **500 events/sec** | **499 eps** | 2.01 s | 1,000 | **0.085 ms** | 0.023 ms | 0.728 ms | **0.279 ms** | **PASSED** |
| **1,000 events/sec** | **995 eps** | 2.01 s | 2,000 | **0.057 ms** | 0.021 ms | 0.783 ms | **0.215 ms** | **PASSED** |

## Analysis & Performance Characteristics

These measurements are a historical local run, not a performance guarantee. Results depend on hardware, Node.js version, payload shape, storage adapter, and concurrency. Re-run the benchmark on the target deployment before using these figures for capacity planning. The audit engine also has an optional asynchronous batching mode; evaluate its durability and shutdown behavior against the application's requirements before enabling it.

## Reproducing Benchmarks

To execute the benchmark suite locally:
```bash
npm run benchmark
```
