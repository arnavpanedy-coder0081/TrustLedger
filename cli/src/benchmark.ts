import { AuditChainEngine, MemoryAuditStore } from '@role-audit/audit';
import { defaultMetrics } from '@role-audit/core';

export interface BenchmarkResult {
  targetRate: number;
  actualRate: number;
  totalEvents: number;
  durationSeconds: number;
  avgLatencyMs: number;
  minLatencyMs: number;
  maxLatencyMs: number;
  p95LatencyMs: number;
}

export async function runRateBenchmark(
  targetEventsPerSec: number,
  durationSec = 2
): Promise<BenchmarkResult> {
  const store = new MemoryAuditStore();
  const engine = new AuditChainEngine({
    store,
    strictMode: true
  });

  const totalEvents = targetEventsPerSec * durationSec;
  const intervalMs = 1000 / targetEventsPerSec;
  const latencies: number[] = [];

  const startTime = performance.now();

  for (let i = 0; i < totalEvents; i++) {
    const eventStart = performance.now();
    await engine.log({
      tenant_id: 'benchmark-tenant',
      principal_id: `user-${i % 10}`,
      principal_type: 'human',
      action: 'invoice:read',
      resource_type: 'invoice',
      resource_id: `inv-${1000 + i}`,
      decision: 'ALLOW',
      request_context: {
        correlationId: `corr-${i}`,
        ip: '127.0.0.1'
      },
      payload: {
        amount: 250.75,
        currency: 'USD',
        customerEmail: 'user@example.com' // will be masked
      }
    });
    const eventDuration = performance.now() - eventStart;
    latencies.push(eventDuration);

    // Precise throttling to target rate
    const elapsedSoFar = performance.now() - startTime;
    const targetElapsed = (i + 1) * intervalMs;
    const sleepNeeded = targetElapsed - elapsedSoFar;
    if (sleepNeeded > 1) {
      await new Promise((r) => setTimeout(r, sleepNeeded));
    }
  }

  const totalDuration = (performance.now() - startTime) / 1000;
  latencies.sort((a, b) => a - b);

  const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
  const minLatency = latencies[0] || 0;
  const maxLatency = latencies[latencies.length - 1] || 0;
  const p95Idx = Math.floor(latencies.length * 0.95);
  const p95Latency = latencies[p95Idx] || 0;

  return {
    targetRate: targetEventsPerSec,
    actualRate: Math.round(totalEvents / totalDuration),
    totalEvents,
    durationSeconds: parseFloat(totalDuration.toFixed(2)),
    avgLatencyMs: parseFloat(avgLatency.toFixed(3)),
    minLatencyMs: parseFloat(minLatency.toFixed(3)),
    maxLatencyMs: parseFloat(maxLatency.toFixed(3)),
    p95LatencyMs: parseFloat(p95Latency.toFixed(3))
  };
}

export async function runFullBenchmarkSuite(): Promise<BenchmarkResult[]> {
  console.log('\n======================================================');
  console.log(' ROLE-AUDIT BENCHMARK SUITE (PRD Section 18)');
  console.log(' Evaluating at 100, 500, and 1,000 audit events/sec');
  console.log('======================================================\n');

  const rates = [100, 500, 1000];
  const results: BenchmarkResult[] = [];

  for (const rate of rates) {
    process.stdout.write(`Benchmarking target ${rate} events/sec... `);
    const result = await runRateBenchmark(rate, 2);
    results.push(result);
    console.log(
      `Done. Actual: ${result.actualRate} eps | Avg Latency: ${result.avgLatencyMs}ms | p95: ${result.p95LatencyMs}ms`
    );
  }

  console.log('\n---------------- SUMMARY TABLE ----------------');
  console.table(results);
  return results;
}

if (process.argv[1]?.includes('benchmark')) {
  runFullBenchmarkSuite().catch(console.error);
}
