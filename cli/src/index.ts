#!/usr/bin/env node
import { Command } from 'commander';
import { AuditChainVerifier, MemoryAuditStore } from '@role-audit/audit';
import { PostgresAuditStore } from '@role-audit/postgres';
import { runTamperAttackSuite } from './tamper-test.js';
import { runFullBenchmarkSuite, runRateBenchmark } from './benchmark.js';

const program = new Command();

program
  .name('role-audit')
  .description('CLI tool for Role-Based Identity & Audit Log Middleware Engine')
  .version('1.0.0');

program
  .command('verify')
  .description('Verify the tamper-evident SHA-256 hash chain for a tenant')
  .requiredOption('-t, --tenant <tenantId>', 'Tenant ID to verify')
  .option('-d, --database-url <url>', 'PostgreSQL database connection URL')
  .action(async (options) => {
    try {
      console.log(`\nVerifying audit chain for tenant: "${options.tenant}"...`);

      let store;
      if (options.databaseUrl) {
        store = new PostgresAuditStore({ connectionString: options.databaseUrl });
      } else {
        console.log('Note: No database URL provided. Checking local in-memory store.');
        store = new MemoryAuditStore();
      }

      const verifier = new AuditChainVerifier(store);
      const result = await verifier.verifyTenantChain(options.tenant);

      console.log('\n--- VERIFICATION REPORT ---');
      console.log(`Tenant ID:       ${result.tenant_id}`);
      console.log(`Total Events:    ${result.total_events}`);
      console.log(`Genesis Hash:    ${result.genesis_hash}`);
      console.log(`Head Hash:       ${result.head_hash || 'None (empty stream)'}`);
      console.log(`Execution Time:  ${result.duration_ms.toFixed(2)} ms`);
      console.log(`Checked At:      ${result.checked_at}`);

      if (result.verified) {
        console.log('\n STATUS: [PASSED] 100% Hash Chain Integrity Intact. No tampering detected.\n');
        process.exit(0);
      } else {
        console.error('\n STATUS: [ALERT - TAMPERING DETECTED]');
        console.error(`First Broken Link Index: ${result.first_broken_link?.index}`);
        console.error(`Audit Event ID:         ${result.first_broken_link?.audit_id}`);
        console.error(`Tamper Reason:          ${result.first_broken_link?.reason}`);
        console.error(`Expected Previous Hash: ${result.first_broken_link?.expected_previous_hash}`);
        console.error(`Actual Previous Hash:   ${result.first_broken_link?.actual_previous_hash}`);
        console.error(`Expected Event Hash:    ${result.first_broken_link?.expected_event_hash}`);
        console.error(`Actual Event Hash:      ${result.first_broken_link?.actual_event_hash}`);
        console.error(`Details:                ${result.first_broken_link?.details}\n`);
        process.exit(1);
      }
    } catch (err: any) {
      console.error('Verification failed with error:', err.message);
      process.exit(1);
    }
  });

program
  .command('tamper-test')
  .description('Run automated tampering attack suite (modification, deletion, insertion, reordering)')
  .action(async () => {
    const success = await runTamperAttackSuite();
    process.exit(success ? 0 : 1);
  });

program
  .command('benchmark')
  .description('Run performance benchmark (evaluates 100, 500, and 1,000 eps per PRD)')
  .option('-r, --rate <rate>', 'Target events per second (default: all)')
  .option('-s, --duration <sec>', 'Duration in seconds', '2')
  .action(async (options) => {
    if (options.rate) {
      const rate = parseInt(options.rate, 10);
      const duration = parseInt(options.duration, 10);
      const res = await runRateBenchmark(rate, duration);
      console.table([res]);
    } else {
      await runFullBenchmarkSuite();
    }
  });

program.parse(process.argv);
