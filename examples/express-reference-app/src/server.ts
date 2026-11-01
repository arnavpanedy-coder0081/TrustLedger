import { createApp } from './app.js';
import { PostgresAuditStore } from '@role-audit/postgres';

const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

async function bootstrap() {
  let store;
  if (process.env.DATABASE_URL) {
    console.log('Connecting to PostgreSQL at:', process.env.DATABASE_URL);
    const pgStore = new PostgresAuditStore({ connectionString: process.env.DATABASE_URL });
    await pgStore.runMigrations();
    store = pgStore;
  }

  const allowInsecureDemoIdentity = process.env.ALLOW_INSECURE_DEMO_IDENTITY === 'true';
  const { app } = createApp({ store, allowInsecureDemoIdentity });

  app.listen(port, () => {
    console.log(`\n======================================================`);
    console.log(` ROLE-AUDIT REFERENCE APP RUNNING ON PORT ${port}`);
    console.log(` Healthcheck:       http://localhost:${port}/health`);
    console.log(` Invoices:          http://localhost:${port}/api/invoices`);
    console.log(` Audit Trail:       http://localhost:${port}/api/audit/events`);
    console.log(` Verify Chain:      http://localhost:${port}/api/audit/verify`);
    console.log(`======================================================\n`);
  });
}

bootstrap().catch((err) => {
  console.error('Failed to start reference server:', err);
  process.exit(1);
});
