import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      '@role-audit/core': path.resolve(__dirname, 'packages/core/src/index.ts'),
      '@role-audit/masking': path.resolve(__dirname, 'packages/masking/src/index.ts'),
      '@role-audit/rbac': path.resolve(__dirname, 'packages/rbac/src/index.ts'),
      '@role-audit/abac': path.resolve(__dirname, 'packages/abac/src/index.ts'),
      '@role-audit/audit': path.resolve(__dirname, 'packages/audit/src/index.ts'),
      '@role-audit/postgres': path.resolve(__dirname, 'packages/postgres/src/index.ts')
    }
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts']
  }
});
