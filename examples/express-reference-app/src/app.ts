import express, { type Request, type Response } from 'express';
import {
  type AuditStore,
  defaultMetrics
} from '@role-audit/core';
import { DataMasker } from '@role-audit/masking';
import { RbacEngine } from '@role-audit/rbac';
import { AbacEngine, AuthorizationEngine } from '@role-audit/abac';
import {
  AuditChainEngine,
  AuditChainVerifier,
  identityMiddleware,
  authorize,
  auditMiddleware,
  MemoryAuditStore
} from '@role-audit/audit';

export interface AppOptions {
  store?: AuditStore;
  /** Enables caller-controlled demo headers. Never enable this in production. */
  allowInsecureDemoIdentity?: boolean;
}

export function createApp(options: AppOptions = {}) {
  const app = express();
  app.use(express.json());

  // 1. Audit Store & Masker
  const auditStore = options.store || new MemoryAuditStore();
  const masker = new DataMasker({
    sensitiveFieldNames: ['creditCard', 'password', 'token', 'ssn'],
    pseudonymizeFields: ['customerEmail', 'email'] // Demonstrate deterministic pseudonymization
  });

  const auditEngine = new AuditChainEngine({
    store: auditStore,
    masker,
    strictMode: true
  });

  const verifier = new AuditChainVerifier(auditStore);

  // 2. RBAC Engine Setup
  const rbacEngine = new RbacEngine();

  // 3. ABAC Engine Setup
  const abacEngine = new AbacEngine();

  // Register ABAC policies according to PRD Section 15
  abacEngine.registerPolicies([
    {
      policyId: 'invoice-access',
      version: 1,
      effect: 'ALLOW',
      tenantId: '*',
      actions: ['invoice:read', 'invoice:create'],
      resources: ['invoice'],
      roles: ['manager', 'admin', 'finance_manager', 'viewer'],
      conditions: [
        {
          attribute: 'resource.tenantId',
          operator: 'equals',
          value: 'tenant.tenantId',
          description: 'Tenant isolation: resource must belong to caller tenant'
        }
      ]
    },
    {
      policyId: 'patient-department-match',
      version: 2,
      effect: 'ALLOW',
      tenantId: 'tenant-healthcare',
      actions: ['patient:read', 'patient:update'],
      resources: ['patient'],
      roles: ['manager', 'admin', 'analyst', 'viewer'],
      conditions: [
        {
          attribute: 'resource.attributes.department',
          operator: 'equals',
          value: 'subject.attributes.department',
          description: 'Department matching ABAC rule'
        }
      ]
    },
    {
      policyId: 'export-data-policy',
      version: 1,
      effect: 'ALLOW',
      tenantId: '*',
      actions: ['data:export'],
      resources: ['data'],
      roles: ['analyst', 'manager', 'admin']
    },
    {
      policyId: 'audit-admin-policy',
      version: 1,
      effect: 'ALLOW',
      tenantId: '*',
      actions: ['audit:read', 'audit:verify'],
      resources: ['audit'],
      roles: ['auditor', 'admin']
    },
    {
      policyId: 'deny-confidential-without-clearance',
      version: 1,
      effect: 'DENY',
      tenantId: '*',
      actions: ['*'],
      resources: ['*'],
      conditions: [
        {
          attribute: 'resource.attributes.classification',
          operator: 'equals',
          value: 'top-secret'
        },
        {
          attribute: 'subject.attributes.clearance',
          operator: 'notEquals',
          value: 'top-secret'
        }
      ],
      description: 'Explicit DENY if top-secret classification without matching clearance'
    }
  ]);

  // 4. Combined Authorization Engine (RBAC + ABAC + Multi-Tenant Isolation)
  const authzEngine = new AuthorizationEngine({
    rbac: rbacEngine,
    abac: abacEngine,
    strategy: 'RBAC_AND_ABAC',
    enforceTenantIsolation: true
  });

  // 5. Global Middlewares
  app.use(identityMiddleware(options.allowInsecureDemoIdentity ? {
    resolvePrincipal: (req) => {
      const userId = (req.headers['x-user-id'] as string) || 'alice-mgr';
      const rolesHeader = req.headers['x-user-roles'] as string;
      const roles = rolesHeader ? rolesHeader.split(',').map((r) => r.trim()) : ['manager'];
      const dept = (req.headers['x-user-department'] as string) || 'oncology';
      const clearance = (req.headers['x-user-clearance'] as string) || 'standard';

      return {
        id: userId,
        type: 'human',
        roles,
        attributes: {
          department: dept,
          clearance
        }
      };
    },
    resolveTenant: (req) => {
      const tenantId = (req.headers['x-tenant-id'] as string) || 'tenant-alpha';
      const status = (req.headers['x-tenant-status'] as any) || 'active';
      return { tenantId, status };
    }
  } : {}));

  // Global Audit Interceptor
  app.use(auditMiddleware({
    auditEngine,
    includeRequestBody: true
  }));

  // ---------------- ROUTES ----------------

  // Healthcheck & Observability
  app.get('/health', (req: Request, res: Response) => {
    res.json({
      status: 'UP',
      timestamp: new Date().toISOString(),
      metrics: defaultMetrics.getSnapshot()
    });
  });

  // Business Route: List Invoices
  app.get(
    '/api/invoices',
    authorize({
      action: 'invoice:read',
      resource: 'invoice',
      authzEngine,
      auditEngine
    }),
    (req: Request, res: Response) => {
      res.json({
        invoices: [
          { id: 'inv-101', amount: 500.0, status: 'PAID' },
          { id: 'inv-102', amount: 1200.5, status: 'PENDING' }
        ]
      });
    }
  );

  // Business Route: Create Invoice (Contains PII & Sensitive Payment Info)
  app.post(
    '/api/invoices',
    authorize({
      action: 'invoice:create',
      resource: 'invoice',
      authzEngine,
      auditEngine
    }),
    (req: Request, res: Response) => {
      const body = req.body || {};
      req.auditPayload = {
        invoiceId: body.invoiceId || 'inv-999',
        amount: body.amount,
        customerEmail: body.customerEmail, // will be pseudonymized
        creditCard: body.creditCard, // will be masked
        cvv: body.cvv, // will be redacted
        billingAddress: body.billingAddress
      };

      res.status(201).json({
        success: true,
        message: 'Invoice created successfully',
        invoiceId: req.auditPayload.invoiceId
      });
    }
  );

  // Business Route: Patient Records (Enforces ABAC Department Match)
  app.get(
    '/api/patients/:id',
    authorize({
      action: 'patient:read',
      resource: (req) => ({
        type: 'patient',
        id: String(req.params.id),
        tenantId: req.securityContext?.tenant.tenantId,
        attributes: {
          department: (req.query.department as string) || 'oncology'
        }
      }),
      authzEngine,
      auditEngine
    }),
    (req: Request, res: Response) => {
      res.json({
        patientId: req.params.id,
        department: req.query.department || 'oncology',
        diagnosis: 'Stage 1 Recovery Plan'
      });
    }
  );

  // Business Route: Data Export
  app.post(
    '/api/export',
    authorize({
      action: 'data:export',
      resource: 'data',
      authzEngine,
      auditEngine
    }),
    (req: Request, res: Response) => {
      res.json({
        exportJobId: 'export-777',
        status: 'PROCESSING'
      });
    }
  );

  // Audit Administration: Query Audit Events
  app.get(
    '/api/audit/events',
    authorize({
      action: 'audit:read',
      resource: 'audit',
      authzEngine,
      auditEngine
    }),
    async (req: Request, res: Response) => {
      const tenantId = req.securityContext?.tenant.tenantId || 'tenant-alpha';
      const events = await auditStore.getEvents(tenantId);
      res.json({
        tenantId,
        count: events.length,
        events
      });
    }
  );

  // Audit Administration: Run Cryptographic Chain Verification
  app.get(
    '/api/audit/verify',
    authorize({
      action: 'audit:verify',
      resource: 'audit',
      authzEngine,
      auditEngine
    }),
    async (req: Request, res: Response) => {
      const tenantId = req.securityContext?.tenant.tenantId || 'tenant-alpha';
      const result = await verifier.verifyTenantChain(tenantId);
      res.json(result);
    }
  );

  return { app, auditStore, auditEngine, verifier, authzEngine };
}
