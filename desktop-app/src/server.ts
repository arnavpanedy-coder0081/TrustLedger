import http from 'node:http';
import { exec } from 'node:child_process';

// @ts-ignore
import uiHtml from './ui.html';

import { generateUuid } from '../../packages/core/src/index.js';
import { DataMasker } from '../../packages/masking/src/index.js';
import { RbacEngine } from '../../packages/rbac/src/index.js';
import { AbacEngine, AuthorizationEngine } from '../../packages/abac/src/index.js';
import {
  AuditChainEngine,
  AuditChainVerifier,
  FileAuditStore
} from '../../packages/audit/src/index.js';
import { runRateBenchmark } from '../../cli/src/benchmark.js';
import { isAllowedDesktopRequest } from './security.js';

// Setup Engines
let store = new FileAuditStore(process.env.TRUSTLEDGER_DATA_FILE);
const masker = new DataMasker({
  sensitiveFieldNames: ['creditCard', 'password', 'token', 'ssn'],
  pseudonymizeFields: ['email', 'customerEmail']
});
let auditEngine = new AuditChainEngine({ store, masker });
let verifier = new AuditChainVerifier(store);

const rbac = new RbacEngine();
const abac = new AbacEngine();

// Register standard policies
abac.registerPolicies([
  {
    policyId: 'invoice-access',
    version: 1,
    effect: 'ALLOW',
    tenantId: '*',
    actions: ['invoice:read', 'invoice:create'],
    resources: ['invoice'],
    roles: ['manager', 'admin', 'analyst', 'viewer']
  },
  {
    policyId: 'patient-department-match',
    version: 2,
    effect: 'ALLOW',
    tenantId: '*',
    actions: ['patient:read', 'patient:update'],
    resources: ['patient'],
    roles: ['manager', 'admin', 'analyst', 'viewer'],
    conditions: [
      {
        attribute: 'resource.attributes.department',
        operator: 'equals',
        value: 'subject.attributes.department',
        description: 'Department match condition'
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
    policyId: 'audit-verify-policy',
    version: 1,
    effect: 'ALLOW',
    tenantId: '*',
    actions: ['audit:verify', 'audit:read'],
    resources: ['audit'],
    roles: ['auditor', 'admin']
  }
]);

const authz = new AuthorizationEngine({
  rbac,
  abac,
  strategy: 'RBAC_AND_ABAC',
  enforceTenantIsolation: true
});

// Seed Initial Events
async function seedInitialEvents() {
  await auditEngine.log({
    tenant_id: 'tenant-alpha',
    principal_id: 'system',
    principal_type: 'system',
    action: 'tenant:create',
    resource_type: 'tenant',
    resource_id: 'tenant-alpha',
    decision: 'ALLOW',
    request_context: { correlationId: 'init-1', ip: '127.0.0.1' },
    payload: { status: 'INITIALIZED', region: 'us-east-1' }
  });

  await auditEngine.log({
    tenant_id: 'tenant-alpha',
    principal_id: 'alice-mgr',
    principal_type: 'human',
    action: 'invoice:create',
    resource_type: 'invoice',
    resource_id: 'inv-101',
    decision: 'ALLOW',
    request_context: { correlationId: 'init-2', ip: '192.168.1.10' },
    payload: {
      amount: 450.0,
      customerEmail: 'billing@enterprise.com',
      creditCard: '4111 2222 3333 4444'
    }
  });

  await auditEngine.log({
    tenant_id: 'tenant-alpha',
    principal_id: 'bob-analyst',
    principal_type: 'human',
    action: 'invoice:read',
    resource_type: 'invoice',
    resource_id: 'inv-101',
    decision: 'ALLOW',
    request_context: { correlationId: 'init-3', ip: '192.168.1.15' },
    payload: { invoiceId: 'inv-101' }
  });
}

// HTTP Server
const server = http.createServer(async (req, res) => {
  if (!isAllowedDesktopRequest(req.headers.host, req.headers.origin, PORT)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }
  const url = req.url || '/';

  const sendJson = (statusCode: number, data: any) => {
    res.writeHead(statusCode, {
      'Content-Type': 'application/json; charset=utf-8'
    });
    res.end(JSON.stringify(data));
  };

  const readBody = (): Promise<any> => {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch (err) {
          reject(err);
        }
      });
      req.on('error', reject);
    });
  };

  if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(uiHtml);
    return;
  }

  if (req.method === 'GET' && url === '/api/events') {
    const events = await store.getEvents('tenant-alpha');
    sendJson(200, events);
    return;
  }

  if (req.method === 'GET' && url === '/api/verify') {
    const result = await verifier.verifyTenantChain('tenant-alpha');
    sendJson(200, result);
    return;
  }

  if (req.method === 'POST' && url === '/api/evaluate') {
    try {
      const body = await readBody();
      const roles = body.roles && body.roles[0] === 'unassigned' ? [] : body.roles || ['manager'];

      const decision = await authz.check({
        subject: {
          id: body.userId || 'alice-mgr',
          type: 'human',
          roles,
          attributes: {
            department: body.userDepartment || 'oncology'
          }
        },
        tenant: {
          tenantId: body.tenantId || 'tenant-alpha',
          status: 'active'
        },
        action: body.action || 'invoice:read',
        resource: {
          type: body.resourceType || 'invoice',
          tenantId: body.tenantId || 'tenant-alpha',
          attributes: {
            department: body.resourceDepartment || 'oncology'
          }
        },
        request: {
          correlationId: generateUuid(),
          ip: req.socket.remoteAddress
        }
      });

      await auditEngine.log({
        tenant_id: body.tenantId || 'tenant-alpha',
        principal_id: body.userId || 'alice-mgr',
        principal_type: 'human',
        action: body.action || 'invoice:read',
        resource_type: body.resourceType || 'invoice',
        decision: decision.effect,
        policy_id: decision.policyId,
        policy_version: decision.policyVersion,
        request_context: {
          correlationId: generateUuid(),
          ip: req.socket.remoteAddress
        },
        payload: {
          reason: decision.reason,
          matchedConditions: decision.matchedConditions
        }
      });

      sendJson(200, { decision });
    } catch (err: any) {
      sendJson(500, { error: err.message });
    }
    return;
  }

  if (req.method === 'POST' && url === '/api/mask') {
    try {
      const body = await readBody();
      const masked = masker.mask(body.payload);
      sendJson(200, { masked });
    } catch (err: any) {
      sendJson(500, { error: err.message });
    }
    return;
  }

  if (req.method === 'POST' && url === '/api/tamper') {
    try {
      const body = await readBody();
      const attackType = body.attackType;
      const events = await store.getEvents('tenant-alpha');

      if (attackType === 'reset') {
        store.clear();
        await seedInitialEvents();
        sendJson(200, { success: true, message: 'Chain restored to clean state' });
        return;
      }

      if (events.length === 0) {
        sendJson(400, { error: 'No events to tamper with. Seed events first.' });
        return;
      }

      if (attackType === 'modify') {
        const target = events[1] || events[0]!;
        store.tamperModifyEvent(target.audit_id, (ev) => {
          ev.masked_payload = { ...ev.masked_payload, TAMPERED_FIELD: 'MALICIOUS_MODIFICATION' };
        });
        sendJson(200, { success: true, message: `Modified payload of audit event "${target.audit_id}"` });
        return;
      }

      if (attackType === 'delete') {
        const target = events[1] || events[0]!;
        store.tamperDeleteEvent(target.audit_id);
        sendJson(200, { success: true, message: `Deleted event "${target.audit_id}" from chain` });
        return;
      }

      if (attackType === 'insert') {
        store.tamperInsertEvent(1, {
          audit_id: generateUuid(),
          tenant_id: 'tenant-alpha',
          timestamp: new Date().toISOString(),
          principal_id: 'hacker',
          principal_type: 'human',
          action: 'admin:backdoor',
          resource_type: 'system',
          resource_id: null,
          decision: 'ALLOW',
          policy_id: null,
          policy_version: null,
          request_context: { correlationId: 'rogue-injection' },
          masked_payload: null,
          previous_hash: 'forged_previous_hash',
          event_hash: 'forged_event_hash',
          schema_version: '1.0.0'
        });
        sendJson(200, { success: true, message: 'Injected rogue unauthorized event into index 1' });
        return;
      }

      if (attackType === 'reorder') {
        if (events.length >= 2) {
          store.tamperReorderEvents(0, 1);
          sendJson(200, { success: true, message: 'Swapped event 0 and event 1 order' });
        } else {
          sendJson(400, { error: 'Need at least 2 events to reorder' });
        }
        return;
      }

      sendJson(400, { error: 'Unknown attack type' });
    } catch (err: any) {
      sendJson(500, { error: err.message });
    }
    return;
  }

  if (req.method === 'POST' && url === '/api/benchmark') {
    try {
      const body = await readBody();
      const rate = body.rate || 100;
      const result = await runRateBenchmark(rate, 1);
      sendJson(200, result);
    } catch (err: any) {
      sendJson(500, { error: err.message });
    }
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 4200;

seedInitialEvents().then(() => {
  server.listen(PORT, '127.0.0.1', () => {
    const appUrl = `http://127.0.0.1:${PORT}`;
    console.log('\n=============================================================');
    console.log(' ROLE-BASED IDENTITY & AUDIT LOG MIDDLEWARE ENGINE');
    console.log(` Running Minimal Desktop App at: ${appUrl}`);
    console.log(' Press Ctrl+C in this window to stop.');
    console.log('=============================================================\n');

    exec(`start ${appUrl}`, () => {});
  });
});
