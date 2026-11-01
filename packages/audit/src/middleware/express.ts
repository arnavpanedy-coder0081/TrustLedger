import type { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  type SecurityContext,
  type Principal,
  type TenantContext,
  type Decision,
  type ResourceContext,
  generateUuid,
  defaultMetrics
} from '@role-audit/core';
import { AuthorizationEngine } from '@role-audit/abac';
import { AuditChainEngine } from '../engine/chain.js';

declare global {
  namespace Express {
    interface Request {
      securityContext?: SecurityContext;
      decision?: Decision;
      auditAction?: string;
      auditResourceType?: string;
      auditResourceId?: string;
      auditPayload?: Record<string, unknown>;
    }
  }
}

export interface IdentityAdapterOptions {
  resolvePrincipal?: (req: Request) => Promise<Principal | null> | Principal | null;
  resolveTenant?: (req: Request) => Promise<TenantContext | null> | TenantContext | null;
  defaultTenantId?: string;
}

export function identityMiddleware(options: IdentityAdapterOptions = {}): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const requestId = (req.headers['x-request-id'] as string) || generateUuid();
      const correlationId = (req.headers['x-correlation-id'] as string) || requestId;
      res.setHeader('x-request-id', requestId);
      res.setHeader('x-correlation-id', correlationId);

      // 1. Resolve Tenant Context. Never trust an unverified tenant header here.
      let tenant: TenantContext | null = null;
      if (options.resolveTenant) {
        tenant = await options.resolveTenant(req);
      } else {
        const tenantId = options.defaultTenantId || 'default-tenant';
        tenant = {
          tenantId,
          status: 'active'
        };
      }

      // 2. Resolve Principal. Authentication belongs to a trusted adapter;
      // caller-controlled identity headers must never grant roles by default.
      let principal: Principal | null = null;
      if (options.resolvePrincipal) {
        principal = await options.resolvePrincipal(req);
      } else {
        principal = {
          id: 'anonymous',
          type: 'anonymous',
          roles: [],
          tenantId: tenant?.tenantId,
        };
      }

      req.securityContext = {
        principal: principal || {
          id: 'anonymous',
          type: 'anonymous',
          roles: []
        },
        tenant: tenant || {
          tenantId: 'default-tenant',
          status: 'active'
        },
        requestId,
        correlationId,
        ip: req.ip || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
        timestamp: new Date().toISOString()
      };

      next();
    } catch (err) {
      next(err);
    }
  };
}

export interface AuthorizeOptions {
  action: string;
  resource: string | ((req: Request) => ResourceContext);
  authzEngine: AuthorizationEngine;
  auditEngine?: AuditChainEngine;
}

/**
 * Route-level or general authorization middleware
 */
export function authorize(options: AuthorizeOptions): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const secCtx = req.securityContext;
    if (!secCtx) {
      res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Identity context missing' });
      return;
    }

    const action = options.action;
    const resource: ResourceContext =
      typeof options.resource === 'function'
        ? options.resource(req)
        : { type: options.resource, id: (req.params?.id as string) || undefined, tenantId: secCtx.tenant.tenantId };

    req.auditAction = action;
    req.auditResourceType = resource.type;
    req.auditResourceId = resource.id;

    const decision = await defaultMetrics.timeAsync('authz.evaluation_duration_ms', async () => {
      return options.authzEngine.check({
        subject: secCtx.principal,
        tenant: secCtx.tenant,
        action,
        resource,
        request: {
          correlationId: secCtx.correlationId,
          requestId: secCtx.requestId,
          ip: secCtx.ip,
          userAgent: secCtx.userAgent,
          httpMethod: req.method,
          httpPath: req.originalUrl || req.path
        }
      });
    });

    req.decision = decision;

    if (decision.effect === 'DENY') {
      defaultMetrics.incrementCounter('authz.denials_total');

      // Intercept and write audit record on access denial immediately
      if (options.auditEngine) {
        await options.auditEngine.log({
          tenant_id: secCtx.tenant.tenantId,
          principal_id: secCtx.principal.id,
          principal_type: secCtx.principal.type,
          action,
          resource_type: resource.type,
          resource_id: resource.id ?? null,
          decision: 'DENY',
          policy_id: decision.policyId ?? null,
          policy_version: decision.policyVersion ?? null,
          request_context: {
            correlationId: secCtx.correlationId,
            requestId: secCtx.requestId,
            ip: secCtx.ip,
            userAgent: secCtx.userAgent,
            httpMethod: req.method,
            httpPath: req.originalUrl || req.path,
            statusCode: 403
          },
          payload: {
            reason: decision.reason,
            traces: decision.traces,
            matchedConditions: decision.matchedConditions
          }
        }).catch((err) => console.error('Failed to log audit on denial:', err));
      }

      res.status(403).json({
        error: 'FORBIDDEN',
        message: decision.reason,
        policyId: decision.policyId,
        traces: decision.traces
      });
      return;
    }

    defaultMetrics.incrementCounter('authz.allowances_total');
    next();
  };
}

export interface AuditMiddlewareOptions {
  auditEngine: AuditChainEngine;
  resolvePayload?: (req: Request, res: Response) => Record<string, unknown> | null;
  includeRequestBody?: boolean;
}

/**
 * Audit interceptor middleware capturing request completion, outcome, and hash chaining.
 */
export function auditMiddleware(options: AuditMiddlewareOptions): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const startTime = performance.now();

    res.on('finish', () => {
      const durationMs = performance.now() - startTime;
      const secCtx = req.securityContext;

      if (!secCtx) return;

      // Avoid double logging if already audited on DENY
      if (req.decision?.effect === 'DENY' && res.statusCode === 403) {
        return;
      }

      const decision = req.decision ? req.decision.effect : (res.statusCode < 400 ? 'ALLOW' : 'DENY');
      const action = req.auditAction || `${req.method.toLowerCase()}:${req.baseUrl || req.path}`;
      const resourceType = req.auditResourceType || (req.path.split('/')[2] || 'endpoint');
      const resourceId = req.auditResourceId || (req.params?.id as string) || null;

      let payload: Record<string, unknown> | null = null;
      if (options.resolvePayload) {
        payload = options.resolvePayload(req, res);
      } else if (req.auditPayload) {
        payload = req.auditPayload;
      } else if (options.includeRequestBody && req.body && Object.keys(req.body).length > 0) {
        payload = { body: req.body };
      }

      options.auditEngine.log({
        tenant_id: secCtx.tenant.tenantId,
        principal_id: secCtx.principal.id,
        principal_type: secCtx.principal.type,
        action,
        resource_type: resourceType,
        resource_id: resourceId,
        decision,
        policy_id: req.decision?.policyId ?? null,
        policy_version: req.decision?.policyVersion ?? null,
        request_context: {
          correlationId: secCtx.correlationId,
          requestId: secCtx.requestId,
          ip: secCtx.ip,
          userAgent: secCtx.userAgent,
          httpMethod: req.method,
          httpPath: req.originalUrl || req.path,
          statusCode: res.statusCode,
          durationMs: Math.round(durationMs)
        },
        payload
      }).catch((err) => {
        console.error('Audit persistence failure in interceptor:', err);
      });
    });

    next();
  };
}
