# Policy Specification & Authorization Guide

The engine supports a hybrid authorization model uniting Role-Based Access Control (RBAC) with Attribute-Based Access Control (ABAC).

## 1. Role-Based Access Control (RBAC)

### Standard Enterprise Roles (PRD Section 6.1)
- **`viewer`**: Read-only capability across tenant resources (`*:read`).
- **`analyst`**: Analysis, read, and data export operations (`*:read`, `*:export`, `*:analyze`). Inherits from `viewer`.
- **`manager`**: Management operations over tenant resources, reads, creates, updates, and exports (`*:read`, `*:create`, `*:update`, `*:export`). Inherits from `analyst`.
- **`admin`**: Full administrative access across all tenant resources (`*:*`). Inherits from `manager`.
- **`auditor`**: Compliance and security access to audit logs and verification tooling (`audit:read`, `audit:verify`, `policy:read`, `report:read`).

### Explicit Deny Semantics
Explicit deny takes strict precedence over any inherited or explicit allowances. Permissions prefixed with `!` trigger immediate denial:
```json
{
  "name": "restricted-manager",
  "permissions": ["*:*", "!invoice:delete"],
  "inherits": ["manager"]
}
```

## 2. Attribute-Based Access Control (ABAC)

ABAC policies provide dynamic, context-aware policy evaluation across subject, resource, action, environment, and tenant attributes.

### Policy Schema (PRD Section 15)
```json
{
  "policyId": "invoice-department-policy",
  "version": 1,
  "effect": "ALLOW",
  "tenantId": "*",
  "actions": ["invoice:read", "invoice:update"],
  "resources": ["invoice"],
  "roles": ["manager"],
  "priority": 10,
  "conditions": [
    {
      "attribute": "resource.tenantId",
      "operator": "equals",
      "value": "tenant.tenantId",
      "description": "Tenant isolation: resource must belong to caller tenant"
    },
    {
      "attribute": "resource.attributes.department",
      "operator": "equals",
      "value": "subject.attributes.department",
      "description": "Department match: user can only access invoices for their assigned department"
    }
  ]
}
```

### Supported Condition Operators

| Operator | Description | Example |
|---|---|---|
| `equals` / `eq` | Strict equality | `"resource.tenantId" equals "tenant.tenantId"` |
| `notEquals` / `neq` | Inequality | `"subject.attributes.clearance" notEquals "guest"` |
| `in` | Value exists in target array or string | `"subject.attributes.department" in ["finance", "legal"]` |
| `notIn` | Value does not exist in target array | `"request.ip" notIn ["10.0.0.1"]` |
| `contains` | Target array contains value | `"resource.attributes.tags" contains "sensitive"` |
| `greaterThan` / `gt` | Numeric greater than | `"resource.attributes.amount" gt 1000` |
| `greaterThanOrEqual` / `gte` | Numeric greater than or equal | `"subject.attributes.clearanceLevel" gte 3` |
| `lessThan` / `lt` | Numeric less than | `"resource.attributes.riskScore" lt 50` |
| `lessThanOrEqual` / `lte` | Numeric less than or equal | `"resource.attributes.count" lte 100` |
| `matches` | Regular expression match | `"resource.id" matches "^inv-[0-9]{4}$"` |
| `exists` | Field exists and is non-empty | `"resource.attributes.ownerId" exists true` |
| `timeWindow` | UTC business hours time window | `"request.timestamp" timeWindow "09:00-17:00"` |
| `cidrMatches` | IP or subnet mask match | `"request.ip" cidrMatches "192.168.1.*"` |
