# Audit Chain Verification Guide

This guide explains how the cryptographic verification engine guarantees audit trail integrity, how tampering is detected, and how to operate the CLI verification tooling.

## Mathematical Model

Each tenant maintains a distinct linear hash chain. The root event (Genesis Block) points to a known 64-character constant:
```
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
```

For every subsequent event $i > 0$:
1. The event's `previous_hash` must match the exact `event_hash` of event $i - 1$:
   $$\text{previous\_hash}_i = \text{event\_hash}_{i - 1}$$
2. The event's own `event_hash` is computed deterministically:
   $$\text{event\_hash}_i = \text{SHA256}(\text{canonical\_json}(\text{event}_i) \parallel \text{"\|"} \parallel \text{previous\_hash}_i)$$

## Tamper-Evidence Detection

| Attack Vector | Detection Mechanism | Reported Reason |
|---|---|---|
| **Modification Attack**<br>Altering an event's payload, decision, or user ID | Recalculated SHA-256 hash differs from stored `event_hash` | `EVENT_HASH_MISMATCH` |
| **Deletion Attack**<br>Removing an intermediate record | Next record's `previous_hash` fails to match predecessor's `event_hash` | `PREVIOUS_HASH_MISMATCH` |
| **Insertion Attack**<br>Injecting a fraudulent rogue record | Predecessor/successor linkage breaks at insertion point | `PREVIOUS_HASH_MISMATCH` |
| **Reordering Attack**<br>Swapping two adjacent records | Chain links between swapped events and neighbors break | `PREVIOUS_HASH_MISMATCH` or `OUT_OF_ORDER` |

## CLI Verification Usage

### Verify a Specific Tenant
```bash
npm run cli -- verify --tenant tenant-alpha --database-url postgresql://postgres:postgres@localhost:5432/role_audit_db
```

Sample success output:
```
--- VERIFICATION REPORT ---
Tenant ID:       tenant-alpha
Total Events:    42
Genesis Hash:    0000000000000000000000000000000000000000000000000000000000000000
Head Hash:       7a1cf718f673891461ea55fa02f1ba8e578c772e70e173e3518e2be35c5c0882
Execution Time:  1.42 ms
Checked At:      2026-10-07T12:00:00.000Z

 STATUS: [PASSED] 100% Hash Chain Integrity Intact. No tampering detected.
```

Sample tampering alert output:
```
--- VERIFICATION REPORT ---
Tenant ID:       tenant-tampered
Total Events:    10
...
 STATUS: [ALERT - TAMPERING DETECTED]
First Broken Link Index: 3
Audit Event ID:         c56a4180-65aa-42ec-a945-5fd21dec0538
Tamper Reason:          EVENT_HASH_MISMATCH
Expected Previous Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Actual Previous Hash:   5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Expected Event Hash:    9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72
Actual Event Hash:      4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945
Details:                Payload or metadata modification detected for audit_id "c56a4180-65aa-42ec-a945-5fd21dec0538" at index 3.
```

### Running Automated Attack Suite
Run the automated test fixtures to verify detection of all attack classes:
```bash
npm run tamper-test
```
