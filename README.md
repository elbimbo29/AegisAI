# AegisAI

### Real-Time AI Ethics · Governance · Audit

AegisAI is a real-time AI governance layer that converts ethical principles into enforceable policy-as-code, applies inline governance decisions, and maintains a SHA-256 hash-chained audit trail for tamper-evident accountability.

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## The Three Pillars

| Pillar | What it does | Where it lives |
|---|---|---|
| **Ethics** | Policy-as-code rules that encode your principles | `policies/policies.yaml` |
| **Governance** | Inline enforcement — allow, redact, block, or escalate | `app/policy_kernel.py`, `app/enforcement.py` |
| **Audit** | SHA-256 hash chain that proves logs weren't altered | `app/audit.py` |

Detection (`app/plugins/`) feeds findings to both Ethics and Governance. The kernel decides. The gateway enforces. The audit chain proves.

---
## Architecture

![AegisAI request pipeline: Client → Gateway → Detect → Decide → Audit → Enforce → LLM or 403/202](docs/architecture.png)

AegisAI intercepts every request, evaluates it against policy, and logs the decision immutably.

## Request Lifecycle

Every request passes through four stages. The audit stage runs **before** enforcement, so even rejected requests produce tamper-evident records.

### 1. Detect — `app/plugins/`
The prompt is scanned by independent plugins. Each exposes the same interface: `scan(text) -> list[Finding]`. Plugins don't decide anything — they only report what they found.

- **PII plugin** — regex detectors for EMAIL, SSN, PHONE, and CREDIT_CARD (validated with the Luhn checksum to avoid false positives).
- **Injection plugin** — pattern matching for jailbreak attempts, split into `high` and `medium` severity tiers.

Adding a new detector is two lines: write the plugin, register it in `app/plugins/__init__.py`. Nothing else changes.

### 2. Decide — `app/policy_kernel.py`

The kernel receives findings and returns a `Decision`. It evaluates rules from `policies.yaml` using two principles:

- **Deny-trumps-allow** — any BLOCK rule short-circuits evaluation. If one plugin finds an SSN and another finds an email, the SSN wins.
- **First-match-wins** — within the same severity tier, the first matching rule determines the action.

If no rule matches, `default_action` (usually `allow`) applies. The kernel is pure logic — no I/O, no side effects, fully testable in isolation.

### 3. Audit — `app/audit.py`

Before any enforcement happens, the decision is written to a SQLite hash chain. Each row's `chain_hash` is: chain_hash = sha256(prev_hash + canonical_payload)

The first row uses `prev_hash = "0" * 64` (genesis). Verification recomputes every hash in order and compares. Editing any row invalidates its hash; deleting a row breaks the `prev_hash` linkage of the next row. Either way, tampering is detectable.

The audit **does not store raw prompts** — only their SHA-256 hash. This proves *what was scanned* without retaining sensitive content.

Because audit runs before enforcement, a blocked request still produces a record. The audit log is complete, not partial.

### 4. Enforce — `app/enforcement.py` + `app/main.py`

The gateway acts on the decision:

| Decision | Behavior |
|---|---|
| `allow` | Forward to the model unchanged |
| `redact` | Mask the matched span in-place, then forward |
| `block` | Return HTTP 403 — the prompt **never** reaches the model |
| `escalate` | Return HTTP 202 — queued for human review |

Enforcement has no knowledge of *why* a decision was made — it just executes. That separation keeps the gateway easy to reason about.

### Observability (parallel to the pipeline)

As decisions are made, counters are incremented in Redis:

- `aegis:decisions:<action>` — one counter per action
- `aegis:policies:<policy_name>` — one counter per triggered policy
- `aegis:findings:<plugin>` — one counter per detector

Grafana reads these counters to visualize governance activity in real time. Metrics are **best-effort**: if Redis is unavailable, the gateway keeps functioning and metrics are silently skipped. AegisAI's correctness never depends on observability.
