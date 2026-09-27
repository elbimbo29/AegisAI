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

