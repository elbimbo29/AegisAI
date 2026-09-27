"""AegisAI — FastAPI entrypoint.

Real-Time AI Ethics · Governance · Audit
"""

import os
import time

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response

from app import audit, metrics
from app.enforcement import describe_decision, redact_text
from app.gateway import forward_to_model
from app.models import ChatRequest, ChatResponse, Finding
from app.plugins import run_all as run_all_plugins
from app.policy_kernel import PolicyKernel

load_dotenv()

AUDIT_DB_PATH = os.getenv("AUDIT_DB_PATH", "./data/audit.db")

app = FastAPI(
    title="AegisAI",
    description="Real-time AI governance layer with tamper-evident audit.",
    version="0.6.0",
)

kernel = PolicyKernel.from_yaml("policies/policies.yaml")


# --- Health & introspection ---


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {
        "status": "ok",
        "service": "aegisai",
        "version": app.version,
    }


@app.get("/policies")
async def list_policies() -> list[dict]:
    """Inspect the loaded policy set."""
    return [rule.model_dump() for rule in kernel.policy_file.policies]


@app.get("/metrics")
async def get_metrics() -> dict:
    """Snapshot of AegisAI metrics. Grafana can poll this or read Redis directly."""
    return metrics.snapshot()


# --- Audit endpoints ---


@app.get("/audit")
async def get_audit(limit: int = 20) -> list[dict]:
    """Return the most recent audit records (newest first)."""
    return audit.recent_records(AUDIT_DB_PATH, limit=limit)


@app.get("/audit/verify")
async def verify_audit() -> dict:
    """Verify the audit chain's integrity."""
    valid, broken_at = audit.verify_chain(AUDIT_DB_PATH)
    return {"valid": valid, "broken_at": broken_at}


# --- Main endpoint ---


@app.post("/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(
    request: ChatRequest,
    response: Response,
) -> ChatResponse:
    """OpenAI-compatible chat completions endpoint.

    Phase 6 flow:
      1. Scan input for findings
      2. Evaluate findings -> decision (timed)
      3. Write audit record (every decision, including blocks)
      4. Record metrics
      5. Enforce (allow / redact / block / escalate)
      6. Forward to model (only if allow or redact)
      7. Attach decision metadata to response headers
    """
    # 1. Scan.
    last_user_text = next(
        (m.content for m in reversed(request.messages) if m.role == "user"),
        "",
    )
    findings: list[Finding] = run_all_plugins(last_user_text)

    # 2. Decide (timed).
    start = time.perf_counter()
    decision = kernel.evaluate(findings)
    latency_ms = (time.perf_counter() - start) * 1000.0

    # 3. Audit — always, before enforcement, so even blocked requests are logged.
    record = audit.write_record(AUDIT_DB_PATH, last_user_text, decision)

    # 4. Metrics — best-effort.
    metrics.record_decision(
        action=decision.action,
        policy_name=decision.policy_name,
        findings_count=len(findings),
    )
    for finding in findings:
        metrics.record_finding(finding.plugin)
    metrics.record_latency(latency_ms)

    # 5. Enforce.
    if decision.action == "block":
        print(
            f"[AegisAI] BLOCK -> {describe_decision(decision)} (audit_id={record.id})"
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "blocked_by_aegisai",
                "policy": decision.policy_name,
                "reason": decision.reason,
                "decision": decision.action,
                "audit_id": record.id,
            },
        )

    if decision.action == "escalate":
        print(
            f"[AegisAI] ESCALATE -> {describe_decision(decision)} "
            f"(audit_id={record.id})"
        )
        raise HTTPException(
            status_code=202,
            detail={
                "error": "escalated_for_review",
                "policy": decision.policy_name,
                "reason": decision.reason,
                "audit_id": record.id,
            },
        )

    if decision.action == "redact":
        redacted = redact_text(last_user_text, findings)
        for i in range(len(request.messages) - 1, -1, -1):
            if request.messages[i].role == "user":
                request.messages[i].content = redacted
                break
        print(
            f"[AegisAI] REDACT -> {describe_decision(decision)} (audit_id={record.id})"
        )

    if decision.action == "allow":
        print(f"[AegisAI] ALLOW (audit_id={record.id})")

    # 6. Forward.
    model_response = await forward_to_model(request)

    # 7. Headers.
    response.headers["x-aegis-decision"] = decision.action
    response.headers["x-aegis-policy"] = decision.policy_name or ""
    response.headers["x-aegis-findings"] = str(len(findings))
    response.headers["x-aegis-audit-id"] = str(record.id)

    return model_response
