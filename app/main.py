"""AegisAI — FastAPI entrypoint.

Real-Time AI Ethics · Governance · Audit
"""

from fastapi import FastAPI, HTTPException

from app.enforcement import describe_decision, redact_text
from app.gateway import forward_to_model
from app.models import ChatRequest, ChatResponse, Finding
from app.plugins import run_all as run_all_plugins
from app.policy_kernel import PolicyKernel

app = FastAPI(
    title="AegisAI",
    description="Real-time AI governance layer with tamper-evident audit.",
    version="0.4.0",
)

kernel = PolicyKernel.from_yaml("policies/policies.yaml")


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "service": "aegisai"}


@app.get("/policies")
async def list_policies() -> list[dict]:
    """Inspect the loaded policy set."""
    return [rule.model_dump() for rule in kernel.policy_file.policies]


@app.post("/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(
    request: ChatRequest,
    response: Response,
) -> ChatResponse:
    """OpenAI-compatible chat completions endpoint.

    Phase 4 flow:
      1. Scan input for findings
      2. Evaluate findings -> decision
      3. Enforce decision (allow / redact / block / escalate)
      4. Forward to model (only if allow or redact)
      5. Attach decision metadata to response headers
    """
    # 1. Scan the last user message.
    last_user_text = next(
        (m.content for m in reversed(request.messages) if m.role == "user"),
        "",
    )
    findings: list[Finding] = run_all_plugins(last_user_text)

    # 2. Decide.
    decision = kernel.evaluate(findings)

    # 3. Enforce.
    if decision.action == "block":
        print(
            f"[AegisAI] BLOCK -> {describe_decision(decision)} "
            f"(findings={len(findings)})"
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "blocked_by_aegisai",
                "policy": decision.policy_name,
                "reason": decision.reason,
                "decision": decision.action,
            },
        )

    if decision.action == "escalate":
        print(f"[AegisAI] ESCALATE -> {describe_decision(decision)}")
        raise HTTPException(
            status_code=202,
            detail={
                "error": "escalated_for_review",
                "policy": decision.policy_name,
                "reason": decision.reason,
            },
        )

    if decision.action == "redact":
        redacted = redact_text(last_user_text, findings)
        for i in range(len(request.messages) - 1, -1, -1):
            if request.messages[i].role == "user":
                request.messages[i].content = redacted
                break
        print(
            f"[AegisAI] REDACT -> {describe_decision(decision)} "
            f"(findings={len(findings)})"
        )

    if decision.action == "allow":
        print(f"[AegisAI] ALLOW (findings={len(findings)})")

    # 4. Forward.
    model_response = await forward_to_model(request)

    # 5. Attach decision metadata to response headers.
    response.headers["x-aegis-decision"] = decision.action
    response.headers["x-aegis-policy"] = decision.policy_name or ""
    response.headers["x-aegis-findings"] = str(len(findings))

    return model_response
