"""AegisAI — FastAPI entrypoint.

Real-Time AI Ethics · Governance · Audit
"""

from fastapi import FastAPI

from app.gateway import forward_to_model
from app.models import ChatRequest, ChatResponse
from app.plugins import run_all as run_all_plugins
from app.policy_kernel import PolicyKernel

app = FastAPI(
    title="AegisAI",
    description="Real-time AI governance layer with tamper-evident audit.",
    version="0.2.0",
)

# Load the policy kernel once at startup.
# Phase 6 will add hot-reload; for now, restart to pick up changes.
kernel = PolicyKernel.from_yaml("policies/policies.yaml")


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "service": "aegisai"}


@app.get("/policies")
async def list_policies() -> list[dict]:
    """Inspect the loaded policy set. Useful for demos and debugging."""
    return [rule.model_dump() for rule in kernel.policy_file.policies]


@app.post("/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(request: ChatRequest) -> ChatResponse:
    """OpenAI-compatible chat completions endpoint.

    Phase 3: scans the last user message and feeds findings to the kernel.
    Phase 4: will branch on decision.action to enforce.
    """
    # Scan only the last user message for now.
    # Phase 4 will scan all messages + the model's response.
    last_user_text = next(
        (m.content for m in reversed(request.messages) if m.role == "user"),
        "",
    )

    findings = run_all_plugins(last_user_text)
    decision = kernel.evaluate(findings)

    # Phase 4 will branch on decision.action here.
    # For now, forward regardless — but log what we saw.
    print(
        f"[AegisAI] findings={len(findings)} "
        f"action={decision.action} policy={decision.policy_name}"
    )

    return await forward_to_model(request)
