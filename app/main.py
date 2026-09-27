"""AegisAI — FastAPI entrypoint.

Real-Time AI Ethics · Governance · Audit
"""

from fastapi import FastAPI

from app.gateway import forward_to_model
from app.models import ChatRequest, ChatResponse, Decision, Finding
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

    Phase 2: evaluates an empty findings list (always 'allow' for now).
    Phase 3: real scanners produce findings.
    Phase 4: enforcement acts on the decision.
    """
    # Placeholder: Phase 3 will replace this with real plugin scans.
    findings: list[Finding] = []
    decision: Decision = kernel.evaluate(findings)

    # Phase 4 will branch on decision.action here.
    # For now, just forward as before.
    return await forward_to_model(request)
