"""Gateway: forwards chat requests to the model provider.

Phase 1 starts in mock mode so we can build the pipeline without burning
API credits. Phase 1.5 (below) adds the real OpenAI call.
"""

from __future__ import annotations

import uuid

from app.models import ChatChoice, ChatRequest, ChatResponse, Message

# Toggle via .env later; for now it's a constant.
MOCK_MODE = True


def _mock_response(request: ChatRequest) -> ChatResponse:
    """Return a canned response that echoes the last user message."""
    last_user = next(
        (m.content for m in reversed(request.messages) if m.role == "user"),
        "",
    )

    return ChatResponse(
        id=f"chatcmpl-mock-{uuid.uuid4().hex[:8]}",
        model=request.model,
        choices=[
            ChatChoice(
                index=0,
                message=Message(
                    role="assistant",
                    content=f"[mock] You said: {last_user}",
                ),
                finish_reason="stop",
            )
        ],
    )


async def forward_to_model(request: ChatRequest) -> ChatResponse:
    """Forward a chat request to the model provider.

    Phase 1: always returns a mock response.
    Phase 1.5: will call OpenAI when MOCK_MODE is False.
    """
    if MOCK_MODE:
        return _mock_response(request)

    raise NotImplementedError("Real model call lands in Phase 1.5")
