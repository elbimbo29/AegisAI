"""Pydantic models for AegisAI's OpenAI-compatible API surface."""

from typing import Literal

from pydantic import BaseModel, Field


class Message(BaseModel):
    """A single chat message."""

    role: Literal["system", "user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    """Incoming chat completion request (OpenAI-compatible subset)."""

    model: str = "gpt-4o-mini"
    messages: list[Message]
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    stream: bool = False


class ChatChoice(BaseModel):
    """A single completion choice."""

    index: int = 0
    message: Message
    finish_reason: str = "stop"


class ChatResponse(BaseModel):
    """Outgoing chat completion response."""

    id: str
    object: str = "chat.completion"
    model: str
    choices: list[ChatChoice]


# --- Phase 2: Policy decisions ---

ActionType = Literal["allow", "redact", "block", "escalate"]


class Finding(BaseModel):
    """A single issue detected by a plugin (Phase 3 will produce these)."""

    plugin: str  # "pii" or "injection"
    entity: str | None = None  # "EMAIL", "SSN", "CREDIT_CARD"
    severity: str | None = None  # "low", "medium", "high" (injection)
    span: tuple[int, int] | None = None
    text: str | None = None  # the matched substring


class Decision(BaseModel):
    """The kernel's verdict for a given request."""

    action: ActionType
    policy_name: str | None = None
    reason: str | None = None
    findings: list[Finding] = []
