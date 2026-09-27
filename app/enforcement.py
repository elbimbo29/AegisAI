"""Enforcement actions.

Pure functions that transform a decision into an outcome:
  - allow    -> request passes unchanged
  - redact   -> matched spans are masked in-place
  - block    -> request is rejected (caller raises HTTPException)
  - escalate -> request is queued for human review

These functions have NO FastAPI dependencies on purpose. They're testable
in isolation and reusable outside HTTP contexts (batch jobs, CLI, etc.).
"""

from __future__ import annotations

from app.models import Decision, Finding

REDACTION_TOKEN = "<{entity}_REDACTED>"


def redact_text(text: str, findings: list[Finding]) -> str:
    """Replace every finding's span with a typed placeholder.

    Processes findings right-to-left so earlier spans stay valid when
    later ones are replaced.
    """
    # Only redact findings that have a span (PII-style findings)
    redactable = [f for f in findings if f.span is not None]
    # Sort descending by start index to avoid shifting positions
    redactable.sort(key=lambda f: f.span[0], reverse=True)

    for finding in redactable:
        start, end = finding.span
        token = REDACTION_TOKEN.format(entity=finding.entity or "VALUE")
        text = text[:start] + token + text[end:]

    return text


def describe_decision(decision: Decision) -> str:
    """Return a human-readable one-liner for logs and headers."""
    if decision.policy_name:
        return f"{decision.action} ({decision.policy_name})"
    return decision.action
