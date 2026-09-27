"""Tests for enforcement actions.

Covers redaction logic and the describe_decision helper.
The HTTP-level behavior (403, 202, headers) is covered in test_main.py.
"""

from app.enforcement import describe_decision, redact_text
from app.models import Decision, Finding


def test_redact_single_span():
    text = "my email is john@example.com ok"
    findings = [Finding(plugin="pii", entity="EMAIL", span=(12, 28))]
    assert redact_text(text, findings) == "my email is <EMAIL_REDACTED> ok"


def test_redact_multiple_spans_right_to_left():
    text = "a@b.com and c@d.com"
    findings = [
        Finding(plugin="pii", entity="EMAIL", span=(0, 7)),
        Finding(plugin="pii", entity="EMAIL", span=(12, 19)),
    ]
    result = redact_text(text, findings)
    assert result == "<EMAIL_REDACTED> and <EMAIL_REDACTED>"


def test_redact_ignores_findings_without_span():
    text = "no pii here"
    findings = [Finding(plugin="injection", severity="high")]  # no span
    assert redact_text(text, findings) == text


def test_describe_decision_with_policy():
    d = Decision(action="block", policy_name="block_ssn", reason="...")
    assert describe_decision(d) == "block (block_ssn)"


def test_describe_decision_without_policy():
    d = Decision(action="allow")
    assert describe_decision(d) == "allow"
