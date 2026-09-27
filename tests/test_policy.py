"""Tests for the Policy Kernel.

Covers:
  - PII entity matching -> block / redact decisions
  - Injection severity matching -> block / escalate decisions
  - Deny-trumps-allow behavior
  - Default action when no rule matches
"""

from app.models import Finding
from app.policy_kernel import PolicyFile, PolicyKernel

# --- Fixtures ---


def make_kernel() -> PolicyKernel:
    """Build a kernel from an in-memory policy file (no YAML I/O)."""
    return PolicyKernel(
        PolicyFile(
            version=1,
            default_action="allow",
            policies=[
                {
                    "name": "block_ssn",
                    "description": "Block SSNs",
                    "match": {"plugin": "pii", "entities": ["SSN"]},
                    "action": "block",
                },
                {
                    "name": "redact_email",
                    "description": "Redact emails",
                    "match": {"plugin": "pii", "entities": ["EMAIL"]},
                    "action": "redact",
                },
                {
                    "name": "block_jailbreak_high",
                    "description": "Block high-severity injections",
                    "match": {"plugin": "injection", "severity": "high"},
                    "action": "block",
                },
                {
                    "name": "escalate_jailbreak_medium",
                    "description": "Escalate medium injections",
                    "match": {"plugin": "injection", "severity": "medium"},
                    "action": "escalate",
                },
            ],
        )
    )


# --- Tests ---


def test_ssn_triggers_block():
    kernel = make_kernel()
    findings = [Finding(plugin="pii", entity="SSN")]
    decision = kernel.evaluate(findings)
    assert decision.action == "block"
    assert decision.policy_name == "block_ssn"


def test_email_triggers_redact():
    kernel = make_kernel()
    findings = [Finding(plugin="pii", entity="EMAIL")]
    decision = kernel.evaluate(findings)
    assert decision.action == "redact"
    assert decision.policy_name == "redact_email"


def test_high_injection_triggers_block():
    kernel = make_kernel()
    findings = [Finding(plugin="injection", severity="high")]
    decision = kernel.evaluate(findings)
    assert decision.action == "block"
    assert decision.policy_name == "block_jailbreak_high"


def test_medium_injection_triggers_escalate():
    kernel = make_kernel()
    findings = [Finding(plugin="injection", severity="medium")]
    decision = kernel.evaluate(findings)
    assert decision.action == "escalate"


def test_deny_trumps_allow():
    """A BLOCK must win even if a REDACT rule also matches."""
    kernel = make_kernel()
    findings = [
        Finding(plugin="pii", entity="EMAIL"),  # would trigger redact
        Finding(plugin="pii", entity="SSN"),  # must trigger block
    ]
    decision = kernel.evaluate(findings)
    assert decision.action == "block"
    assert decision.policy_name == "block_ssn"


def test_default_action_when_no_match():
    kernel = make_kernel()
    findings = [Finding(plugin="pii", entity="PHONE")]
    decision = kernel.evaluate(findings)
    assert decision.action == "allow"
    assert decision.policy_name is None


def test_loads_from_real_yaml_file():
    """Sanity check that our shipped policies.yaml parses."""
    kernel = PolicyKernel.from_yaml("policies/policies.yaml")
    assert kernel.policy_file.version == 1
    assert len(kernel.policy_file.policies) >= 5
