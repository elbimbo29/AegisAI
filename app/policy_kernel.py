"""Policy Kernel — the brain of AegisAI.

Loads `policies.yaml`, evaluates scan findings against rules, and returns
a Decision. Pure logic: no I/O, no enforcement, no side effects.

Evaluation rules:
  1. deny-trumps-allow : any BLOCK match short-circuits immediately.
  2. first-match-wins  : within the same severity tier, first rule wins.
  3. default_action    : used when no rule matches.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from app.models import ActionType, Decision, Finding

# --- Internal schema for the YAML file ---


class PolicyMatch(BaseModel):
    """What a policy rule looks for in scan findings."""

    plugin: str
    entities: list[str] | None = None
    severity: str | None = None


class PolicyRule(BaseModel):
    """A single rule from policies.yaml."""

    name: str
    description: str | None = None
    match: PolicyMatch
    action: ActionType


class PolicyFile(BaseModel):
    """The whole policies.yaml file."""

    version: int = 1
    default_action: ActionType = "allow"
    policies: list[PolicyRule] = Field(default_factory=list)


# --- Kernel ---


class PolicyKernel:
    """Evaluates findings against loaded policy rules."""

    def __init__(self, policy_file: PolicyFile):
        self.policy_file = policy_file

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyKernel:
        """Load a PolicyKernel from a YAML file."""
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls(PolicyFile(**raw))

    def _rule_matches(self, rule: PolicyRule, finding: Finding) -> bool:
        """Check whether a single rule matches a single finding."""
        if rule.match.plugin != finding.plugin:
            return False

        # PII rules: match by entity name
        if rule.match.entities is not None:
            if finding.entity not in rule.match.entities:
                return False

        # Injection rules: match by severity
        if rule.match.severity is not None:
            if finding.severity != rule.match.severity:
                return False

        return True

    def evaluate(self, findings: list[Finding]) -> Decision:
        """Evaluate findings and return a Decision.

        Priority: BLOCK > ESCALATE > REDACT > ALLOW
        Implemented as: first-pass for BLOCK (deny-trumps-allow),
        then first-match-wins for the rest.
        """
        # Pass 1: deny-trumps-allow — any BLOCK wins immediately
        for rule in self.policy_file.policies:
            if rule.action != "block":
                continue
            for finding in findings:
                if self._rule_matches(rule, finding):
                    return Decision(
                        action="block",
                        policy_name=rule.name,
                        reason=rule.description,
                        findings=findings,
                    )

        # Pass 2: first-match-wins for escalate / redact
        for rule in self.policy_file.policies:
            if rule.action not in ("escalate", "redact"):
                continue
            for finding in findings:
                if self._rule_matches(rule, finding):
                    return Decision(
                        action=rule.action,
                        policy_name=rule.name,
                        reason=rule.description,
                        findings=findings,
                    )

        # No match: default
        return Decision(
            action=self.policy_file.default_action,
            policy_name=None,
            reason="no policy matched",
            findings=findings,
        )
