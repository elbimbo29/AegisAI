"""Prompt injection detection plugin.

Phase 3 uses a keyword + heuristic approach. Fast, zero-dependency,
explainable. Phase 3.5 can swap in an ML classifier without touching
anything else, because the interface is the same: scan(text) -> Findings.
"""

from __future__ import annotations

import re

from app.models import Finding

# --- High severity: classic jailbreak / instruction-override patterns ---

HIGH_SEVERITY_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"ignore (all )?prior instructions",
    r"disregard (all )?(previous|prior|above) instructions",
    r"you are now (dan|jailbroken|unrestricted)",
    r"act as (dan|an? unrestricted|a jailbroken)",
    r"pretend you (are|have) no (rules|restrictions|guidelines)",
    r"forget (everything|all) (you|that)",
    r"override (your )?(safety|security|system)",
    r"reveal your (system )?prompt",
    r"print your (system )?instructions",
]

# --- Medium severity: softer manipulation attempts ---

MEDIUM_SEVERITY_PATTERNS = [
    r"hypothetically",
    r"in a fictional (world|scenario)",
    r"for (educational|research) purposes only",
    r"as a thought experiment",
    r"just between us",
    r"this is a test",
]

_HIGH_RES = [re.compile(p, re.IGNORECASE) for p in HIGH_SEVERITY_PATTERNS]
_MEDIUM_RES = [re.compile(p, re.IGNORECASE) for p in MEDIUM_SEVERITY_PATTERNS]


def _scan_severity(
    text: str,
    patterns: list[re.Pattern[str]],
    severity: str,
) -> list[Finding]:
    """Return findings for a given severity tier."""
    findings: list[Finding] = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    plugin="injection",
                    severity=severity,
                    span=(match.start(), match.end()),
                    text=match.group(0),
                )
            )
    return findings


def scan(text: str) -> list[Finding]:
    """Scan text for prompt-injection signals."""
    findings: list[Finding] = []
    findings.extend(_scan_severity(text, _HIGH_RES, "high"))
    findings.extend(_scan_severity(text, _MEDIUM_RES, "medium"))
    return findings
