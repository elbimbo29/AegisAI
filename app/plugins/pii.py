"""PII detection plugin.

Regex-based, zero-dependency scanner. Phase 3 keeps it simple on purpose:
no ML, no external services. The point is to prove the pipeline works
end-to-end before adding sophistication.

Detects: EMAIL, SSN, CREDIT_CARD, PHONE
"""

from __future__ import annotations

import re

from app.models import Finding

# --- Patterns ---
# Anchored loosely so partial matches inside larger text still register.
# Each pattern returns a Finding with `entity` set and `span` = (start, end).

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# US SSN: 3-2-4 with dashes. We avoid matching random 9-digit numbers.
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Credit card: 13-19 digits, optionally separated by spaces or dashes.
# We validate with the Luhn algorithm below to cut false positives.
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# US phone: (123) 456-7890, 123-456-7890, or 123.456.7890
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")


def _luhn_valid(number: str) -> bool:
    """Return True if the digit string passes the Luhn checksum."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _scan_pattern(
    text: str,
    pattern: re.Pattern[str],
    entity: str,
    validator=None,
) -> list[Finding]:
    """Run a single regex and emit Findings. Optional validator for FP control."""
    findings: list[Finding] = []
    for match in pattern.finditer(text):
        value = match.group(0)
        if validator is not None and not validator(value):
            continue
        findings.append(
            Finding(
                plugin="pii",
                entity=entity,
                span=(match.start(), match.end()),
                text=value,
            )
        )
    return findings


def scan(text: str) -> list[Finding]:
    """Scan text for PII and return a flat list of findings."""
    findings: list[Finding] = []
    findings.extend(_scan_pattern(text, EMAIL_RE, "EMAIL"))
    findings.extend(_scan_pattern(text, SSN_RE, "SSN"))
    findings.extend(
        _scan_pattern(text, CREDIT_CARD_RE, "CREDIT_CARD", validator=_luhn_valid)
    )
    findings.extend(_scan_pattern(text, PHONE_RE, "PHONE"))
    return findings
