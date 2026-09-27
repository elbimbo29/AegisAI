"""Plugin registry.

Each plugin exposes a `scan(text: str) -> list[Finding]` function.
The registry runs all of them and returns a flat list.

Adding a new plugin is two lines:
  1. write app/plugins/myplugin.py with a scan() function
  2. add it to the PLUGINS list below
"""

from __future__ import annotations

from app.models import Finding
from app.plugins import injection, pii

PLUGINS = [
    pii,
    injection,
]


def run_all(text: str) -> list[Finding]:
    """Run every registered plugin and return all findings."""
    findings: list[Finding] = []
    for plugin in PLUGINS:
        findings.extend(plugin.scan(text))
    return findings
