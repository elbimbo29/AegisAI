"""Tamper-evident audit log.

Every decision writes one row to SQLite. Each row's `chain_hash` is
computed as:

    sha256(prev_hash + canonical_payload)

where `canonical_payload` is a JSON dump of the record's fields (excluding
`chain_hash` itself). The first row uses prev_hash = "0" * 64 (genesis).

Any modification to a row breaks verification of that row and every
subsequent row, which is what makes the log tamper-evident.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.models import AuditRecord, Decision

GENESIS_HASH = "0" * 64


# --- Hashing ---


def _hash_prompt(prompt: str) -> str:
    """sha256 the raw prompt. Used instead of storing the prompt itself."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _canonical_payload(record: dict) -> str:
    """Serialize the record deterministically for hashing.

    Excludes `chain_hash` because it's what we're about to compute.
    Uses sorted keys + no whitespace so the same record always hashes the same.
    """
    payload = {k: v for k, v in record.items() if k != "chain_hash"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _compute_chain_hash(prev_hash: str, record: dict) -> str:
    """Compute this record's chain hash."""
    data = prev_hash + _canonical_payload(record)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# --- Storage ---


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    decision TEXT NOT NULL,
    policy_name TEXT,
    reason TEXT,
    findings_count INTEGER NOT NULL DEFAULT 0
);
"""


def _connect(db_path: str | Path) -> sqlite3.Connection:
    """Open the audit DB and ensure the schema exists."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(_SCHEMA)
    conn.commit()
    return conn


# --- Public API ---


def write_record(
    db_path: str | Path,
    prompt: str,
    decision: Decision,
) -> AuditRecord:
    """Append a new record to the audit chain. Returns the stored record."""
    conn = _connect(db_path)
    try:
        # Get the previous chain hash (or genesis if empty).
        row = conn.execute(
            "SELECT chain_hash FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row[0] if row else GENESIS_HASH

        now = datetime.now(timezone.utc)

        # Build the record (without chain_hash yet).
        record = {
            "ts": now.isoformat(),
            "request_hash": _hash_prompt(prompt),
            "prev_hash": prev_hash,
            "decision": decision.action,
            "policy_name": decision.policy_name,
            "reason": decision.reason,
            "findings_count": len(decision.findings),
        }

        chain_hash = _compute_chain_hash(prev_hash, record)

        cursor = conn.execute(
            """
            INSERT INTO audit
              (ts, request_hash, prev_hash, chain_hash, decision,
               policy_name, reason, findings_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["ts"],
                record["request_hash"],
                record["prev_hash"],
                chain_hash,
                record["decision"],
                record["policy_name"],
                record["reason"],
                record["findings_count"],
            ),
        )
        conn.commit()
        record_id = cursor.lastrowid

        return AuditRecord(id=record_id, chain_hash=chain_hash, **record)
    finally:
        conn.close()


def verify_chain(db_path: str | Path) -> tuple[bool, int | None]:
    """Recompute the chain and confirm nothing has been altered.

    Returns (True, None) if valid, or (False, first_broken_id) if not.
    """
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, ts, request_hash, prev_hash, chain_hash, decision,
                   policy_name, reason, findings_count
            FROM audit
            ORDER BY id ASC
            """
        ).fetchall()
    finally:
        conn.close()

    expected_prev = GENESIS_HASH
    for row in rows:
        (
            row_id,
            ts,
            request_hash,
            prev_hash,
            chain_hash,
            decision,
            policy_name,
            reason,
            findings_count,
        ) = row

        # 1. prev_hash must match the previous record's chain_hash.
        if prev_hash != expected_prev:
            return False, row_id

        # 2. Recompute the chain_hash and compare.
        record = {
            "ts": ts,
            "request_hash": request_hash,
            "prev_hash": prev_hash,
            "decision": decision,
            "policy_name": policy_name,
            "reason": reason,
            "findings_count": findings_count,
        }
        recomputed = _compute_chain_hash(prev_hash, record)
        if recomputed != chain_hash:
            return False, row_id

        expected_prev = chain_hash

    return True, None


def recent_records(db_path: str | Path, limit: int = 20) -> list[dict]:
    """Return the most recent audit records (newest first)."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, ts, request_hash, prev_hash, chain_hash, decision,
                   policy_name, reason, findings_count
            FROM audit
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    columns = [
        "id",
        "ts",
        "request_hash",
        "prev_hash",
        "chain_hash",
        "decision",
        "policy_name",
        "reason",
        "findings_count",
    ]
    return [dict(zip(columns, row)) for row in rows]
