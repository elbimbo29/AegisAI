"""Tests for the tamper-evident audit chain.

Covers:
  - chain integrity after multiple writes
  - verify_chain detects row edits
  - verify_chain detects row deletion
  - recent_records ordering
"""

import sqlite3
from pathlib import Path

from app import audit
from app.models import Decision


def _decision(action="allow", policy=None, findings=0):
    return Decision(
        action=action,
        policy_name=policy,
        reason="test",
        findings=[] if findings == 0 else [object()] * findings,  # type: ignore
    )


def test_empty_chain_is_valid(tmp_path: Path):
    db = tmp_path / "audit.db"
    valid, broken_at = audit.verify_chain(db)
    assert valid is True
    assert broken_at is None


def test_single_record_chain(tmp_path: Path):
    db = tmp_path / "audit.db"
    record = audit.write_record(db, "hello", _decision())
    assert record.id == 1
    assert record.prev_hash == audit.GENESIS_HASH

    valid, broken_at = audit.verify_chain(db)
    assert valid is True


def test_multiple_records_chain(tmp_path: Path):
    db = tmp_path / "audit.db"
    for i in range(5):
        audit.write_record(db, f"prompt-{i}", _decision())

    valid, broken_at = audit.verify_chain(db)
    assert valid is True
    assert broken_at is None

    records = audit.recent_records(db, limit=10)
    assert len(records) == 5
    # Newest first
    assert records[0]["id"] == 5
    assert records[-1]["id"] == 1


def test_verify_detects_edited_record(tmp_path: Path):
    db = tmp_path / "audit.db"
    for i in range(3):
        audit.write_record(db, f"p-{i}", _decision())

    # Tamper: change the decision of row 2 from 'allow' to 'block'.
    conn = sqlite3.connect(db)
    conn.execute("UPDATE audit SET decision = 'block' WHERE id = 2")
    conn.commit()
    conn.close()

    valid, broken_at = audit.verify_chain(db)
    assert valid is False
    assert broken_at == 2


def test_verify_detects_deleted_record(tmp_path: Path):
    db = tmp_path / "audit.db"
    for i in range(3):
        audit.write_record(db, f"p-{i}", _decision())

    # Tamper: delete row 2.
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM audit WHERE id = 2")
    conn.commit()
    conn.close()

    valid, broken_at = audit.verify_chain(db)
    assert valid is False
    # Deletion of row 2 makes row 3's prev_hash reference a missing hash.
    assert broken_at == 3
