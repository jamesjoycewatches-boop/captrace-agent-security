"""Deterministic SHA-256 hash chain for simulated event traces.

Not a digital signature and not a substitute for trusted, append-only storage.
An independently saved head hash is required to detect deletion of a suffix.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

GENESIS = "0" * 64


def _digest(index: int, previous_hash: str, event: Mapping[str, Any]) -> str:
    payload = json.dumps(
        {"index": index, "previous_hash": previous_hash, "event": event},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def seal(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Return a deterministic, hash-linked copy of events and its final digest."""
    previous = GENESIS
    entries: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        # Canonical JSON round trip ensures seal is not affected by subsequent mutation.
        snapshot = json.loads(json.dumps(event, sort_keys=True, allow_nan=False))
        digest = _digest(index, previous, snapshot)
        entries.append({"index": index, "previous_hash": previous,
                        "event": snapshot, "hash": digest})
        previous = digest
    return {"algorithm": "sha256-json-v1", "head": previous, "entries": entries}


def verify(ledger: Mapping[str, Any], *, trusted_head: str) -> bool:
    """Check integrity and completeness against an independently trusted head.

    Returns False rather than raising on malformed or tampered ledger data.
    Neither the head inside the ledger nor the ledger itself is trusted.
    """
    try:
        if ledger["algorithm"] != "sha256-json-v1":
            return False
        entries = ledger["entries"]
        if not isinstance(entries, list):
            return False
        previous = GENESIS
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or set(entry) != {
                    "index", "previous_hash", "event", "hash"}:
                return False
            if type(entry["index"]) is not int or entry["index"] != index:
                return False
            if not isinstance(entry["event"], dict):
                return False
            expected = _digest(index, previous, entry["event"])
            if entry["previous_hash"] != previous or entry["hash"] != expected:
                return False
            previous = expected
        return ledger["head"] == previous and previous == trusted_head
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
