"""Exhaustive bounded schedule explorer for permission revocation races.

Every valid ordering of N plan/dispatch pairs and one revoke is explored.
Scheduling is virtual, deterministic and offline; no threads or live tools run.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

from .runner import run_scenario


@dataclass(frozen=True)
class ExploreReport:
    policy: str
    calls: int
    schedules: int
    violations: int
    witnesses: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {"policy": self.policy, "calls": self.calls,
                "schedules": self.schedules, "violations": self.violations,
                "witnesses": list(self.witnesses)}


def schedules(calls: int) -> Iterator[tuple[str, ...]]:
    """Generate each legal interleaving once, with plan<i before dispatch<i."""
    if type(calls) is not int or not 1 <= calls <= 4:
        raise ValueError("calls must be an integer between 1 and 4")

    def visit(order: tuple[str, ...], planned: frozenset[int],
              dispatched: frozenset[int], revoked: bool) -> Iterator[tuple[str, ...]]:
        if len(order) == 2 * calls + 1:
            yield order
            return
        for i in range(calls):
            if i not in planned:
                yield from visit(order + (f"plan:{i}",), planned | {i}, dispatched, revoked)
            elif i not in dispatched:
                yield from visit(order + (f"dispatch:{i}",), planned,
                                 dispatched | {i}, revoked)
        if not revoked:
            yield from visit(order + ("revoke",), planned, dispatched, True)

    yield from visit((), frozenset(), frozenset(), False)


def build_case(schedule: tuple[str, ...]) -> dict[str, Any]:
    """Construct oracle expectations from dispatch-time authorization state."""
    steps: list[dict[str, Any]] = []
    expected: dict[str, bool] = {}
    revoked = False
    for at, operation in enumerate(schedule, start=1):
        if operation == "revoke":
            steps.append({"at": at, "op": "revoke", "cap_id": "root"})
            revoked = True
            continue
        kind, index = operation.split(":")
        call_id = f"call{index}"
        if kind == "plan":
            steps.append({"at": at, "op": "plan", "call_id": call_id,
                          "cap_id": "root", "principal": "agent",
                          "action": "read", "resource": "doc:42"})
        else:
            steps.append({"at": at, "op": "dispatch", "call_id": call_id})
            expected[call_id] = not revoked
    return {"name": "interleaving", "description": "bounded revoke race",
            "grants": [{"id": "root", "principal": "agent",
                        "resource": "doc:42", "actions": ["read"],
                        "expires_at": len(schedule) + 10}],
            "steps": steps, "expected": expected}


def explore(*, policy: str = "runtime", calls: int = 2,
            max_witnesses: int = 3) -> ExploreReport:
    if policy not in {"runtime", "cached"}:
        raise ValueError("policy must be runtime or cached")
    if type(max_witnesses) is not int or not 0 <= max_witnesses <= 20:
        raise ValueError("max_witnesses must be between 0 and 20")
    count = 0
    violations = 0
    witnesses: list[dict[str, Any]] = []
    for schedule in schedules(calls):
        count += 1
        case = build_case(schedule)
        result = run_scenario(case, policy=policy)
        if not result.passed:
            violations += 1
            if len(witnesses) < max_witnesses:
                witnesses.append({"order": list(schedule), "expected": result.expected,
                                  "observed": result.observed,
                                  "effects": result.effects,
                                  "replay": case})
    return ExploreReport(policy, calls, count, violations, tuple(witnesses))
