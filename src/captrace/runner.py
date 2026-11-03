"""Scenario format and isolated, deterministic replay."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import Decision, Engine
from .audit import seal


@dataclass
class CaseResult:
    name: str
    description: str
    policy: str
    passed: bool
    expected: dict[str, bool]
    observed: dict[str, bool]
    timeline: list[dict[str, Any]]
    effects: list[dict[str, Any]]

    def as_dict(self, *, include_audit: bool = False) -> dict[str, Any]:
        result = {"name": self.name, "description": self.description,
                "policy": self.policy, "passed": self.passed,
                "expected": self.expected, "observed": self.observed,
                "timeline": self.timeline, "effects": self.effects}
        if include_audit:
            result["audit"] = seal(self.timeline)
        return result


def load_scenario(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as file:
        case = json.load(file)
    for key in ("name", "description", "grants", "steps", "expected"):
        if key not in case:
            raise ValueError(f"scenario missing {key}: {path}")
    if not isinstance(case["expected"], dict):
        raise ValueError("expected must map call IDs to booleans")
    if not all(isinstance(v, bool) for v in case["expected"].values()):
        raise ValueError("expected values must be booleans")
    return case


def run_scenario(case: dict[str, Any], policy: str = "runtime") -> CaseResult:
    if policy not in {"runtime", "cached"}:
        raise ValueError("policy must be runtime or cached")
    engine = Engine()
    for grant in case["grants"]:
        if grant.get("parent_id"):
            engine.delegate(parent_id=grant["parent_id"], cap_id=grant["id"],
                            principal=grant["principal"], actions=grant["actions"],
                            expires_at=grant["expires_at"], now=0)
        else:
            engine.grant(cap_id=grant["id"], principal=grant["principal"],
                         resource=grant["resource"], actions=grant["actions"],
                         expires_at=grant["expires_at"], now=0)
    plans: dict[str, tuple[dict[str, Any], Decision]] = {}
    observed: dict[str, bool] = {}
    previous_time = 0
    for step in case["steps"]:
        at = step["at"]
        if not isinstance(at, int) or isinstance(at, bool) or at < previous_time:
            raise ValueError("scenario steps must have nondecreasing integer times")
        previous_time = at
        operation = step["op"]
        if operation == "plan":
            call_id = step["call_id"]
            if call_id in plans:
                raise ValueError(f"duplicate plan id: {call_id}")
            fields = {k: step[k] for k in ("cap_id", "principal", "action", "resource")}
            snapshot = engine.check(**fields, now=at)
            plans[call_id] = (fields, snapshot)
            engine._record(at, "plan", call_id=call_id,
                           cached_allowed=snapshot.allowed,
                           cached_reason=snapshot.reason)
        elif operation == "revoke":
            engine.revoke(step["cap_id"], now=at)
        elif operation == "dispatch":
            call_id = step["call_id"]
            if call_id not in plans or call_id in observed:
                raise ValueError(f"dispatch requires one unused plan: {call_id}")
            fields, snapshot = plans[call_id]
            result = engine.dispatch(call_id=call_id, **fields, now=at,
                                     policy=policy, cached=snapshot)
            observed[call_id] = result.allowed
        else:
            raise ValueError(f"unknown step: {operation}")
    expected = case["expected"]
    return CaseResult(case["name"], case["description"], policy,
                      observed == expected, expected, observed,
                      engine.timeline, engine.effects)


def fixture_paths() -> list[Path]:
    # Installed as package data, so CLI works after pip install.
    return sorted((Path(__file__).parent / "scenarios").glob("*.json"))


def run_suite(policy: str = "runtime") -> list[CaseResult]:
    return [run_scenario(load_scenario(path), policy) for path in fixture_paths()]
