"""Deterministic capability-based authorization simulator.

This is an educational test harness, not a production authorization service.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Capability:
    id: str
    principal: str
    resource: str
    actions: frozenset[str]
    expires_at: int
    parent_id: str | None = None
    revoked: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


@dataclass
class Engine:
    capabilities: dict[str, Capability] = field(default_factory=dict)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    effects: list[dict[str, Any]] = field(default_factory=list)

    def grant(self, *, cap_id: str, principal: str, resource: str,
              actions: list[str], expires_at: int, now: int = 0) -> Capability:
        if cap_id in self.capabilities:
            raise ValueError(f"duplicate capability id: {cap_id}")
        if not cap_id or not principal or not resource or not actions or any(not a for a in actions):
            raise ValueError("capability fields must be nonempty")
        if expires_at <= now:
            raise ValueError("expiration must be in the future")
        cap = Capability(cap_id, principal, resource, frozenset(actions), expires_at)
        self.capabilities[cap_id] = cap
        self._record(now, "grant", cap_id=cap_id, principal=principal)
        return cap

    def delegate(self, *, parent_id: str, cap_id: str, principal: str,
                 actions: list[str], expires_at: int, now: int) -> Capability:
        parent = self.capabilities[parent_id]
        status = self._chain_status(parent_id, now)
        if not status.allowed:
            raise ValueError(f"inactive parent: {status.reason}")
        if not actions or not set(actions).issubset(parent.actions):
            raise ValueError("delegation cannot broaden actions")
        if expires_at > parent.expires_at:
            raise ValueError("delegation cannot outlive parent")
        cap = self.grant(cap_id=cap_id, principal=principal,
                         resource=parent.resource, actions=actions,
                         expires_at=expires_at, now=now)
        cap.parent_id = parent_id
        self._record(now, "delegate", cap_id=cap_id, parent_id=parent_id)
        return cap

    def revoke(self, cap_id: str, now: int) -> None:
        cap = self.capabilities[cap_id]
        cap.revoked = True
        self._record(now, "revoke", cap_id=cap_id)

    def _chain_status(self, cap_id: str, now: int) -> Decision:
        seen: set[str] = set()
        current: str | None = cap_id
        while current is not None:
            if current in seen:
                return Decision(False, "delegation cycle")
            seen.add(current)
            cap = self.capabilities.get(current)
            if cap is None:
                return Decision(False, "missing capability")
            if cap.revoked:
                return Decision(False, "revoked capability")
            if now >= cap.expires_at:
                return Decision(False, "expired capability")
            current = cap.parent_id
        return Decision(True, "active capability")

    def check(self, *, cap_id: str, principal: str, resource: str,
              action: str, now: int) -> Decision:
        chain = self._chain_status(cap_id, now)
        if not chain.allowed:
            return chain
        cap = self.capabilities[cap_id]
        if cap.principal != principal:
            return Decision(False, "wrong principal")
        if cap.resource != resource:
            return Decision(False, "wrong resource")
        if action not in cap.actions:
            return Decision(False, "action not permitted")
        return Decision(True, "authorized")

    def dispatch(self, *, call_id: str, cap_id: str, principal: str,
                 action: str, resource: str, now: int,
                 policy: str, cached: Decision) -> Decision:
        if policy == "runtime":
            decision = self.check(cap_id=cap_id, principal=principal,
                                  resource=resource, action=action, now=now)
        elif policy == "cached":
            decision = cached
        else:
            raise ValueError(f"unsupported policy: {policy}")
        self._record(now, "dispatch", call_id=call_id, cap_id=cap_id,
                     allowed=decision.allowed, reason=decision.reason,
                     policy=policy)
        if decision.allowed:
            self.effects.append({"call_id": call_id, "at": now,
                                 "action": action, "resource": resource})
        return decision

    def _record(self, at: int, kind: str, **details: Any) -> None:
        self.timeline.append({"at": at, "kind": kind, **details})
