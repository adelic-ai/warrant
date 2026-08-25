"""Core data model: identities, resources, delegations, obligations, audit records.

No policy-engine dependency lives here — this module is the deterministic ground truth
that Phase 2's PDP (Cedar or the hand-rolled fallback) is evaluated against.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def _uuid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IdentityKind(str, enum.Enum):
    HUMAN = "human"
    AGENT = "agent"
    WORKLOAD = "workload"


class Decision(str, enum.Enum):
    PERMIT = "PERMIT"
    FORBID = "FORBID"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Identity(SQLModel, table=True):
    # e.g. "user:rick", "agent:A17" — human-readable, stable, used as the join key everywhere.
    id: str = Field(primary_key=True)
    kind: IdentityKind
    display_name: str
    spiffe_id: Optional[str] = None  # populated once Phase 4 issues a workload identity


class Resource(SQLModel, table=True):
    id: str = Field(primary_key=True)  # e.g. "doc:123"
    kind: str
    # Scope containment key — a delegation's `scope` is checked against this, not against the
    # resource id directly, so a delegation can cover a whole case without enumerating documents.
    belongs_to: str  # e.g. "case:42"


class Delegation(SQLModel, table=True):
    id: str = Field(default_factory=lambda: _uuid("del"), primary_key=True)
    principal_id: str  # the human who delegated
    delegate_id: str  # the agent acting for them
    scope: str  # a `belongs_to` value, e.g. "case:42"
    permitted_actions: str  # comma-separated; SQLite has no native array column
    requires_approval_actions: str = ""
    forbidden_actions: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime

    # Provenance for the defeater-surfacing seam (pdp.py) — the Delegation is the only thing in
    # this system capable of overriding a default-deny, so it's the thing that needs an owner,
    # a reason, and a review date attached, not a Cedar policy annotation. `owner` is
    # `principal_id` (who granted it) — no separate field needed.
    granted_reason: str = "no reason recorded"
    reviewed_at: Optional[datetime] = None

    def _split(self, field: str) -> list[str]:
        return [a for a in field.split(",") if a]

    @property
    def permitted(self) -> list[str]:
        return self._split(self.permitted_actions)

    @property
    def requires_approval(self) -> list[str]:
        return self._split(self.requires_approval_actions)

    @property
    def forbidden(self) -> list[str]:
        return self._split(self.forbidden_actions)

    def is_expired(self, *, now: Optional[datetime] = None) -> bool:
        now = now or utcnow()
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now >= expires


class Obligation(SQLModel, table=True):
    """A REQUIRE_APPROVAL decision creates one of these. It is discharged only through the
    /approve endpoint by a distinct approver identity — never by the agent itself, and never by
    just flipping a flag the agent controls."""

    id: str = Field(default_factory=lambda: _uuid("obl"), primary_key=True)
    subject_id: str
    principal_id: str
    action: str
    resource_id: str
    delegation_id: str
    created_at: datetime = Field(default_factory=utcnow)
    discharged: bool = False
    discharged_by: Optional[str] = None
    discharged_at: Optional[datetime] = None


class UidAllocation(SQLModel, table=True):
    """Which OS uid a token's own egress-verifier session was allocated, and for how long.
    `token_jti` is the minted token's own `jti` claim (tokens.exchange) -- the join key back to
    "which delegation/session does this uid's observed egress belong to." `released_at=None`
    means still held; egress_verifier.UidAllocation.covers() (the pure-logic module) is what
    actually enforces the time window when reconciling, this table just persists the fact."""

    id: str = Field(default_factory=lambda: _uuid("uidalloc"), primary_key=True)
    token_jti: str = Field(index=True)
    uid: int
    allocated_at: datetime = Field(default_factory=utcnow)
    released_at: Optional[datetime] = None


class EgressObservation(SQLModel, table=True):
    """One CONNECT the egress proxy actually observed -- persisted ground truth, not warrant's
    own claim about what should have happened. `uid` is None when the proxy couldn't resolve the
    connecting process's uid (surfaced as unresolved, never guessed at as any specific session)."""

    id: str = Field(default_factory=lambda: _uuid("egress"), primary_key=True)
    uid: Optional[int]
    host: str
    port: int
    timestamp: datetime = Field(default_factory=utcnow)


class AuditRecord(SQLModel, table=True):
    """Every /authorize decision, in full — never a bare boolean. This table is the append-only
    ground truth /audit/reconcile checks obligation-discharge claims against (Phase 7)."""

    id: str = Field(default_factory=lambda: _uuid("aud"), primary_key=True)
    timestamp: datetime = Field(default_factory=utcnow)
    subject_id: str
    principal_id: str
    action: str
    resource_id: str
    decision: Decision
    policy: str
    facts: str  # JSON-encoded list[str]
    reason: str
    obligation_id: Optional[str] = None
