"""Reconciles warrant's own authorization decisions against an independent ground-truth
plane -- a uid-tagged egress proxy log -- to catch a gateway bypass: an agent process
reaching a downstream host directly instead of through warrant's own PEP.

Structural correlation (uid -> token -> authorized hosts), not timing-window inference: the
proxy records which OS uid made each CONNECT; warrant records which uid it allocated to which
token, for what time window, and which hosts that token is authorized to reach. Reconciling is
a join, not a guess about whether two timestamps are "close enough."

Design and its constraints (the Black Hat 2026 "Trusted Enough to Run" trust-handoff lesson,
warden's uid-range precedent) are in considerations/warden-agentwatch-enhance-warrant.md. This
module is the pure-logic half only. It deliberately knows nothing about the OS-level
enforcement (ephemeral per-session uids, the static nftables rule scoping their range, the
proxy's own peer-credential capture) -- that needs a real Linux host to build and validate, and
isn't part of this module. Feed it real ProxyLogEntry/UidAllocation data from wherever that
capture actually runs, or synthetic data in tests.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class UidAllocation:
    """Which uid warrant allocated to which token, for however long. `released_at=None` means
    still held (the session's work window hasn't ended)."""

    uid: int
    token_id: str
    allocated_at: datetime
    released_at: datetime | None = None

    def covers(self, at: datetime) -> bool:
        if at < self.allocated_at:
            return False
        return self.released_at is None or at <= self.released_at


@dataclass(frozen=True)
class ProxyLogEntry:
    """One CONNECT observed by the egress proxy -- the ground-truth plane. `uid` is the
    connecting process's uid, captured via peer credentials at the proxy, not self-reported."""

    uid: int
    host: str
    timestamp: datetime


class Verdict(str, enum.Enum):
    AUTHORIZED = "AUTHORIZED"  # egress matched a token's own authorized hosts
    CONFIRMED = "CONFIRMED"  # egress with no authorizing token behind it -- a real discrepancy


@dataclass(frozen=True)
class ReconciledEntry:
    entry: ProxyLogEntry
    verdict: Verdict
    token_id: str | None  # which token's allocation covered this uid at this time, if any
    reason: str


def reconcile(
    proxy_log: list[ProxyLogEntry],
    uid_allocations: list[UidAllocation],
    authorized_hosts: dict[str, set[str]],  # token_id -> hosts that token may reach
) -> list[ReconciledEntry]:
    results: list[ReconciledEntry] = []
    for entry in proxy_log:
        covering = [a for a in uid_allocations if a.uid == entry.uid and a.covers(entry.timestamp)]

        if not covering:
            results.append(
                ReconciledEntry(
                    entry=entry,
                    verdict=Verdict.CONFIRMED,
                    token_id=None,
                    reason=f"uid {entry.uid} has no token allocation covering {entry.timestamp.isoformat()}",
                )
            )
            continue

        if len(covering) > 1:
            # Two allocations covering the same uid at the same instant is a provisioning bug
            # (uids are supposed to be held exclusively for one token's work window) -- surfaced
            # rather than silently picking one and hiding the ambiguity.
            results.append(
                ReconciledEntry(
                    entry=entry,
                    verdict=Verdict.CONFIRMED,
                    token_id=None,
                    reason=(
                        f"uid {entry.uid} has {len(covering)} overlapping allocations at "
                        f"{entry.timestamp.isoformat()} -- ambiguous, not evaluated as authorized"
                    ),
                )
            )
            continue

        allocation = covering[0]
        hosts = authorized_hosts.get(allocation.token_id, set())
        if entry.host in hosts:
            results.append(
                ReconciledEntry(
                    entry=entry,
                    verdict=Verdict.AUTHORIZED,
                    token_id=allocation.token_id,
                    reason=f"token {allocation.token_id} is authorized to reach {entry.host}",
                )
            )
        else:
            results.append(
                ReconciledEntry(
                    entry=entry,
                    verdict=Verdict.CONFIRMED,
                    token_id=allocation.token_id,
                    reason=f"token {allocation.token_id}'s authorized hosts do not include {entry.host}",
                )
            )
    return results
