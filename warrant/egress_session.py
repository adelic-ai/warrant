"""Wires the three independently-built-and-tested egress-verifier pieces into one live path:
`uid_pool`/`egress_proxy` (OS-level, real Linux primitives), `models.UidAllocation`/
`EgressObservation` (persistence), and `egress_verifier` (the pure-logic reconciler). This module
is the only one that touches all three -- each of the others stays independently testable and
independently true to its own single job.

`authorized_hosts`, here, is deliberately not per-token-derived from anything in the Delegation
model. Warrant's own gateway pattern (credential injection -- warrant/gateway.py) means the agent
should never need to reach any downstream resource directly at all: the gateway fetches it and
injects the credential server-side. So the one and only legitimate egress destination for ANY
token is warrant's own gateway host -- not a per-token set to compute, a single constant. Any
observed egress to anything else is unambiguously a bypass attempt, by construction of the PEP
pattern itself, not by a permission list that could be wrong or stale.
"""
from __future__ import annotations

import os
from typing import Optional

from sqlmodel import Session, select

from warrant import egress_verifier as ev
from warrant import uid_pool
from warrant.db import ENGINE
from warrant.egress_proxy import EgressProxy, ObservedConnect
from warrant.models import EgressObservation, UidAllocation, utcnow

#: The one legitimate egress destination for every token -- see module docstring. Configurable
#: because "warrant's own host" is a deployment fact, not something this module should hardcode;
#: same env-var-configurable-with-a-sensible-default shape as WARRANT_DB_PATH (db.py).
GATEWAY_HOST = os.environ.get("WARRANT_GATEWAY_HOST", "warrant.local")


def allocate_session_uid(session: Session, *, token_jti: str) -> int:
    """Provisions a real OS user for this token's work window and records the allocation. The
    caller (whoever is about to launch the agent process for this token) uses the returned uid to
    actually run that process as -- this function does not launch anything itself, it only
    provisions the identity the launcher should use."""
    uid = uid_pool.allocate_uid()
    session.add(UidAllocation(token_jti=token_jti, uid=uid))
    session.commit()
    return uid


def release_session_uid(session: Session, *, token_jti: str) -> None:
    """Marks the allocation released and tears down the real OS user. Idempotent: a token with no
    open allocation (already released, or never allocated one) is a no-op, not an error -- release
    is cleanup, and cleanup running twice must never raise."""
    allocation = session.exec(
        select(UidAllocation)
        .where(UidAllocation.token_jti == token_jti)
        .where(UidAllocation.released_at == None)  # noqa: E711 -- SQLModel/SQLAlchemy needs `== None`, not `is None`
    ).first()
    if allocation is None:
        return
    uid_pool.release_uid(allocation.uid)
    allocation.released_at = utcnow()
    session.add(allocation)
    session.commit()


def record_observation(session: Session, observed: ObservedConnect) -> None:
    """The egress proxy's on_connect callback should call this -- persists what the proxy actually
    saw. Called once per real CONNECT; never batched, never summarized, so an unresolved uid
    (observed.uid is None) is preserved as such rather than dropped."""
    session.add(
        EgressObservation(
            uid=observed.uid, host=observed.host, port=observed.port, timestamp=observed.timestamp
        )
    )
    session.commit()


def reconcile_egress(session: Session, *, warrant_host: str = GATEWAY_HOST) -> list[dict]:
    """The live version of egress_verifier.reconcile(): pulls persisted observations and
    allocations, and reconciles against the one-and-only authorized destination (warrant's own
    gateway host -- see module docstring), returning only the CONFIRMED (unauthorized) entries, in
    the same violations-list shape audit.reconcile() already returns, so both can sit side by side
    in `/audit/reconcile`'s response without the caller needing two different result shapes."""
    observations = session.exec(select(EgressObservation)).all()
    allocations = session.exec(select(UidAllocation)).all()

    proxy_log = [
        ev.ProxyLogEntry(uid=o.uid, host=o.host, timestamp=o.timestamp)
        for o in observations
        if o.uid is not None  # an unresolved uid can't join to any allocation; see below
    ]
    uid_allocations = [
        ev.UidAllocation(
            uid=a.uid, token_id=a.token_jti, allocated_at=a.allocated_at, released_at=a.released_at
        )
        for a in allocations
    ]
    # Every token's only authorized host is warrant's own gateway -- see module docstring.
    authorized_hosts = {a.token_jti: {warrant_host} for a in allocations}

    reconciled = ev.reconcile(proxy_log, uid_allocations, authorized_hosts)

    violations = [
        {
            "uid": r.entry.uid,
            "host": r.entry.host,
            "timestamp": r.entry.timestamp.isoformat(),
            "token_id": r.token_id,
            "violation": r.reason,
        }
        for r in reconciled
        if r.verdict == ev.Verdict.CONFIRMED
    ]

    # Unresolved-uid observations are, on their own, exactly as serious as a CONFIRMED entry --
    # the proxy saw *something* leave the observed uid range's window with no attributable owner,
    # which is itself never something to drop silently. Surfaced the same way, not folded into
    # the join above (there is nothing to join an unresolved uid against).
    for o in observations:
        if o.uid is None:
            violations.append(
                {
                    "uid": None,
                    "host": o.host,
                    "timestamp": o.timestamp.isoformat(),
                    "token_id": None,
                    "violation": "proxy could not resolve the connecting process's uid",
                }
            )

    return violations


def start_live_proxy(*, host: str = "127.0.0.1", port: int = 0) -> EgressProxy:
    """Starts a real EgressProxy wired to persist every observation. `on_connect` fires from one
    of the proxy's own per-connection threads (see egress_proxy.EgressProxy._handle), never from
    a request-handling thread -- it opens its own short-lived Session against the shared ENGINE
    per call rather than reusing any request's session, the same "each thread gets its own
    Session object" shape test_multi_replica_signing.py already validated is safe against this
    engine's connect_args (check_same_thread=False, db.py). The caller owns the returned proxy's
    lifecycle -- stop it with proxy.stop()."""

    def _on_connect(observed: ObservedConnect) -> None:
        with Session(ENGINE) as session:
            record_observation(session, observed)

    proxy = EgressProxy(host=host, port=port, on_connect=_on_connect)
    proxy.start()
    return proxy
