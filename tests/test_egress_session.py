"""Tests for the wiring layer. record_observation/reconcile_egress are pure DB logic and run
everywhere; allocate_session_uid/release_session_uid call real uid_pool functions and need real
Linux root, same as test_uid_pool.py -- skipped, not faked, elsewhere."""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

from warrant import egress_session
from warrant.egress_proxy import ObservedConnect
from warrant.models import EgressObservation, UidAllocation

linux_root_only = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="allocate/release call real useradd/userdel, need real root on real Linux",
)

GATEWAY_HOST = "warrant.local"


def test_record_observation_persists_what_the_proxy_saw(session):
    observed = ObservedConnect(uid=501, host="evil.example.com", port=443, timestamp=datetime.now(timezone.utc))
    egress_session.record_observation(session, observed)

    from sqlmodel import select

    rows = session.exec(select(EgressObservation)).all()
    assert len(rows) == 1
    assert rows[0].uid == 501
    assert rows[0].host == "evil.example.com"


def test_reconcile_finds_nothing_when_egress_matches_the_gateway_host(session):
    now = datetime.now(timezone.utc)
    session.add(UidAllocation(token_jti="tok-a", uid=501, allocated_at=now - timedelta(seconds=5)))
    session.commit()
    egress_session.record_observation(
        session, ObservedConnect(uid=501, host=GATEWAY_HOST, port=443, timestamp=now)
    )

    violations = egress_session.reconcile_egress(session, warrant_host=GATEWAY_HOST)
    assert violations == []


def test_reconcile_flags_egress_to_anything_other_than_the_gateway_host(session):
    """The actual bypass scenario this whole design exists to catch: a session uid reaches a
    downstream host directly instead of going through warrant's own gateway."""
    now = datetime.now(timezone.utc)
    session.add(UidAllocation(token_jti="tok-a", uid=501, allocated_at=now - timedelta(seconds=5)))
    session.commit()
    egress_session.record_observation(
        session, ObservedConnect(uid=501, host="downstream-docs.internal", port=443, timestamp=now)
    )

    violations = egress_session.reconcile_egress(session, warrant_host=GATEWAY_HOST)
    assert len(violations) == 1
    assert violations[0]["host"] == "downstream-docs.internal"
    assert violations[0]["token_id"] == "tok-a"


def test_reconcile_flags_an_unresolved_uid_rather_than_dropping_it(session):
    now = datetime.now(timezone.utc)
    egress_session.record_observation(
        session, ObservedConnect(uid=None, host=GATEWAY_HOST, port=443, timestamp=now)
    )

    violations = egress_session.reconcile_egress(session, warrant_host=GATEWAY_HOST)
    assert len(violations) == 1
    assert violations[0]["uid"] is None
    assert "could not resolve" in violations[0]["violation"]


def test_reconcile_flags_egress_from_a_uid_with_no_allocation(session):
    now = datetime.now(timezone.utc)
    egress_session.record_observation(
        session, ObservedConnect(uid=999, host=GATEWAY_HOST, port=443, timestamp=now)
    )

    violations = egress_session.reconcile_egress(session, warrant_host=GATEWAY_HOST)
    assert len(violations) == 1
    assert violations[0]["uid"] == 999
    assert violations[0]["token_id"] is None


@linux_root_only
def test_allocate_and_release_wires_the_real_os_user_and_the_db_row_together(session):
    from sqlmodel import select

    uid = egress_session.allocate_session_uid(session, token_jti="tok-real")
    row = session.exec(select(UidAllocation).where(UidAllocation.token_jti == "tok-real")).first()
    assert row is not None
    assert row.uid == uid
    assert row.released_at is None

    with open("/etc/passwd") as f:
        passwd = f.read()
    from warrant import uid_pool
    assert uid_pool.username_for(uid) in passwd

    egress_session.release_session_uid(session, token_jti="tok-real")
    session.refresh(row)
    assert row.released_at is not None

    with open("/etc/passwd") as f:
        passwd_after = f.read()
    assert uid_pool.username_for(uid) not in passwd_after


@linux_root_only
def test_release_is_idempotent(session):
    egress_session.allocate_session_uid(session, token_jti="tok-b")
    egress_session.release_session_uid(session, token_jti="tok-b")
    egress_session.release_session_uid(session, token_jti="tok-b")  # must not raise


def test_release_of_a_token_with_no_allocation_is_a_noop(session):
    egress_session.release_session_uid(session, token_jti="never-allocated")  # must not raise
