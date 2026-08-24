from datetime import datetime, timedelta, timezone

from warrant.egress_verifier import ProxyLogEntry, UidAllocation, Verdict, reconcile

T0 = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)


def _at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


def test_egress_to_an_authorized_host_is_AUTHORIZED():
    entry = ProxyLogEntry(uid=5001, host="storage.example.com", timestamp=_at(5))
    allocation = UidAllocation(uid=5001, token_id="tok_a17", allocated_at=T0, released_at=_at(10))
    results = reconcile(
        [entry], [allocation], authorized_hosts={"tok_a17": {"storage.example.com"}}
    )
    assert len(results) == 1
    assert results[0].verdict == Verdict.AUTHORIZED
    assert results[0].token_id == "tok_a17"


def test_egress_to_an_unauthorized_host_is_CONFIRMED_with_the_offending_token_attached():
    entry = ProxyLogEntry(uid=5001, host="evil.example.com", timestamp=_at(5))
    allocation = UidAllocation(uid=5001, token_id="tok_a17", allocated_at=T0, released_at=_at(10))
    results = reconcile(
        [entry], [allocation], authorized_hosts={"tok_a17": {"storage.example.com"}}
    )
    assert results[0].verdict == Verdict.CONFIRMED
    assert results[0].token_id == "tok_a17"
    assert "evil.example.com" in results[0].reason


def test_uid_with_no_allocation_at_all_is_CONFIRMED_as_an_orphan():
    # A uid the proxy saw egress from, but warrant never allocated to any token -- the sharpest
    # possible finding: something is reaching the network that warrant has no record of at all.
    entry = ProxyLogEntry(uid=9999, host="storage.example.com", timestamp=_at(5))
    results = reconcile([entry], uid_allocations=[], authorized_hosts={})
    assert results[0].verdict == Verdict.CONFIRMED
    assert results[0].token_id is None
    assert "no token allocation" in results[0].reason


def test_egress_outside_the_allocation_time_window_is_treated_as_unattributed():
    # The uid was allocated to tok_a17, but only from T0..T0+10m. Egress at T0+20m from the
    # same uid must NOT be credited to tok_a17 -- uid reuse across sessions is exactly the case
    # this time-window check exists for.
    entry = ProxyLogEntry(uid=5001, host="storage.example.com", timestamp=_at(20))
    allocation = UidAllocation(uid=5001, token_id="tok_a17", allocated_at=T0, released_at=_at(10))
    results = reconcile(
        [entry], [allocation], authorized_hosts={"tok_a17": {"storage.example.com"}}
    )
    assert results[0].verdict == Verdict.CONFIRMED
    assert results[0].token_id is None


def test_still_open_allocation_covers_egress_with_no_upper_bound():
    entry = ProxyLogEntry(uid=5001, host="storage.example.com", timestamp=_at(500))
    allocation = UidAllocation(uid=5001, token_id="tok_a17", allocated_at=T0, released_at=None)
    results = reconcile(
        [entry], [allocation], authorized_hosts={"tok_a17": {"storage.example.com"}}
    )
    assert results[0].verdict == Verdict.AUTHORIZED


def test_overlapping_allocations_for_the_same_uid_are_flagged_ambiguous_not_silently_resolved():
    entry = ProxyLogEntry(uid=5001, host="storage.example.com", timestamp=_at(5))
    allocations = [
        UidAllocation(uid=5001, token_id="tok_a17", allocated_at=T0, released_at=_at(10)),
        UidAllocation(uid=5001, token_id="tok_b1", allocated_at=_at(2), released_at=_at(8)),
    ]
    results = reconcile(
        [entry],
        allocations,
        authorized_hosts={"tok_a17": {"storage.example.com"}, "tok_b1": {"storage.example.com"}},
    )
    assert results[0].verdict == Verdict.CONFIRMED
    assert results[0].token_id is None
    assert "overlapping" in results[0].reason


def test_multiple_entries_reconciled_independently_in_order():
    entries = [
        ProxyLogEntry(uid=5001, host="storage.example.com", timestamp=_at(1)),
        ProxyLogEntry(uid=5002, host="evil.example.com", timestamp=_at(2)),
    ]
    allocations = [
        UidAllocation(uid=5001, token_id="tok_a17", allocated_at=T0, released_at=_at(10)),
        UidAllocation(uid=5002, token_id="tok_b1", allocated_at=T0, released_at=_at(10)),
    ]
    results = reconcile(
        entries,
        allocations,
        authorized_hosts={"tok_a17": {"storage.example.com"}, "tok_b1": {"storage.example.com"}},
    )
    assert [r.verdict for r in results] == [Verdict.AUTHORIZED, Verdict.CONFIRMED]
