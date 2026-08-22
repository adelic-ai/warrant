from sage.identity import CA
from sage.tokens import ExchangeError, exchange, exchange_chained, issue_subject_token, verify_exchanged_token


def test_three_hop_chain_scope_narrows_and_both_identities_are_nested(session):
    subject_token = issue_subject_token("user:rick")
    hop1 = exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=CA.issue("A17").cert_pem,
        case="case:42",
        requested_actions=["read"],
    )
    hop2 = exchange_chained(
        session,
        parent_token=hop1,
        sub_actor_cert_pem=CA.issue("B1").cert_pem,
        requested_actions=["read"],
    )
    claims = verify_exchanged_token(hop2)
    assert claims["sub"] == "user:rick"  # the human principal is unchanged, three hops in
    assert claims["act"]["sub"] == "spiffe://sage.local/agent/B1"
    assert claims["act"]["act"]["sub"] == "spiffe://sage.local/agent/A17"  # nested, not flattened
    assert claims["scope"] == ["read"]


def test_chain_rejects_a_widen_attempt_at_the_second_hop(session):
    subject_token = issue_subject_token("user:rick")
    hop1 = exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=CA.issue("A17").cert_pem,
        case="case:42",
        requested_actions=["read"],  # narrow — no export
    )
    try:
        exchange_chained(
            session,
            parent_token=hop1,
            sub_actor_cert_pem=CA.issue("B1").cert_pem,
            requested_actions=["read", "export"],  # sub-agent tries to widen beyond the parent
        )
        assert False, "expected ExchangeError"
    except ExchangeError as exc:
        assert "exceeds the parent token's own scope" in str(exc)


def test_chain_rejects_an_unverifiable_sub_actor(session):
    from sage.identity import LocalCA

    subject_token = issue_subject_token("user:rick")
    hop1 = exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=CA.issue("A17").cert_pem,
        case="case:42",
        requested_actions=["read"],
    )
    forged = LocalCA().issue("B1").cert_pem
    try:
        exchange_chained(session, parent_token=hop1, sub_actor_cert_pem=forged, requested_actions=["read"])
        assert False, "expected ExchangeError"
    except ExchangeError as exc:
        assert "verification" in str(exc)
