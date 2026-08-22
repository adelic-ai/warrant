from warrant.identity import CA, LocalCA
from warrant.tokens import ExchangeError, exchange, issue_subject_token, verify_exchanged_token


def _actor_cert(agent_id: str = "A17") -> bytes:
    return CA.issue(agent_id).cert_pem


def test_exchange_narrows_scope_and_carries_both_identities(session):
    subject_token = issue_subject_token("user:rick")
    token = exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=_actor_cert(),
        case="case:42",
        requested_actions=["read"],
    )
    claims = verify_exchanged_token(token)
    assert claims["sub"] == "user:rick"
    assert claims["act"]["sub"] == "spiffe://warrant.local/agent/A17"
    assert claims["scope"] == ["read"]


def test_exchange_rejects_scope_widen_attempt(session):
    subject_token = issue_subject_token("user:rick")
    # "modify" is explicitly forbidden by the demo delegation — never grantable via exchange.
    try:
        exchange(
            session,
            subject_token=subject_token,
            actor_cert_pem=_actor_cert(),
            case="case:42",
            requested_actions=["read", "modify"],
        )
        assert False, "expected ExchangeError"
    except ExchangeError as exc:
        assert "exceeds" in str(exc)


def test_exchange_rejects_unverifiable_actor_assertion(session):
    subject_token = issue_subject_token("user:rick")
    forged = LocalCA().issue("A17").cert_pem  # signed by a different CA
    try:
        exchange(
            session,
            subject_token=subject_token,
            actor_cert_pem=forged,
            case="case:42",
            requested_actions=["read"],
        )
        assert False, "expected ExchangeError"
    except ExchangeError as exc:
        assert "verification" in str(exc)


def test_exchange_rejects_when_no_delegation_covers_the_case(session):
    subject_token = issue_subject_token("user:rick")
    try:
        exchange(
            session,
            subject_token=subject_token,
            actor_cert_pem=_actor_cert(),
            case="case:99",  # Rick never delegated this case to Agent17
            requested_actions=["read"],
        )
        assert False, "expected ExchangeError"
    except ExchangeError as exc:
        assert "no active delegation" in str(exc)
