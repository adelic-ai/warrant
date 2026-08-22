from warrant.identity import CA, LocalCA, spiffe_id_for


def test_issue_and_verify_roundtrip():
    svid = CA.issue("A17")
    assert svid.spiffe_id == "spiffe://warrant.local/agent/A17"
    verified = CA.verify(svid.cert_pem)
    assert verified == svid.spiffe_id


def test_verify_rejects_expired_cert():
    svid = CA.issue("A17", ttl_minutes=-5)  # already expired at issuance
    assert CA.verify(svid.cert_pem) is None


def test_verify_rejects_cert_from_a_different_ca():
    other_ca = LocalCA()
    svid = other_ca.issue("A17")
    # CA (the module singleton) did not sign this cert — must not validate against it.
    assert CA.verify(svid.cert_pem) is None


def test_spiffe_id_convention():
    assert spiffe_id_for("A17") == "spiffe://warrant.local/agent/A17"
