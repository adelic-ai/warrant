"""HTTP-level tests for the egress verifier's endpoints. /egress/allocate and /egress/release call
real uid_pool functions -- Linux/root-only, skipped elsewhere, same as tests/test_uid_pool.py.
/audit/reconcile/egress is pure DB logic and runs everywhere."""
from __future__ import annotations

import os
import sys

import pytest

from tests.conftest import bootstrap_headers

linux_root_only = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="egress/allocate and egress/release call real useradd/userdel, need real root on real Linux",
)


def _get_access_token(client) -> str:
    subject_token = client.post("/token/subject", json={"principal": "user:rick"}).json()["subject_token"]
    cert_pem = client.post(
        "/identity/issue", json={"agent_id": "A17"}, headers=bootstrap_headers("A17")
    ).json()["cert_pem"]
    resp = client.post(
        "/token/exchange",
        json={
            "subject_token": subject_token,
            "actor_cert_pem": cert_pem,
            "case": "case:42",
            "requested_actions": ["read"],
        },
    )
    return resp.json()["access_token"]


def test_reconcile_egress_endpoint_is_clean_with_no_observations(client):
    resp = client.get("/audit/reconcile/egress")
    assert resp.status_code == 200
    body = resp.json()
    assert body["clean"] is True
    assert body["violations"] == []


@linux_root_only
def test_allocate_endpoint_provisions_a_real_uid(client):
    token = _get_access_token(client)
    resp = client.post("/egress/allocate", json={"access_token": token})
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["uid"], int)
    assert body["username"].startswith("warrant-sess-")

    with open("/etc/passwd") as f:
        assert body["username"] in f.read()

    release = client.post("/egress/release", json={"access_token": token})
    assert release.status_code == 200
    assert release.json()["released"] is True

    with open("/etc/passwd") as f:
        assert body["username"] not in f.read()


def test_allocate_endpoint_rejects_an_invalid_token(client):
    resp = client.post("/egress/allocate", json={"access_token": "not-a-real-token"})
    assert resp.status_code == 400


def test_release_endpoint_rejects_an_invalid_token(client):
    resp = client.post("/egress/release", json={"access_token": "not-a-real-token"})
    assert resp.status_code == 400
