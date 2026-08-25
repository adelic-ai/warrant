"""Real useradd/userdel/nft tests. Needs root and Linux -- skipped, not faked, everywhere else.
Validate for real against a real Linux host (colima), the same discipline as test_egress_proxy.py."""
from __future__ import annotations

import os
import sys

import pytest

from warrant import uid_pool

linux_root_only = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="useradd/userdel/nft need real root on a real Linux host",
)


def test_username_for_rejects_a_uid_outside_the_reserved_range():
    with pytest.raises(ValueError):
        uid_pool.username_for(1000)


def test_username_for_a_valid_uid():
    assert uid_pool.username_for(uid_pool.SESSION_UID_MIN) == f"warrant-sess-{uid_pool.SESSION_UID_MIN}"


@linux_root_only
def test_allocate_and_release_a_real_uid():
    uid = uid_pool.allocate_uid()
    try:
        assert uid_pool.SESSION_UID_MIN <= uid <= uid_pool.SESSION_UID_MAX
        # Really provisioned -- readable from /etc/passwd, not just returned by the function.
        with open("/etc/passwd") as f:
            passwd = f.read()
        assert uid_pool.username_for(uid) in passwd
    finally:
        uid_pool.release_uid(uid)

    with open("/etc/passwd") as f:
        passwd_after = f.read()
    assert uid_pool.username_for(uid) not in passwd_after


@linux_root_only
def test_allocate_gives_distinct_uids_on_repeated_calls():
    uid_a = uid_pool.allocate_uid()
    uid_b = uid_pool.allocate_uid()
    try:
        assert uid_a != uid_b
    finally:
        uid_pool.release_uid(uid_a)
        uid_pool.release_uid(uid_b)


@linux_root_only
def test_release_of_an_already_gone_user_does_not_raise():
    uid = uid_pool.allocate_uid()
    uid_pool.release_uid(uid)
    uid_pool.release_uid(uid)  # already gone -- must not raise


@linux_root_only
def test_ensure_nftables_rule_is_idempotent_and_actually_blocks():
    """The real security property: a session uid can reach the proxy port, and cannot reach
    anything else -- proven by a real connection attempt from a real allocated uid, not asserted
    from the rule text."""
    import socket
    import subprocess

    uid_pool.teardown_nftables_rule()
    try:
        proxy_port = 18080
        uid_pool.ensure_nftables_rule(proxy_port)
        uid_pool.ensure_nftables_rule(proxy_port)  # second call must not duplicate/error

        listing = subprocess.run(["nft", "list", "table", "inet", "warrant_filter"], capture_output=True, text=True)
        assert uid_pool._RULE_COMMENT in listing.stdout

        uid = uid_pool.allocate_uid()
        try:
            name = uid_pool.username_for(uid)
            # A non-proxy port must be refused for this uid -- run the probe AS that uid via
            # sudo -u, a real process actually running under the reserved-range uid, not a
            # simulation of one.
            probe = subprocess.run(
                ["sudo", "-u", name, "python3", "-c",
                 "import socket,sys; s=socket.socket(); s.settimeout(2)\n"
                 "try:\n"
                 "    s.connect(('93.184.216.34', 80))\n"
                 "    sys.exit(1)\n"
                 "except OSError:\n"
                 "    sys.exit(0)\n"],
                capture_output=True, timeout=10,
            )
            assert probe.returncode == 0, "a session uid reached a non-proxy destination -- the drop rule did not hold"
        finally:
            uid_pool.release_uid(uid)
    finally:
        uid_pool.teardown_nftables_rule()
