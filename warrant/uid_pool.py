"""Ephemeral per-session OS users, allocated from a static, pre-reserved uid range -- the OS-level
half of the egress verifier (STATUS.md Phase 10, considerations/warden-agentwatch-enhance-warrant.md).

Linux-only. Needs root (useradd/userdel). Not importable/usable on the Mac this is developed on --
validate against a real Linux host (colima, in this project's case), same "real substrate, not a
fake" discipline the sibling `warden` project runs on.

Why a static range, not per-session firewall rules: a session that crashes without clean teardown
leaves an orphaned OS user, not a stale firewall hole. One `nftables` rule (see `ensure_nftables_rule`)
covers the whole reserved range once; `release_uid` returning a uid to the pool is a cleanup
convenience, not something network enforcement depends on. Mirrors warden's own already-validated
decision, "Audit scoping key: uid range, not auid (loginuid)" (warden/DECISIONS.md) -- scope by
range, not by a single dynamic identifier, for the same robustness reason.
"""
from __future__ import annotations

import subprocess

#: Reserved for warrant session users. Chosen to sit clear of normal system/service accounts
#: (Debian/Ubuntu system uids typically end well below 1000; systemd's own DynamicUser range is
#: 61184-65519) and to leave room -- 900 concurrent sessions -- without colliding with it.
SESSION_UID_MIN = 58000
SESSION_UID_MAX = 58899

_USER_PREFIX = "warrant-sess-"

#: The nft table/chain/rule this module owns. A distinguishing comment lets ensure_nftables_rule
#: detect whether its rule is already present (idempotent) without depending on rule ordering or
#: handle numbers, which nft reassigns.
_NFT_TABLE = "inet"
_NFT_CHAIN = "warrant_egress"
_RULE_COMMENT = "warrant-session-uid-range-to-proxy-only"


class UidPoolError(RuntimeError):
    """A privileged operation (useradd/userdel/nft) failed. Never swallowed -- a failed
    allocation must not silently hand back a uid nothing actually provisioned."""


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=15)


def username_for(uid: int) -> str:
    if not (SESSION_UID_MIN <= uid <= SESSION_UID_MAX):
        raise ValueError(f"uid {uid} is outside the reserved session range {SESSION_UID_MIN}-{SESSION_UID_MAX}")
    return f"{_USER_PREFIX}{uid}"


def _existing_session_uids() -> set[int]:
    """Uids in the reserved range that already have a provisioned user -- from /etc/passwd, not
    from warrant's own bookkeeping, so a uid leaked by a crash (bookkeeping lost, OS user still
    there) is still seen as taken, never double-allocated."""
    taken: set[int] = set()
    with open("/etc/passwd") as f:
        for line in f:
            fields = line.rstrip("\n").split(":")
            if len(fields) < 3:
                continue
            try:
                uid = int(fields[2])
            except ValueError:
                continue
            if SESSION_UID_MIN <= uid <= SESSION_UID_MAX:
                taken.add(uid)
    return taken


def allocate_uid() -> int:
    """Provisions a new, no-login, no-home ephemeral OS user in the reserved range and returns
    its uid. Raises UidPoolError if the range is exhausted or useradd fails for any other reason
    -- an exhausted pool must surface as a real error, not silently reuse a live uid."""
    taken = _existing_session_uids()
    for uid in range(SESSION_UID_MIN, SESSION_UID_MAX + 1):
        if uid in taken:
            continue
        name = username_for(uid)
        result = _run(["useradd", "-M", "-N", "-s", "/usr/sbin/nologin", "-u", str(uid), name])
        if result.returncode == 0:
            return uid
        if "already exists" in result.stderr or "in use" in result.stderr:
            # Lost a race with another allocator (or /etc/passwd was stale for another reason) --
            # try the next uid rather than erroring on a transient collision.
            continue
        raise UidPoolError(f"useradd failed for uid {uid}: {result.stderr.strip()}")
    raise UidPoolError(
        f"session uid pool exhausted: no free uid in {SESSION_UID_MIN}-{SESSION_UID_MAX}"
    )


def release_uid(uid: int) -> None:
    """Best-effort userdel. Never raises on 'already gone' -- a session that crashed and left no
    user to delete is not an error here; the uid just silently returns to the pool on the next
    _existing_session_uids() scan. Does raise on a real privilege/tooling failure, since a
    userdel that fails for a reason OTHER than "already gone" deserves to be seen, not hidden."""
    name = username_for(uid)
    result = _run(["userdel", name])
    if result.returncode != 0 and "does not exist" not in result.stderr:
        raise UidPoolError(f"userdel failed for {name}: {result.stderr.strip()}")


def ensure_nftables_rule(proxy_port: int) -> None:
    """Idempotently ensures the ONE static rule exists: uids in the reserved range may only reach
    the proxy port; everything else from those uids is dropped. Safe to call on every process
    start -- checks for the rule's own comment before adding, so it never duplicates.

    This is observation-forcing, not general containment: its only job is guaranteeing the proxy
    sees every session uid's egress, so the proxy's log is complete rather than a hopeful sample.
    It does not touch any other uid's traffic, and it does not decide what's "safe" -- reconciling
    what the proxy actually saw against what warrant actually authorized is egress_verifier.py's
    job, not this rule's.
    """
    check = _run(["nft", "-a", "list", "table", _NFT_TABLE, "warrant_filter"])
    if _RULE_COMMENT in check.stdout:
        return

    _run(["nft", "add", "table", _NFT_TABLE, "warrant_filter"])
    _run([
        "nft", "add", "chain", _NFT_TABLE, "warrant_filter", _NFT_CHAIN,
        "{", "type", "filter", "hook", "output", "priority", "0", ";", "}",
    ])
    # Allow the range to reach the proxy port and loopback (the proxy itself needs to answer);
    # drop everything else from that range. Order matters: the allow rule must be added first,
    # since nft evaluates rules in the chain in insertion order.
    add_allow = _run([
        "nft", "add", "rule", _NFT_TABLE, "warrant_filter", _NFT_CHAIN,
        "meta", "skuid", f"{SESSION_UID_MIN}-{SESSION_UID_MAX}",
        "tcp", "dport", str(proxy_port), "accept",
        "comment", _RULE_COMMENT,
    ])
    if add_allow.returncode != 0:
        raise UidPoolError(f"failed to add the proxy-allow rule: {add_allow.stderr.strip()}")

    add_drop = _run([
        "nft", "add", "rule", _NFT_TABLE, "warrant_filter", _NFT_CHAIN,
        "meta", "skuid", f"{SESSION_UID_MIN}-{SESSION_UID_MAX}",
        "drop",
        "comment", f"{_RULE_COMMENT}-drop-rest",
    ])
    if add_drop.returncode != 0:
        raise UidPoolError(f"failed to add the drop-rest rule: {add_drop.stderr.strip()}")


def teardown_nftables_rule() -> None:
    """Removes the table this module created. Test/dev convenience -- a real deployment leaves
    the rule in place for the process lifetime; nothing here depends on this being called."""
    _run(["nft", "delete", "table", _NFT_TABLE, "warrant_filter"])
