"""A toy protected backend — stands in for a real internal service (a document store, a case
management API) that requires its own internal credential. Nothing about this module knows about
agents, delegation, or Cedar; it only trusts whoever presents `INTERNAL_KEY`. The whole point of
Phase 5's gateway is that the caller (the agent) never sees that key — only the gateway does.
"""
from __future__ import annotations

import secrets

# Generated once per process, never returned by any API response. This is the credential
# Roblox's Ring 4 talk describes as "mathematically removed from the memory of the agent process."
INTERNAL_KEY = secrets.token_hex(32)

_DOCUMENTS = {
    "doc:123": "Case 42 — deposition transcript excerpt.",
    "doc:999": "Case 99 — unrelated matter, not delegated to Agent17.",
}


class DownstreamAuthError(Exception):
    pass


def fetch_document(doc_id: str, *, internal_key: str) -> str:
    if not secrets.compare_digest(internal_key, INTERNAL_KEY):
        raise DownstreamAuthError("bad internal credential")
    if doc_id not in _DOCUMENTS:
        raise KeyError(doc_id)
    return _DOCUMENTS[doc_id]
