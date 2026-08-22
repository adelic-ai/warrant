"""Thin HTTP client for warrant's API — used by the demo's Strands tools, and by the harness itself
for the out-of-band steps (Rick's login, Rick's approval) that no agent tool should be able to do."""
from __future__ import annotations

import httpx


class WarrantClient:
    def __init__(self, base_url: str) -> None:
        self.http = httpx.Client(base_url=base_url, timeout=30.0)

    def _raise_for_status(self, resp: httpx.Response) -> httpx.Response:
        if resp.status_code >= 400:
            raise RuntimeError(f"{resp.request.method} {resp.request.url} -> {resp.status_code}: {resp.text}")
        return resp

    def issue_subject_token(self, principal: str) -> str:
        resp = self._raise_for_status(self.http.post("/token/subject", json={"principal": principal}))
        return resp.json()["subject_token"]

    def issue_identity(self, agent_id: str) -> dict:
        resp = self._raise_for_status(self.http.post("/identity/issue", json={"agent_id": agent_id}))
        return resp.json()  # {"spiffe_id", "cert_pem"}

    def exchange(self, *, subject_token: str, actor_cert_pem: str, case: str, requested_actions: list[str]) -> str:
        resp = self._raise_for_status(
            self.http.post(
                "/token/exchange",
                json={
                    "subject_token": subject_token,
                    "actor_cert_pem": actor_cert_pem,
                    "case": case,
                    "requested_actions": requested_actions,
                },
            )
        )
        return resp.json()["access_token"]

    def exchange_chained(self, *, parent_token: str, sub_actor_cert_pem: str, requested_actions: list[str]) -> str:
        resp = self._raise_for_status(
            self.http.post(
                "/token/exchange/chain",
                json={
                    "parent_token": parent_token,
                    "sub_actor_cert_pem": sub_actor_cert_pem,
                    "requested_actions": requested_actions,
                },
            )
        )
        return resp.json()["access_token"]

    def gateway_read(self, *, token: str, doc_id: str) -> dict:
        resp = self._raise_for_status(
            self.http.get(f"/gateway/documents/{doc_id}", headers={"Authorization": f"Bearer {token}"})
        )
        return resp.json()

    def gateway_export(self, *, token: str, doc_id: str) -> dict:
        resp = self._raise_for_status(
            self.http.post(f"/gateway/documents/{doc_id}/export", headers={"Authorization": f"Bearer {token}"})
        )
        return resp.json()

    def approve(self, *, obligation_id: str, approver: str) -> dict:
        resp = self._raise_for_status(
            self.http.post("/approve", json={"obligation_id": obligation_id, "approver": approver})
        )
        return resp.json()

    def audit_log(self) -> list[dict]:
        resp = self._raise_for_status(self.http.get("/audit/log"))
        return resp.json()

    def audit_reconcile(self) -> dict:
        resp = self._raise_for_status(self.http.get("/audit/reconcile"))
        return resp.json()
