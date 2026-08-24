# Status

Built live, supervised, in one sitting on 2026-08-22. Not run via warden's unattended hands-off
mode in the end — built directly in a normal Claude Code session instead, to avoid the sandbox's
egress-allowlist/timeout friction discussed earlier in this thread. See `docs/build-prompt.md` for
the original hands-off prompt this was based on (kept for transparency, not executed as written).

## Done, real, tested (44/44 passing)

- Identity/delegation/resource/obligation/audit models (SQLite via SQLModel).
- PDP: real Cedar (`cedarpy`) as the permit/forbid substrate, with a disclosed pure-Python
  fallback if the wheel isn't available. `PDP_BACKEND` always reports which is active — no silent
  downgrade.
- SPIFFE-shaped agent identity: short-lived X.509 SVIDs, local CA, URI SAN convention.
- RFC 8693 token exchange: delegation (`act` claim, not impersonation), scope narrowing enforced
  at mint time, and real chained delegation (agent → sub-agent) with nested `act` claims.
- PEP/gateway: MCP-shaped, enforces the token's *own* scope (not just the delegation's), performs
  credential injection (Roblox Ring 4 pattern) — proven by test that the downstream credential
  never reaches the caller.
- All three deontic seams: obligation discharge (distinct approver, no self-approval, ground-truth
  checked before completion), defeater provenance (owner/reason/reviewed surfaced on every
  non-default-deny decision), scope non-increase (enforced and tested across a real chain).
- Audit reconciliation: `/audit/reconcile`, tested against both the clean path and a manufactured
  backdated-approval violation.
- Dockerfile written.
- README covering the full pitch — why, architecture, what's real vs. disclosed, design
  principles and their sourcing, API surface, explicitly-out-of-scope.

## Disclosed simplifications (see README's table for full detail)

- SPIFFE identity is self-signed-CA-shaped, not real SPIRE (no persistent trust bundle). Caller
  auth added 2026-08-23: `/identity/issue` requires a pre-shared per-agent bootstrap token
  (`WARRANT_BOOTSTRAP_TOKENS`) — closes "any caller can mint an identity for any agent_id," but is
  still not real platform attestation (verifying what's actually running).
- SQLite, not Postgres.
- Dockerfile build-verified (2026-08-23, via colima): `docker build .` succeeds, container starts,
  `/health` responds with real Cedar (`pdp_backend: cedar`).
- `issue_subject_token` stands in for a real IdP; signing keys are ephemeral in-process by default
  (regenerated every process start, not persisted/KMS-backed) — which is a real bug, not just a
  simplification, the moment a second replica exists: each would sign with a different key, so no
  replica could verify another's tokens. Fixed 2026-08-23 (`warrant/keystore.py`,
  `WARRANT_SIGNING_KEY_PATH` / `WARRANT_CA_KEY_PATH`, opt-in): a shared key file, loaded once and
  race-safe across concurrent first-boot. Proven with a real multi-process test (two separate
  `subprocess.run` Python processes, not mocked) — `tests/test_multi_replica_signing.py`. Still not
  KMS-backed; a real deployment would put a KMS/Vault behind the same load-or-create contract.

## Explicitly out of scope (considered, not built)

- **Real SPIRE deployment.** What's built today (2026-08-23) is a shared-secret stand-in — one
  pre-provisioned bootstrap token per `agent_id`, checked with a constant-time string compare
  (`warrant/identity.py:check_bootstrap_token`). That closes "any caller can mint an identity for
  any agent_id" but is not attestation: it verifies the caller *holds a secret*, not that the
  caller *is* the workload it claims to be. Real SPIRE would need, roughly in order of how much
  new infrastructure each requires:
  1. **Platform attestation plugins** — verifying a claim independently of anything the workload
     itself asserts (a k8s service account projection checked against the k8s API server, an AWS
     instance identity document checked against AWS, a TPM quote). A held secret can't do this in
     principle: anything that steals the secret impersonates the workload perfectly, whereas
     attestation checks a fact about the environment that isn't just data the workload carries.
  2. **Node attestation as a prerequisite to workload attestation** — SPIRE attests the node the
     agent daemon runs on first, then lets that agent vouch for workloads on it; a second, chained
     trust problem, not a single check.
  3. **A server + per-node agent architecture** — two long-running services to deploy and keep in
     sync, not a library call in one process.
  4. **Trust bundle distribution, rotation, and federation** — one bundle usable fleet-wide (and
     across multiple SPIRE deployments for multi-cluster/multi-cloud), not one ephemeral CA in one
     process.
  5. **The Workload API** — a standard local gRPC socket other tooling (Envoy, Istio, ...) already
     knows how to consume, vs. warrant's bespoke HTTP endpoint.

  None of these are blocked on anything else here; picking this up would start with #1, since the
  bootstrap-token layer already in place gives something to attest *in addition to*, not something
  that needs to be ripped out first.
- Joiner-mover-leaver automation.
- Phase 8 — an LLM-assisted access-request triage feature. Not built: keeping the
  mandatory-approval-gate guarantee simple and structurally non-bypassable mattered more than the
  feature, and adding it would mean carefully re-proving that guarantee still holds with an LLM
  proposing scope changes in the loop.
- Everything in `warden`'s domain: sandboxing, egress control, prompt-injection defense, runtime
  process/network reconciliation.

## Phase 9 — built (not skipped after all)

A real Strands-orchestrated demo (`demo/`), genuinely LLM-driven (Claude Sonnet 5), not scripted.
See `demo/README.md`. It found and drove the fix for a real bug: `warrant/gateway.py` was checking
the PDP against the immediate caller's identity instead of the delegation chain's root, so every
sub-agent was wrongly denied — the 41-test suite hadn't caught it. Fixed with a regression test
added directly from the failure. One real run's transcript + `warrant`'s own audit trail from it are
checked in under `demo/transcripts/`.

Also added along the way, not in the original phase plan: `POST /token/exchange/chain` (the
chained-exchange function existed only in-process before this — the demo needed it over HTTP) and
`GET /audit/log` (a read-only full trail, needed to pair the agent transcript with warrant's own
record).

## Remaining manual steps

- Push to GitHub — not done automatically; review locally first, then push when ready.
- Do not post to LinkedIn or any social platform automatically — that step is manual, by the human,
  always (explicit boundary from the original build prompt, still holds).
- The warden link in the README is a placeholder ("link TODO") — fill in once/if that repo is
  public.
