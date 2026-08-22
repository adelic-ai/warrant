# Status

Built live, supervised, in one sitting on 2026-08-22. Not run via warden's unattended hands-off
mode in the end — built directly in a normal Claude Code session instead, to avoid the sandbox's
egress-allowlist/timeout friction discussed earlier in this thread. See `docs/build-prompt.md` for
the original hands-off prompt this was based on (kept for transparency, not executed as written).

## Done, real, tested (38/38 passing)

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

- SPIFFE identity is self-signed-CA-shaped, not real SPIRE (no attestation, no persistent trust
  bundle).
- SQLite, not Postgres.
- Dockerfile is written but not build-verified (no local Docker daemon in this environment).
- `issue_subject_token` stands in for a real IdP; signing keys are ephemeral in-process (regenerated
  every process start, not persisted/KMS-backed).

## Explicitly out of scope (considered, not built)

- Real SPIRE deployment.
- Joiner-mover-leaver automation.
- Phase 8 — an LLM-assisted access-request triage feature. Not built: keeping the
  mandatory-approval-gate guarantee simple and structurally non-bypassable mattered more than the
  feature, and adding it would mean carefully re-proving that guarantee still holds with an LLM
  proposing scope changes in the loop.
- Everything in `warden`'s domain: sandboxing, egress control, prompt-injection defense, runtime
  process/network reconciliation.

## Phase 9 — built (not skipped after all)

A real Strands-orchestrated demo (`demo/`), genuinely LLM-driven (Claude Sonnet 5), not scripted.
See `demo/README.md`. It found and drove the fix for a real bug: `sage/gateway.py` was checking
the PDP against the immediate caller's identity instead of the delegation chain's root, so every
sub-agent was wrongly denied — the 41-test suite hadn't caught it. Fixed with a regression test
added directly from the failure. One real run's transcript + `sage`'s own audit trail from it are
checked in under `demo/transcripts/`.

Also added along the way, not in the original phase plan: `POST /token/exchange/chain` (the
chained-exchange function existed only in-process before this — the demo needed it over HTTP) and
`GET /audit/log` (a read-only full trail, needed to pair the agent transcript with sage's own
record).

## Remaining manual steps

- Push to GitHub — not done automatically; review locally first, then push when ready.
- Do not post to LinkedIn or any social platform automatically — that step is manual, by the human,
  always (explicit boundary from the original build prompt, still holds).
- Docker build has never actually been run — worth doing once before claiming it works in any
  public-facing description.
- The warden link in the README is a placeholder ("link TODO") — fill in once/if that repo is
  public.
