# sage

Delegated authorization for AI agents acting on behalf of human principals — identity, delegation,
policy decision, and audit for agentic IAM.

An AI agent acting for a human should not simply inherit that human's identity and permissions. It
should hold its own attested identity, a scope narrowed to the task, and a decision trail that
explains itself. `sage` is a working prototype of that: an agent gets a short-lived SPIFFE-shaped
identity, a human delegates a scoped subset of their authority to it via OAuth token exchange, a
Cedar-backed policy decision point evaluates every action, and a gateway enforces the result —
injecting downstream credentials the agent itself never sees, and completing "requires approval"
actions only after checking a real approval record, not a self-reported flag.

## Why this project exists

[removed]

**Scope boundary.** This project is IAM — identity, delegation, authorization, entitlement, audit.
It's deliberately narrower than full "enterprise agentic-deployment security" (sandboxing, egress
control, prompt-injection defense, fleet-wide observability). That broader problem is a sibling
project, `warden` (same author — link TODO once it's public) — a governed-LLM-deployment PoC that
reconciles what an agent *said* it did against unforgeable host-level ground truth. `sage` and `warden` share one
thesis — don't trust an agent's self-report — applied at two different layers: `warden` at the
OS/network level, `sage` at the authorization/obligation level (see "Design principles" below).

## Architecture

```
Human principal (Rick)                    Agent (A17)
      |                                         |
      | POST /token/subject                     | POST /identity/issue
      | (stands in for a real IdP login)         | (SPIFFE-shaped SVID, short-lived X.509)
      v                                         v
  subject_token                          actor SVID (cert_pem)
      \                                         /
       \                                       /
        v                                     v
              POST /token/exchange  (RFC 8693)
              — delegation, not impersonation —
              sub: Rick, act.sub: spiffe://.../A17
              scope narrowed to what the Delegation grants
                          |
                          v
                   delegated access token
                          |
                          v
        GET/POST /gateway/documents/{id}[/export]   <-- the PEP
                          |
              validates token, checks action is
              within the TOKEN's own scope
                          |
                          v
                    PDP  /authorize
              (Cedar substrate + deontic-seam wrapper:
               unknown-resource / expiry / explicit-forbid /
               requires-approval checks, defeater provenance)
                          |
              PERMIT ----+---- REQUIRE_APPROVAL ----+---- FORBID
                 |                    |                        |
        credential injection    Obligation created,       justified verdict,
        (agent never sees       gateway returns no         no content
         the downstream key)    content until a distinct
                 |               /approve call (by the
                 v               principal, never the agent)
            content returned     discharges it
                                        |
                                        v
                              second gateway call completes,
                              writes a distinct audit event
                                        |
                                        v
                          GET /audit/reconcile — flags any
                          completion whose timestamp predates
                          its own obligation's discharge
```

## What's real vs. disclosed-simplified

Nothing here is silently faked — everything below is either fully real or explicitly flagged.

| Component | Status |
|---|---|
| Identity model (human/agent/workload, delegation, obligations) | Real — SQLModel over SQLite |
| Policy decision (PDP) | **Real Cedar** (`cedarpy`), confirmed at runtime via `/health`'s `pdp_backend` field. A pure-Python fallback evaluator exists and is used automatically if the `cedarpy` wheel isn't available — never a silent downgrade, `PDP_BACKEND` always reports which is active. |
| Agent identity | **SPIFFE-shaped, not real SPIRE.** Short-lived X.509 certs with a `spiffe://sage.local/agent/<id>` URI SAN, signed by a local CA generated fresh per process. Real SPIRE would add node/workload attestation and a persistent trust bundle — this has neither; disclosed in `sage/identity.py`'s docstring. |
| Delegation | **Real RFC 8693 token exchange** — `act` claim (delegation, not impersonation), scope narrowed to the intersection of what the Delegation grants, enforced at mint time. Chained delegation (agent → sub-agent) is implemented and tested, with the `act` claim nesting and scope non-increase enforced against the parent token's own scope at every hop. |
| PEP / gateway | Real — an MCP-shaped gateway that validates the token's *own* scope (not just the underlying delegation), calls the PDP, and performs credential injection: the downstream secret is fetched server-side and the caller never sees it (proven by test, not just asserted). |
| The three deontic seams | All real and tested: obligation discharge as first-class state (a distinct `/approve` call, by the principal only, never the agent, checked against a real `Obligation` row — not a trusted flag); defeater provenance (every non-default-deny decision surfaces who granted the delegation, why, and when it was reviewed); scope non-increase across a real chained delegation. |
| Audit / reconciliation | Real. `/audit/reconcile` flags any action-completion whose timestamp predates the obligation it claims to rest on — tested against a manufactured backdated-approval scenario, not just the happy path. |
| Storage | SQLite, not Postgres — a deliberate simplification for build velocity, not what an early design note assumed. Trivial to swap for a real deployment. |
| Docker | A `Dockerfile` is included; not verified by an actual build in this environment (no local Docker daemon available while building this). |

## Design principles (and where they came from)

- **Justified verdicts, never a bare boolean.** Every `/authorize` and gateway decision returns
  `decision`, `policy`, `facts`, and `reason` — the full derivation, not `{"allowed": false}`.
- **Credential injection, not brokering** (`sage/gateway.py`) — directly modeled on Roblox's Ring 4
  pattern from *Caging the Agent*: the agent sends a tool call and its own identity; the gateway
  fetches the real credential and injects it mid-flight. The credential is never in the agent's
  reach. Roblox's own published residual-risk admission — that their Ring 5 visibility logs the
  agent's *self-reported* telemetry with nothing reconciling it against ground truth — is what this
  project's audit-reconciliation layer builds on, credited, not framed as "a gap they missed."
- **Never let structural validity substitute for a real check.** The obligation-discharge seam
  exists because a flag an agent can set itself is not evidence anything happened — the same lesson
  AWS's own *ThreatForest* talk (Black Hat USA 2026) demonstrates from the other direction: their
  own published ablation shows every verifier they shipped is purely syntactic ("is a field
  non-empty," never "is this correct"), and their measured quality ceiling is attributable to
  exactly that gap, patched only by human-in-the-loop gates that were skippable in autonomous mode.
  `sage`'s obligation discharge is deliberately **not** skippable — there is no autonomous-mode flag
  that bypasses it.
- **SPIFFE + OAuth token exchange, not a bespoke credential.** Chosen because it's the converging
  2026 standard (CNCF's guidance is, verbatim, "SPIFFE for identity, OAuth 2.0 for access
  delegation, OPA for policy"; the IETF AIMS draft composes the same primitives; Microsoft Entra
  Agent ID reached GA in April 2026 on this shape) — not because any single reference implementation
  demanded it. Roblox's own actual production system uses JWT + HashiCorp Vault instead (no SPIFFE
  at all) — a legitimate, simpler alternative for a human-in-the-loop scenario like this one. SPIFFE
  was chosen here because this project is greenfield and can build the standards-track end-state
  directly rather than needing Roblox's pragmatic migration path.

## Running it

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q                              # 38 tests
uvicorn sage.main:app --reload         # http://127.0.0.1:8000/docs
```

Or via Docker:

```
docker build -t sage .
docker run -p 8000:8000 sage
```

## API surface

| Endpoint | Purpose |
|---|---|
| `POST /authorize` | Direct PDP evaluation — subject/principal/action/resource in, a justified verdict out. |
| `POST /identity/issue` | Issue a SPIFFE-shaped SVID for an agent. |
| `POST /token/subject` | Stand-in for IdP login — issues a subject token for a human principal. |
| `POST /token/exchange` | RFC 8693 exchange — subject_token + actor SVID → delegated, scope-narrowed access token. |
| `GET /gateway/documents/{id}` | PEP-mediated read, with credential injection. |
| `POST /gateway/documents/{id}/export` | PEP-mediated export — REQUIRE_APPROVAL until discharged. |
| `POST /approve` | Discharge an obligation — principal only, never the triggering agent. |
| `GET /audit/reconcile` | Flags any completion that predates its own obligation's discharge. |
| `GET /health` | Liveness + which PDP backend is actually active. |

## Demo — a real Strands-orchestrated run, not a synthetic test

`demo/` runs genuine LLM-driven agents (Claude Sonnet 5, via [Strands](https://github.com/strands-agents/sdk-python))
against a live `sage` instance over real HTTP — an Intake agent that delegates summarizing to a
narrower-scoped Summarizer sub-agent via a real second-hop token exchange, requests an export that
requires human approval, and completes only after the harness (standing in for Rick, never an
agent) approves it. See `demo/README.md` for the full walkthrough. **This run found a real bug**
(the gateway was checking policy against the wrong identity in a delegation chain) that the
41-test suite had missed — fixed, with a regression test, directly from what the run surfaced.
`demo/transcripts/` has the checked-in evidence from one real run.

## Explicitly out of scope (this build)

Real SPIRE (node/workload attestation, persistent trust bundle); joiner-mover-leaver automation;
an LLM-assisted access-request triage feature (considered — see `docs/build-prompt.md` Phase 8 —
deliberately not built to keep the mandatory-approval-gate guarantee simple and load-bearing rather
than adding a feature that has to be carefully kept from undermining it); anything in `warden`'s
domain (sandboxing, egress control, runtime reconciliation).

## Tests

38 tests across identity issuance/verification, token exchange (happy path, scope-widen rejection,
forged-actor rejection, chained delegation with nested `act` claims), the PDP (all three canonical
decisions, Cedar backend confirmation), the gateway (credential-injection proof, token-scope vs.
delegation-scope distinction), obligation discharge (self-approval rejection, wrong-approver
rejection, double-discharge rejection, full discharge-then-completion flow), defeater provenance,
and audit reconciliation (including a manufactured backdated-approval violation). Run with `pytest -q`.
