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
- Everything in `warden`'s domain: sandboxing, prompt-injection defense, egress *enforcement*
  (blocking/allowlisting traffic) — genuinely "running agents safely," not this project's job.
  **Narrowed 2026-08-23** (see Phase 10 below): egress *observation*, in service of making
  `/audit/reconcile`'s own claim actually check something external, is now in scope. It doesn't
  block anything; it exists only to verify a decision this project already made, same category as
  the existing `/audit/reconcile`, not a new containment feature.

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

## Phase 10 — the egress verifier: closing Phase 7's own unfulfilled promise

`docs/build-prompt.md`'s design intent for `/audit/reconcile` was explicit: *"building on [Roblox's]
published admission [that] nothing reconciles [self-reported telemetry] against unforgeable ground
truth... this is the concrete, working version of 'don't trust self-report.'"* What Phase 7 actually
specified and what got built only checks internal timestamp ordering within warrant's own tables
(does completion precede discharge) — self-consistency, not anything external. Roblox's own admitted
gap was never actually closed; it was narrowed to a smaller version of the same shape.

**Scope call, made explicitly per the build prompt's own rule** ("make the most reasonable call,
note it in STATUS.md, and keep moving"): building the piece that actually reaches outside warrant's
own process to check a claim — did the agent's actual network egress match what warrant authorized —
is finishing that original promise, not new scope. See `considerations/warden-agentwatch-enhance-warrant.md`
for the full design reasoning, including the Black Hat 2026 "Trusted Enough to Run" (Elad Meged)
trust-handoff audit method this design is built against, and the honest case for reading it the
*other* way (that "egress" is named explicitly enough in the original boundary that this is scope
creep regardless of purpose) — recorded there, not hidden.

**What's in scope, precisely, and what stays out:** *observing* egress (a uid-tagged proxy log,
reconciled against warrant's own authorization records) is in scope as of this decision. *Enforcing*
egress (blocking, allowlisting) stays out — that's still "running agents safely," warden's job, not
this project's. The `nftables` rule this needs is there only to guarantee the proxy sees all traffic
so its log is complete, not to block anything the proxy doesn't like.

- `warrant/egress_verifier.py` — the reconciliation/join logic (uid → token allocation → authorized
  hosts), pure Python, no OS dependency, tested (7 tests: authorized/unauthorized/orphan-uid/
  time-window/overlapping-allocation cases).
- `warrant/uid_pool.py` — ephemeral per-session OS users from a static, pre-reserved uid range
  (58000–58899), one idempotent `nftables` rule scoping the whole range to the proxy port only.
  `warrant/egress_proxy.py` — a CONNECT-only forward proxy resolving the connecting uid via
  `/proc/net/tcp` → inode → `/proc/<pid>/status` (what `ss`/`lsof` do), not a Unix socket, so it
  stays usable by any standard HTTP client via `http_proxy`/`https_proxy`. **Built and validated
  for real** against colima (a real Linux VM, not a fake — Darwin has no `nftables`, and macOS's
  socket peer-credential API differs from Linux's `SO_PEERCRED`): as root, a real allocated session
  uid was proven to reach the proxy port and *nothing else* — a real subprocess run as that uid
  attempting a direct connection to an arbitrary external host was actually refused by the kernel,
  not asserted from rule text — and the proxy resolved a real connecting process's real uid over a
  real CONNECT tunnel relaying real bytes. 67 tests pass as root on real Linux (0 skipped); 62 pass
  on the Mac with the Linux/root-only ones correctly skipped, not faked.
- `warrant/egress_session.py` — wires all three pieces into one live path. `UidAllocation` and
  `EgressObservation` now persist to the DB (`models.py`), not just hand-built test data.
  `authorized_hosts` is not a per-token set derived from the Delegation model — warrant's own
  credential-injection gateway pattern (`gateway.py`) means the agent should never reach a
  downstream resource directly at all, so the *one* legitimate destination for every token is
  warrant's own gateway host, a single constant. Any other egress is a bypass by construction of
  the PEP pattern, not by a permission list that could be wrong or stale. **Built and validated for
  real** on colima as root: 75 tests pass, 0 skipped, including a real
  `allocate_session_uid` → real `useradd` → real DB row → real `release_session_uid` → real
  `userdel` round trip. 68 pass on the Mac with the 7 Linux/root-only ones correctly skipped.
- `POST /egress/allocate`, `POST /egress/release`, `GET /audit/reconcile/egress` — HTTP endpoints,
  keyed off the access token's own server-verified `jti` (via `verify_exchanged_token`, never a
  client-supplied session id). `exchange()`/`exchange_chained()` deliberately NOT changed to
  auto-allocate a uid — that would make every existing token-exchange test (dozens, cross-platform)
  attempt a real `useradd`; allocation stays an explicit step for whoever's about to actually
  launch an agent process under observation. `/audit/reconcile/egress` is a separate endpoint from
  `/audit/reconcile` on purpose — obligation-discharge timing and independently-observed egress are
  different kinds of check, and merging them into one violations list would lose that distinction.
  **Built and validated for real** on colima as root: 79 tests pass, 0 skipped, including the full
  HTTP flow — subject token, identity issue, token exchange, real `/egress/allocate` (real
  `useradd`), real `/egress/release` (real `userdel`). 71 pass on the Mac with the 8 Linux/root-only
  ones correctly skipped.
- `WARRANT_EGRESS_PROXY_ENABLED=1` starts a real `EgressProxy` as part of the app's own lifespan
  (off by default — every existing test keeps starting the app exactly as before). **Built and
  validated for real** on colima as root: the running app actually binds a real proxy port,
  actually installs the `nftables` rule, actually relays a real CONNECT tunnel, and
  `/audit/reconcile/egress` actually surfaces the real observation — end to end, no mocks. 81 tests
  pass as root on real Linux, 0 skipped.
- **Deliberately not wired into `demo/agents.py`, and this was a decision, not an oversight.**
  `run_demo.py` never manufactures a violation for the *existing* `/audit/reconcile` either — it
  just calls it once and prints the (expected-clean) result; the actual proof that reconciler
  catches something real lives entirely in `tests/test_audit_reconcile.py`'s manufactured
  backdated-approval scenario. `tests/test_live_egress_app.py` is that same shape for the egress
  verifier — a real, live, end-to-end catch, already proven. Forcing the demo's Strands agent to
  run in a subprocess under an allocated uid would be a real architectural change to something that
  currently works and is tested, in service of a demonstration that wouldn't actually demonstrate
  anything: the demo's own tools (`read_document`, `delegate_to_subagent`, `request_export`) only
  ever call warrant's own gateway — there is no bypass vector for them to attempt, sandboxed or
  not, so a restructured demo would allocate a uid whose session and the agent's actual (still
  same-uid) work wouldn't even correspond to each other. Complete where completeness matters: real
  capability, real tests, real validation on real Linux — not demo theater.

## A further direction, not built — the same-process attribution gap, and "siphonophore"

Found reasoning through Phase 10, not before: uid-based attribution silently assumes one uid per
session, but Strands' actual delegation model doesn't give you that. `demo/agents.py`'s
`delegate_to_subagent` mints a real, separately-scoped second-hop token
(`client.exchange_chained`) for the sub-agent, then just constructs a new `Agent` object and calls
it — `summarizer(...)` is a plain Python function call, not a new process. No `fork`, no
`subprocess.Popen`, nothing. The parent and every delegated sub-agent share one pid *and* one uid,
because they never leave the one OS process the harness is running in. So even with everything in
Phase 10 fully wired, a real deployment with active delegation chains would still have no way to
tell, from the proxy's own observations, which of several concurrently-running agents inside one
process made a given call — they're indistinguishable at the OS level as things stand today.

**What it would take to actually fix, sketched, not built:**

1. **Provision the process at delegation time, not organically.** A pid isn't earned by an agent
   doing something — it's assigned the instant a process is spawned, before it runs any code at
   all. So `delegate_to_subagent` should spawn the sub-agent's process immediately after
   `exchange_chained` mints its token, *before* handing it any real work — the same "provision the
   identity first, then hand off the work" shape `allocate_session_uid`/`/egress/allocate` already
   use for uid. Right now nothing spawns anything, which is *why* there's no pid worth having an
   opinion about yet.
2. **Require a real, proxied check-in before that identity is trusted for anything** — not a
   benign no-op, an actual first network call through the proxy. This is closer to Kerberos than
   to a self-reported flag: neither warrant alone (which only knows the token it minted) nor the
   spawned process alone (which only knows its own token) can produce the pairing "this pid/uid
   really is this token" — it takes putting the two together, one half held by warrant, one half
   observed independently by the proxy at the OS level, the same way a Kerberos ticket only
   verifies when both sides' independently-held pieces agree. A process that never checks in this
   way is exactly as untrusted as one that was never provisioned at all.
3. **Prefer a cgroup over a bare pid for tracking a whole descendant subtree, and this isn't a new
   idea for this codebase's own author — it's the same fix warden/agentwatch already reached for.**
   A pid identifies one process; it says nothing about that process's own children if a sub-agent's
   tool later forks or execs further work. warden's own `reconcile_ebpf_live` docstring
   (`warden/report.py`) already describes exactly this: *"the session cgroup self-seeds from the
   runtime's own exec in the capture stream... so no cgroup argument is needed for the basic
   path."* And the reason cgroups matter there is the same fork-gap warden's own `DECISIONS.md`
   names directly — *"the capture plane ships fork-gap-blind"* — because exec-only observation
   (auditd) can't see a process that forks without ever exec'ing, so its whole subtree falls out of
   scope. A cgroup, unlike a pid, is assigned once to a whole process tree and the kernel tracks
   membership persistently across that entire tree, including descendants that fork later without
   exec'ing — closing exactly the gap a bare pid (or agentwatch's own ancestry-walk, which has the
   identical fork-gap blindness) can't. For warrant's own shape, this would likely mean: keep the
   *broad*, coarse uid range for `nftables` enforcement (it doesn't need per-agent granularity —
   the whole family of session-launched processes reaching only the proxy is the actual boundary
   that matters), and use a cgroup per delegated agent as the *fine-grained* attribution key once
   traffic reaches the proxy — cheaper to provision than a fresh OS user per agent (no `useradd`
   needed, just a cgroup), and robust to a sub-agent's own tool later forking work the way a pid
   alone would not be.

**Named "siphonophore" for the bigger version of this, not scoped for this project:** Strands'
own model is one body (one process) with many tentacles (tool functions) — including delegation to
a sub-agent, which is *also* just another tentacle, not a new body. A siphonophore, biologically,
is the opposite: a colony of individually-complete zooids, each with its own real boundary,
coordinated but never fused into one shared body. A framework where every agent — including every
delegated sub-agent, at arbitrary depth — is its own real OS process by construction, coordinated
through message-passing rather than in-process calls, would make OS-level ground truth (uid,
cgroup, or otherwise) precise no matter how deep a delegation chain goes, rather than correct only
at the top level the way today's design is. That's a different framework, not a fix to this one —
worth a real, separately-scoped pass, not something to fold into this project's own timeline.

## Remaining manual steps

- Push to GitHub — not done automatically; review locally first, then push when ready.
- Do not post to LinkedIn or any social platform automatically — that step is manual, by the human,
  always (explicit boundary from the original build prompt, still holds).
- The warden link in the README is a placeholder ("link TODO") — fill in once/if that repo is
  public.
