# Demo — a real Strands-orchestrated run against a live `warrant`

This is Phase 9 from `docs/build-prompt.md`, built after discussion: not scripted, genuine
LLM-driven agents (Claude Sonnet 5, via the [Strands Agents SDK](https://github.com/strands-agents/sdk-python))
making real tool calls against a live `warrant` instance, over real HTTP. The point is to replace a
synthetic delegation-chain test with agents actually doing something and being genuinely gated.

## What it does

`run_demo.py`:
1. Seeds a fresh `warrant` database with the standard demo scenario and starts a real `uvicorn` server.
2. As the harness (never as an agent) — issues Rick's login token and Agent17's SPIFFE identity,
   then performs the RFC 8693 exchange delegating `read` + `export` on `case:42` to Agent17.
3. Runs **Intake**, a real Strands agent holding that token, with the task: *"review doc:123, get
   it summarized by a sub-agent, then request its export."*
4. Intake calls `delegate_to_subagent`, which mints a **real** second-hop token via
   `exchange_chained` — deliberately narrowed to `read` only, even though Intake itself holds
   `export` — and spins up **Summarizer**, a genuinely separate Strands agent, with only that
   narrower token. Summarizer reads the document and returns a one-line summary.
5. Intake calls `request_export` → real `REQUIRE_APPROVAL`, real `obligation_id`.
6. The harness — standing in for Rick clicking "approve," visibly, as the one thing no agent tool
   can do — calls `/approve`.
7. Intake calls `request_export` again → completes, credential-injected.
8. The harness saves the full agent transcript and `warrant`'s own audit trail to `transcripts/`.

## What the run actually found

The first real run failed at step 4: Summarizer got denied reading a document it should have had
access to. The bug was real, in `warrant/gateway.py`, not in the demo — the gateway was checking
policy against the *immediate* caller's identity (Summarizer/B1), which has no `Delegation` row of
its own (a sub-agent's authority is a narrowed view of the root agent's grant, not a separate
one). Fixed by walking the token's `act` chain down to its root before consulting the PDP, with a
regression test (`tests/test_gateway.py::test_gateway_permits_a_sub_agent_using_a_chained_token`)
added directly from what this run surfaced. The 41-test suite didn't catch this — only a real
orchestrated run with agents actually calling the API did. That's the concrete case for building
this demo instead of stopping at the unit tests.

## Running it yourself

```
pip install -e ".[demo]"
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m demo.run_demo
```

Costs a small number of real Claude Sonnet 5 API calls (two agents, a handful of tool calls each).

## Evidence

`transcripts/run-<timestamp>/` — checked in from one real, successful run:
- `intake_messages.json` — Intake's full message history (reasoning + tool calls + tool results).
- `warrant_audit_log.json` — warrant's own audit trail from that run.
- `warrant_reconcile.json` — the reconciliation check, clean (`{"violations": [], "clean": true}`).
