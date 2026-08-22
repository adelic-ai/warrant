"""The demo harness. Not an agent — this is the part of the system no agent tool is allowed to
be: it does Rick's login (stands in for a real IdP) and Rick's approval (stands in for a human
clicking "approve"), both visibly, both out-of-band from anything Intake or Summarizer can do
themselves. Everything else runs through real HTTP calls against a live warrant instance, real
Strands agents, real Anthropic API calls.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

DEMO_DIR = Path(__file__).parent
REPO_ROOT = DEMO_DIR.parent
DB_PATH = DEMO_DIR / "demo.db"
PORT = 8123
BASE_URL = f"http://127.0.0.1:{PORT}"


def seed(db_path: Path) -> None:
    if db_path.exists():
        db_path.unlink()
    os.environ["WARRANT_DB_PATH"] = str(db_path)
    from sqlmodel import Session

    from warrant.db import ENGINE, init_db
    from warrant.seed import seed_demo

    init_db(ENGINE)
    with Session(ENGINE) as s:
        seed_demo(s)


def start_server() -> subprocess.Popen:
    env = os.environ.copy()
    env["WARRANT_DB_PATH"] = str(DB_PATH)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "warrant.main:app", "--port", str(PORT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for _ in range(50):
        try:
            r = httpx.get(f"{BASE_URL}/health", timeout=1)
            if r.status_code == 200:
                print(f"warrant server up: {r.json()}")
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.terminate()
    out = proc.stdout.read() if proc.stdout else ""
    raise RuntimeError(f"warrant server did not become healthy in time.\n{out}")


def main() -> None:
    if "ANTHROPIC_API_KEY" not in os.environ:
        raise SystemExit("ANTHROPIC_API_KEY is not set in this environment.")

    seed(DB_PATH)
    proc = start_server()
    try:
        from demo.agents import make_intake_agent
        from demo.warrant_client import WarrantClient

        client = WarrantClient(BASE_URL)

        print("\n=== Harness: Rick logs in (stands in for a real IdP) ===")
        subject_token = client.issue_subject_token("user:rick")

        print("=== Harness: Agent17 gets a SPIFFE-shaped identity ===")
        a17 = client.issue_identity("A17")
        print(f"  {a17['spiffe_id']}")

        print("=== Harness: Rick delegates read+export on case:42 to Agent17 (RFC 8693 exchange) ===")
        intake_token = client.exchange(
            subject_token=subject_token,
            actor_cert_pem=a17["cert_pem"],
            case="case:42",
            requested_actions=["read", "export"],
        )

        intake = make_intake_agent(client, intake_token)

        print("\n=== Intake agent run 1 ===")
        result1 = intake(
            "Please review doc:123. Get it summarized by a sub-agent, then request its export."
        )
        print(f"\n[Intake final response]\n{result1}\n")

        print("=== Harness: checking warrant's own audit log for a pending obligation ===")
        pending = [r for r in client.audit_log() if r["decision"] == "REQUIRE_APPROVAL" and r["obligation_id"]]
        if not pending:
            print("No REQUIRE_APPROVAL obligation found — nothing to approve. Stopping here.")
        else:
            obligation_id = pending[-1]["obligation_id"]
            print(f"=== Harness: Rick approves obligation {obligation_id} (NOT something any agent tool can do) ===")
            approval = client.approve(obligation_id=obligation_id, approver="user:rick")
            print(f"  {approval}")

            print("\n=== Intake agent run 2 (completes the export now that it's approved) ===")
            result2 = intake("Please request the export of doc:123 again now.")
            print(f"\n[Intake final response]\n{result2}\n")

        print("=== Harness: reconciliation check ===")
        reconcile = client.audit_reconcile()
        print(f"  {reconcile}")

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = DEMO_DIR / "transcripts" / f"run-{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "intake_messages.json").write_text(json.dumps(intake.messages, indent=2, default=str))
        (out_dir / "warrant_audit_log.json").write_text(json.dumps(client.audit_log(), indent=2))
        (out_dir / "warrant_reconcile.json").write_text(json.dumps(reconcile, indent=2))
        print(f"\nSaved transcript + audit trail to {out_dir}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
