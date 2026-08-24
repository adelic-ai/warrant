"""Real multi-process regression test for the horizontal-scaling signing-key bug: each replica
used to generate its own ephemeral EC key at import time, so a token signed by one process could
never be verified by another. Uses actual subprocess.run — two genuinely separate OS processes,
each importing warrant.tokens fresh — not a mock, because the bug is specifically about what
happens at real process-boundary/import time, which an in-process test can't reproduce.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_ISSUE = "from warrant.tokens import issue_subject_token as f; print(f('user:rick'))"
_VERIFY = "import sys; from warrant.tokens import _decode as f; print(f(sys.argv[1])['sub'])"


def _run(code: str, env: dict, *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"subprocess failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    return result.stdout.strip()


def test_two_processes_sharing_signing_key_path_cross_verify_a_token(tmp_path):
    key_path = tmp_path / "shared_signing_key.pem"
    env = os.environ.copy()
    env["WARRANT_SIGNING_KEY_PATH"] = str(key_path)

    # "Replica A" issues a token in one process.
    token = _run(_ISSUE, env)
    # "Replica B" -- a second, independent process, its own fresh import of warrant.tokens --
    # verifies it. This is the actual scaling bug's regression check.
    subject = _run(_VERIFY, env, token)
    assert subject == "user:rick"


def test_without_the_shared_path_two_processes_do_not_cross_verify(tmp_path):
    # Companion negative case: confirms this is a real bug in the default (unset) mode, not a
    # test artifact, and that the fix is opt-in via the env var rather than always-on.
    env = os.environ.copy()
    env.pop("WARRANT_SIGNING_KEY_PATH", None)

    token = _run(_ISSUE, env)
    result = subprocess.run(
        [sys.executable, "-c", _VERIFY, token],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0, "two ephemeral-key processes should NOT verify each other's tokens"
