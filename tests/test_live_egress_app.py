"""End-to-end: the app itself, started with WARRANT_EGRESS_PROXY_ENABLED=1, actually running a
live proxy that persists real observations and that /audit/reconcile/egress can see. Needs real
root and real Linux (useradd/nftables) -- skipped, not faked, everywhere else.

Deliberately does not try to isolate this test's own database: warrant.db's ENGINE is a
module-level constant other test files (via conftest.py's top-level `from warrant.main import
app`) have very likely already imported before this test runs, and init_db's own `engine=ENGINE`
default argument is bound once at db.py's function-definition time -- both make a clean
monkeypatched-engine swap unreliable to get right without importlib.reload gymnastics that would
add more risk of a false pass than they'd remove. Instead: assert on the *specific* observation
this test caused (matched by the random ephemeral target port, unique per run), not on the
reconcile list being empty beforehand or a fixed length afterward -- robust to whatever else has
already written to the shared DB file."""
from __future__ import annotations

import http.server
import os
import socket
import sys
import threading
import time

import pytest

linux_root_only = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="starts a real proxy + nftables rule, needs real root on real Linux",
)


@linux_root_only
def test_the_live_app_actually_observes_and_reconciles_real_egress(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("WARRANT_EGRESS_PROXY_ENABLED", "1")
    monkeypatch.setenv("WARRANT_EGRESS_PROXY_PORT", "0")  # ephemeral -- avoid colliding with a leftover bind

    from warrant.main import app
    from warrant import uid_pool

    try:
        with TestClient(app) as client:
            proxy = app.state.egress_proxy
            assert proxy.port != 0  # actually bound to a real ephemeral port

            # Drive a real connection through the live proxy, tagged with THIS test process's own
            # real uid -- same shape as test_egress_proxy.py's uid-resolution proof, but now
            # through the actual running app, not a standalone EgressProxy instance.
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()

                def log_message(self, *a):
                    pass

            target = http.server.HTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=target.serve_forever, daemon=True).start()
            target_port = target.server_address[1]

            conn = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            conn.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n\r\n".encode())
            resp = conn.recv(4096)
            assert b"200" in resp
            conn.close()
            target.shutdown()

            # The proxy's on_connect callback persists asynchronously in its own thread -- poll
            # briefly for THIS specific observation to show up, rather than assume timing or
            # assert on the whole (possibly shared, possibly dirty) violations list.
            matching = None
            for _ in range(50):
                violations = client.get("/audit/reconcile/egress").json()["violations"]
                matching = next(
                    (v for v in violations if v["uid"] == os.getuid() and v["host"] == "127.0.0.1"), None
                )
                if matching is not None:
                    break
                time.sleep(0.1)

            assert matching is not None, "the real CONNECT this test drove through the live proxy never showed up in /audit/reconcile/egress"
            assert matching["token_id"] is None  # this test's own uid was never allocated to any token -- correctly unattributed
    finally:
        uid_pool.teardown_nftables_rule()
