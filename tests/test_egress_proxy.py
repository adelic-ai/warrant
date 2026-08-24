"""Real-socket tests for the CONNECT proxy. The relay/parsing logic is platform-agnostic and runs
everywhere; uid resolution needs /proc, so those specific tests are Linux-only -- skipped, not
faked, on the Mac this was developed on. Validate for real against a real Linux host (colima) to
actually exercise the uid-resolution tests, not just confirm they're skipped."""
from __future__ import annotations

import http.server
import os
import socket
import sys
import threading
import urllib.request

import pytest

from warrant.egress_proxy import EgressProxy, ObservedConnect, _parse_connect_request

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="uid resolution reads /proc, Linux-only")


def _free_tcp_target():
    """A trivial HTTP server the proxy can CONNECT to, so relay tests don't depend on real
    internet egress."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_parses_a_connect_request_line():
    assert _parse_connect_request(b"CONNECT example.com:443 HTTP/1.1") == ("example.com", 443)


def test_rejects_a_non_connect_method():
    assert _parse_connect_request(b"GET / HTTP/1.1") is None


def test_relays_bytes_through_a_real_connect_tunnel():
    """Proves the proxy actually tunnels TCP, not just parses CONNECT -- fetch a real page through
    it via a real TLS-free HTTP-over-CONNECT round trip against a local target server."""
    target = _free_tcp_target()
    observed: list[ObservedConnect] = []
    proxy = EgressProxy(on_connect=observed.append)
    proxy.start()
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"127.0.0.1:{proxy.port}"})
        )
        # urllib's ProxyHandler only issues CONNECT for https targets; force it directly instead
        # for a plain-HTTP target by connecting through the tunnel by hand.
        conn = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        target_port = target.server_address[1]
        conn.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n\r\n".encode())
        resp = conn.recv(4096)
        assert b"200" in resp

        conn.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        body = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
        assert b"ok" in body
        assert len(observed) == 1
        assert observed[0].host == "127.0.0.1"
        assert observed[0].port == target_port
    finally:
        proxy.stop()
        target.shutdown()


@linux_only
def test_resolves_the_connecting_process_own_uid():
    """The clearest possible real-substrate check: connect to the proxy from this very process
    and confirm the uid it resolves is this process's own real uid -- not mocked, not assumed."""
    target = _free_tcp_target()
    observed: list[ObservedConnect] = []
    ready = threading.Event()

    def on_connect(entry: ObservedConnect) -> None:
        observed.append(entry)
        ready.set()

    proxy = EgressProxy(on_connect=on_connect)
    proxy.start()
    try:
        conn = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        target_port = target.server_address[1]
        conn.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n\r\n".encode())
        conn.recv(4096)
        ready.wait(timeout=5)
        conn.close()
    finally:
        proxy.stop()
        target.shutdown()

    assert len(observed) == 1
    assert observed[0].uid == os.getuid()
