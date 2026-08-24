"""A CONNECT-only forward proxy that tags every logged connection with the OS uid that made it --
the ground-truth half of the egress verifier (STATUS.md Phase 10). Linux-only (reads /proc).

Why TCP loopback + /proc lookup, not a Unix domain socket: a Unix socket makes uid capture trivial
(SO_PEERCRED, no /proc walking) but constrains every HTTP client that needs to reach the proxy to
support Unix-socket transports -- most don't, by default, without extra configuration on the
client side. A plain TCP loopback proxy works with any standard client that honors http_proxy/
https_proxy env vars, which is the actual requirement here (the agent process's own outbound
calls, via whatever HTTP client its own tooling happens to use) -- at the cost of walking
/proc/net/tcp -> inode -> /proc/<pid>/status for the uid, the same thing `ss`/`lsof` do internally.
Bounded, well-understood complexity, not an open research problem, and it doesn't push a
constraint onto code this project doesn't control.

This proxy only observes and relays. It never decides what's allowed -- enforcing that anything
reaches it at all is uid_pool.ensure_nftables_rule's job; reconciling what it saw against what
warrant actually authorized is egress_verifier.reconcile's job. Kept deliberately separate so no
single component both claims something is safe and acts on that claim -- the trust-handoff shape
this whole design is built to avoid (see the considerations doc).
"""
from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

CONNECT_TIMEOUT = 10.0
RELAY_BUFFER_SIZE = 65536


@dataclass(frozen=True)
class ObservedConnect:
    uid: Optional[int]  # None if the uid couldn't be resolved -- surfaced, never guessed at
    host: str
    port: int
    timestamp: datetime


def _read_uid_map() -> dict[int, int]:
    """inode -> uid, for every socket any process on this host currently owns. Reads /proc/net/tcp
    (local port table, gives inode) then /proc/*/fd (which pid owns which socket inode) then
    /proc/<pid>/status (that pid's real uid) -- the same three-file walk `ss -p` / `lsof` do."""
    inode_to_uid: dict[int, int] = {}
    pid_uid_cache: dict[str, int] = {}

    import os
    import re

    try:
        proc_pids = os.listdir("/proc")
    except OSError:
        # No /proc at all (non-Linux) -- deliberate, not an accident of the outer handler's broad
        # except OSError catching it: resolve_connecting_uid's docstring promises None, not a
        # crash, when resolution isn't possible, and this is the one call in this function that
        # wasn't already individually guarded that way.
        return inode_to_uid
    for pid_dir in proc_pids:
        if not pid_dir.isdigit():
            continue
        fd_dir = f"/proc/{pid_dir}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue

        socket_inodes = []
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            m = re.match(r"socket:\[(\d+)\]", target)
            if m:
                socket_inodes.append(int(m.group(1)))
        if not socket_inodes:
            continue

        if pid_dir not in pid_uid_cache:
            try:
                with open(f"/proc/{pid_dir}/status") as f:
                    for line in f:
                        if line.startswith("Uid:"):
                            # Uid: real effective saved filesystem -- real uid is the field that
                            # matters here (who the process runs as), not effective (e.g. a
                            # setuid binary mid-transition).
                            pid_uid_cache[pid_dir] = int(line.split()[1])
                            break
            except OSError:
                continue
        uid = pid_uid_cache.get(pid_dir)
        if uid is not None:
            for inode in socket_inodes:
                inode_to_uid[inode] = uid

    return inode_to_uid


def _local_port_to_inode(local_port: int) -> Optional[int]:
    """Scans /proc/net/tcp for the row whose local port matches, returns its inode. IPv4 loopback
    only -- this proxy binds 127.0.0.1, which is the only case that needs handling here."""
    try:
        with open("/proc/net/tcp") as f:
            lines = f.readlines()[1:]
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) < 10:
            continue
        local_addr = fields[1]
        _, port_hex = local_addr.split(":")
        if int(port_hex, 16) == local_port:
            return int(fields[9])
    return None


def resolve_connecting_uid(peer_port: int) -> Optional[int]:
    """Given the *client's own* ephemeral source port for this connection (as seen from our side
    of the accepted socket -- i.e. conn.getpeername()[1]), returns the uid of the process that
    owns it. None if it can't be resolved (the process exited between connect and lookup, or a
    permission gap on some /proc/<pid> this process can't read) -- surfaced as None, not silently
    treated as any specific uid; egress_verifier.reconcile treats an unresolved uid as evidence
    the way it treats any uid with no covering allocation, not as authorized-by-default.
    """
    inode = _local_port_to_inode(peer_port)
    if inode is None:
        return None
    return _read_uid_map().get(inode)


def _parse_connect_request(first_line: bytes) -> Optional[tuple[str, int]]:
    try:
        method, target, _version = first_line.decode("latin-1").strip().split(" ", 2)
    except ValueError:
        return None
    if method != "CONNECT":
        return None
    try:
        host, port_s = target.rsplit(":", 1)
        return host, int(port_s)
    except ValueError:
        return None


def _relay(a: socket.socket, b: socket.socket) -> None:
    """Bidirectional byte relay between two already-connected sockets, until either side closes."""
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(RELAY_BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


class EgressProxy:
    """A CONNECT-only proxy. on_connect fires once per successful CONNECT, before relaying begins,
    with the resolved (or unresolved) uid, the target host/port, and a UTC timestamp -- the raw
    material for a ProxyLogEntry, without this module needing to import egress_verifier's own
    types (kept decoupled: this observes, egress_verifier reconciles)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, on_connect: Optional[Callable[[ObservedConnect], None]] = None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(128)
        self._on_connect = on_connect
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1]

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _serve(self) -> None:
        while self._running:
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(CONNECT_TIMEOUT)
            _peer_ip, peer_port = conn.getpeername()
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            first_line, _, _rest = buf.partition(b"\r\n")
            parsed = _parse_connect_request(first_line)
            if parsed is None:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            host, port = parsed

            uid = resolve_connecting_uid(peer_port)
            if self._on_connect is not None:
                self._on_connect(ObservedConnect(uid=uid, host=host, port=port, timestamp=datetime.now(timezone.utc)))

            try:
                upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
            except OSError:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            conn.settimeout(None)
            upstream.settimeout(None)
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _relay(conn, upstream)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
