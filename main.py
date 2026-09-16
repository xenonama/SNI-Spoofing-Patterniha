# main.py — SNI spoofing relay + WinDivert injector (v2, hardened).
from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import traceback
import uuid

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from utils.auto_state import get_auto_state, reset_auto_state
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector, SUPPORTED_METHODS, REAL_METHODS
from monitor_connection import reset_stats, get_snapshot, increment_failed, finish_failed, record_result
from monitor_connection import add_traffic, get_traffic_snapshot
from monitor_connection import register_active, update_active, unregister_active

log = logging.getLogger("main")

# Relay idle timeout: a direction that sees NO bytes for this long is closed
# (dead peer, firewall drop, killed process). Prevents leaked sockets,
# semaphore slots and connection entries. Configurable via IDLE_TIMEOUT_S.
DEFAULT_RELAY_IDLE_TIMEOUT_S = 300.0
RELAY_IDLE_TIMEOUT_S = DEFAULT_RELAY_IDLE_TIMEOUT_S

# Success is decided by bytes actually relayed, NOT by the handshake signal
# (t2a_event was unreliable in the Rust port: deadlocks, missed events ->
# "OK: 0" with a working tunnel). This mirrors the Rust fix.
SUCCESS_BYTES_THRESHOLD = 100


def get_exe_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def parse_args():
    p = argparse.ArgumentParser(description="SNI Spoofing injector")
    p.add_argument("--config", dest="config", default=None,
                   help="Path to config.json (default: next to script/exe)")
    p.add_argument("--log-level", default=os.environ.get("SNI_LOG", "INFO"),
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--self-test", action="store_true",
                   help="Run offline self-test (no Admin/WinDivert needed) and exit")
    return p.parse_known_args()[0]


def run_self_test(config_path: str) -> int:
    """Offline checks: config, packet template, scoreboard, split math. Returns exit code."""
    results: dict = {"checks": {}}
    ok_all = True

    def check(name: str, fn):
        nonlocal ok_all
        try:
            detail = fn()
            results["checks"][name] = {"ok": True, "detail": detail}
        except Exception as exc:
            ok_all = False
            results["checks"][name] = {"ok": False, "detail": str(exc)[:300]}

    def _cfg():
        cfg = load_config(config_path)
        return f"{len(cfg['ENDPOINTS'])} endpoint(s), {len(cfg['FAKE_SNIS'])} SNI(s), method={cfg['BYPASS_METHOD']}"

    def _template():
        rnd, sess, key = os.urandom(32), os.urandom(32), os.urandom(32)
        hello = ClientHelloMaker.get_client_hello_with(rnd, sess, b"example.com", key)
        r2, s2, sni2, k2 = ClientHelloMaker.parse_client_hello(hello)
        assert sni2 == "example.com" and r2 == rnd and s2 == sess and k2 == key
        assert len(hello) == 517
        return f"ClientHello {len(hello)}B round-trip OK"

    def _score():
        reset_stats()
        record_result("1.1.1.1:443", "a.com", True)
        record_result("1.1.1.1:443", "a.com", False)
        snap = get_snapshot()
        assert snap["success_rate"] == 0.0  # counters untouched by record_result
        from monitor_connection import get_scoreboard
        board = get_scoreboard()
        assert board["endpoints"] and board["endpoints"][0]["key"] == "1.1.1.1:443"
        reset_stats()
        return "scoreboard OK"

    def _split():
        from fake_tcp import split_plan
        s1, s2 = split_plan(1000, 517, 258)
        assert s2 == (s1 + 258) & 0xFFFFFFFF
        assert s1 == (1001 - 517) & 0xFFFFFFFF
        return "split math OK"

    def _smart():
        from utils import smart, config_manager
        from fake_tcp import resolve_method
        assert isinstance(smart.SUGGESTED_SNIS, list) and len(smart.SUGGESTED_SNIS) > 3
        assert config_manager.validate(config_manager.migrate({})) == []
        bad = {"CONNECT_IP": "", "CONNECT_PORT": 443, "ENDPOINTS": [],
               "FAKE_SNI": "", "FAKE_SNIS": []}
        assert config_manager.validate(config_manager.migrate(bad)) != []
        assert config_manager.validate(config_manager.migrate({"BYPASS_METHOD": "auto"})) == []
        assert resolve_method("auto") in REAL_METHODS
        assert resolve_method("split_seq") == "split_seq"
        # split_seq re-checks monitor mid-send while holding the per-conn
        # lock (fake_tcp) — the lock must be re-entrant or split deadlocks.
        import socket as _sock
        from monitor_connection import MonitorConnection
        _mc = MonitorConnection(_sock.socket(), "127.0.0.1", "127.0.0.1", 1, 443)
        try:
            acquired = _mc.thread_lock.acquire(blocking=False)
            assert acquired, "conn lock unavailable"
            assert _mc.thread_lock.acquire(blocking=False), "conn lock not re-entrant (split_seq would deadlock)"
            _mc.thread_lock.release()
            _mc.thread_lock.release()
        finally:
            try:
                _mc.sock.close()
            except Exception:
                pass
        assert smart.rank_snis("127.0.0.1", 9, []) == []
        return "helpers OK"

    def _auto_rotation():
        from utils.auto_state import AutoState
        from fake_tcp import resolve_method as rm
        # Deterministic window: tiny thresholds, fake clock.
        clock = [100.0]
        st = AutoState(max_failures=3, max_attempts=10, window_s=60.0,
                       clock=lambda: clock[0])
        # Sticky: same method repeated within the window.
        first = st.next_method()
        assert all(st.next_method() == first for _ in range(5)), "not sticky"
        # 3 failures trigger rotation.
        st.note_failure(); st.note_failure(); st.note_failure()
        second = st.next_method()
        assert second != first, "3 failures did not rotate"
        assert st.stats()["attempts"] == 1 and st.stats()["failures"] == 0
        # 10 attempts trigger rotation.
        for _ in range(9):
            st.next_method()
        third = st.next_method()
        assert third != second, "10 attempts did not rotate"
        # 60s elapsed triggers rotation.
        clock[0] += 61.0
        fourth = st.next_method()
        assert fourth != third, "60s elapsed did not rotate"
        # Singleton integration: resolve_method("auto") is sticky and real.
        reset_auto_state()
        m1 = rm("auto")
        assert m1 in REAL_METHODS
        assert rm("auto") == m1 and rm("auto") == m1, "auto not sticky via resolve_method"
        assert rm("split_seq") == "split_seq", "real method must bypass auto"
        reset_auto_state()
        return "auto rotation OK (3-fail / 10-try / 60s all rotate, never to same)"

    def _bytes_decision():
        from monitor_connection import get_traffic_snapshot
        reset_stats()
        before = get_traffic_snapshot()
        # The threshold logic itself (pure math used by handle()):
        cases = [(0, False), (99, False), (100, True), (1000, True)]
        for moved, expect_ok in cases:
            assert (moved >= SUCCESS_BYTES_THRESHOLD) == expect_ok, \
                "threshold wrong at %d bytes" % moved
        # record_result feeds auto-state only when auto_resolved=True.
        reset_auto_state("padding")
        record_result("9.9.9.9:443", "t.io", True, method="padding", auto_resolved=True)
        record_result("9.9.9.9:443", "t.io", False, method="padding", auto_resolved=True)
        assert get_auto_state().stats()["successes"] == 1
        assert get_auto_state().stats()["failures"] == 1
        # ...and auto_resolved=False leaves it untouched.
        record_result("9.9.9.9:443", "t.io", False, method="padding")
        assert get_auto_state().stats()["failures"] == 1
        assert before == get_traffic_snapshot()
        reset_stats()
        reset_auto_state()
        return "bytes decision OK (0/99=fail, 100/1000=ok; auto reporting wired)"

    def _active_list():
        from monitor_connection import (register_active, update_active,
                                        unregister_active, get_active_list)
        assert get_active_list() == []
        a = register_active("a", "1.1.1.1:443", "x.com", "split_seq")
        b = register_active("b", "2.2.2.2:443", "y.com", "padding")
        c = register_active("c", "3.3.3.3:443", "z.com", "fragmented")
        assert len(get_active_list()) == 3
        update_active(b, up=10, down=20, state="relaying")
        rows = {r["id"]: r for r in get_active_list()}
        assert rows["b"]["up"] == 10 and rows["b"]["down"] == 20
        assert rows["b"]["state"] == "relaying"
        assert rows["b"]["sni_hash"].startswith("sni#"), "sni_hash missing"
        unregister_active(a)
        assert len(get_active_list()) == 2
        unregister_active(b); unregister_active(c)
        assert get_active_list() == []
        return "active list OK (register/update/unregister)"

    def _idle_timeout():
        import asyncio

        async def _run():
            # Mock socket pair: recv() blocks until closed -> idle timeout fires.
            s1, s2 = socket.socketpair()
            s1.setblocking(False)
            s2.setblocking(False)
            closed = {"n": 0}

            class PeerTask:
                def done(self):
                    return False

                def cancel(self):
                    closed["n"] += 1

            t0 = time.monotonic()
            await relay_main_loop(s1, s2, PeerTask(), b"", "up",
                                  idle_timeout=0.5, conn_id="")
            took = time.monotonic() - t0
            assert 0.3 < took < 2.0, "idle timeout did not fire in ~0.5s (took %.2fs)" % took
            assert closed["n"] == 1, "peer task not cancelled after timeout"
            try:
                s1.close()
                s2.close()
            except Exception:
                pass

        asyncio.run(_run())
        # Config plumbing: default valid, bounds enforced.
        from utils import config_manager as _cm
        assert _cm.validate(_cm.migrate({"IDLE_TIMEOUT_S": 300.0})) == []
        assert _cm.validate(_cm.migrate({"IDLE_TIMEOUT_S": 0.0})) != []
        assert _cm.validate(_cm.migrate({"IDLE_TIMEOUT_S": 3601.0})) != []
        return "idle timeout OK (fires at ~timeout, cancels peer, config-validated)"

    def _relay_zero_copy():
        import asyncio
        from monitor_connection import get_traffic_snapshot, get_active_list
        reset_stats()
        reset_auto_state()

        async def _run():
            # Real TCP socketpair THROUGH relay_main_loop: validates the
            # zero-copy recv_into path, first-chunk prefix splicing, traffic
            # accounting and EOF handling end to end.
            from monitor_connection import register_active, unregister_active
            loop = asyncio.get_running_loop()
            a, b = socket.socketpair()
            c, d = socket.socketpair()
            # ALL four sockets are driven through the event loop: blocking
            # sendall/recv here would stall the loop and starve the relay task.
            for s in (a, b, c, d):
                s.setblocking(False)
                tune_relay_socket(s)
            payload = bytes(range(256)) * 400  # 102_400 B: > 1 full 64 KiB chunk
            register_active("rz", "1.2.3.4:1", "t.io", "padding")
            closed = {"n": 0}

            class PeerTask:
                def done(self):
                    return False

                def cancel(self):
                    closed["n"] += 1

            prefix = b"PFX"
            up_task = asyncio.create_task(
                relay_main_loop(a, c, PeerTask(), prefix, "up",
                                idle_timeout=2.0, conn_id="rz"))
            await asyncio.sleep(0.05)
            await loop.sock_sendall(b, payload)
            b.shutdown(socket.SHUT_WR)  # EOF after payload -> relay drains
            got = bytearray()
            need = len(prefix) + len(payload)
            while len(got) < need:
                chunk = await asyncio.wait_for(loop.sock_recv(d, 65536), timeout=3.0)
                if not chunk:
                    break
                got.extend(chunk)
            assert bytes(got[:len(prefix)]) == prefix, "prefix not spliced"
            assert bytes(got[len(prefix):]) == payload, "payload corrupted in zero-copy relay"
            await asyncio.wait_for(up_task, timeout=3.0)
            total = len(prefix) + len(payload)  # prefix counts as relayed bytes
            up_b, down_b = get_traffic_snapshot()
            assert up_b == total and down_b == 0, \
                "traffic accounting wrong: up=%d down=%d" % (up_b, down_b)
            rows = {r["id"]: r for r in get_active_list()}
            rz = rows.get("rz")
            assert rz is not None, "active entry lost after relay"
            assert rz["up"] == total, \
                "batched active-list byte flush wrong: %r" % rz["up"]
            assert rz["state"] == "closing", "final state not flushed"
            unregister_active("rz")
            for s in (a, b, c, d):
                try:
                    s.close()
                except Exception:
                    pass

        asyncio.run(_run())
        reset_stats()
        reset_auto_state()
        return "relay zero-copy OK (prefix + %d KiB byte-exact, EOF, accounting)" % 100

    def _rank_endpoints():
        from utils.smart import rank_endpoints
        # Empty list must not raise.
        assert rank_endpoints([]) == []
        assert rank_endpoints([{}, {"ip": "", "port": 1}]) == []
        # Invalid IPs / ports must not raise; unreachable -> ok=False.
        res = rank_endpoints([{"ip": "999.999.999.999", "port": 443},
                              {"ip": "127.0.0.1", "port": 1}],
                             timeout=0.3, tries=1)
        assert isinstance(res, list) and len(res) >= 1
        assert all(isinstance(r, dict) and "ok" in r for r in res)
        return "rank_endpoints OK (empty + invalid inputs safe)"

    check("config", _cfg)
    check("packet_template", _template)
    check("scoreboard", _score)
    check("split_plan", _split)
    check("helpers", _smart)
    check("auto_rotation", _auto_rotation)
    check("bytes_decision", _bytes_decision)
    check("active_list", _active_list)
    check("idle_timeout", _idle_timeout)
    check("relay_zero_copy", _relay_zero_copy)
    check("rank_endpoints", _rank_endpoints)
    results["ok"] = ok_all
    print(json.dumps(results, indent=2), flush=True)
    return 0 if ok_all else 1


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    # --- v1 -> v2 migration -------------------------------------------------
    # v1: {LISTEN_HOST, LISTEN_PORT, CONNECT_IP, CONNECT_PORT, FAKE_SNI}
    # v2 adds: ENDPOINTS[], FAKE_SNIS[], BYPASS_METHOD, HANDSHAKE_TIMEOUT, ...
    endpoints = []
    if isinstance(cfg.get("ENDPOINTS"), list) and cfg["ENDPOINTS"]:
        for e in cfg["ENDPOINTS"]:
            if isinstance(e, dict) and e.get("ip"):
                endpoints.append({"ip": str(e["ip"]).strip(),
                                  "port": int(e.get("port", cfg.get("CONNECT_PORT", 443)))})
            elif isinstance(e, str):
                endpoints.append({"ip": e.strip(), "port": int(cfg.get("CONNECT_PORT", 443))})
    elif cfg.get("CONNECT_IP"):
        endpoints.append({"ip": str(cfg["CONNECT_IP"]).strip(),
                          "port": int(cfg.get("CONNECT_PORT", 443))})
    if not endpoints:
        raise ValueError("No endpoints configured (CONNECT_IP or ENDPOINTS required)")

    fake_snis: list[str] = []
    if isinstance(cfg.get("FAKE_SNIS"), list) and cfg["FAKE_SNIS"]:
        fake_snis = [str(s).strip() for s in cfg["FAKE_SNIS"] if str(s).strip()]
    elif cfg.get("FAKE_SNI"):
        fake_snis = [str(cfg["FAKE_SNI"]).strip()]
    if not fake_snis:
        raise ValueError("No FAKE_SNI configured")

    method = str(cfg.get("BYPASS_METHOD", "auto")).strip() or "auto"
    if method not in SUPPORTED_METHODS:
        raise ValueError(f"Unsupported BYPASS_METHOD={method!r} (expected one of {SUPPORTED_METHODS})")

    out = {
        "LISTEN_HOST": str(cfg.get("LISTEN_HOST", "0.0.0.0")),
        "LISTEN_PORT": int(cfg.get("LISTEN_PORT", 40443)),
        "ENDPOINTS": endpoints,
        "FAKE_SNIS": fake_snis,
        "BYPASS_METHOD": method,
        "HANDSHAKE_TIMEOUT": float(cfg.get("HANDSHAKE_TIMEOUT", 2.0)),
        "MAX_CONNECTIONS": int(cfg.get("MAX_CONNECTIONS", 200)),
        "FAKE_DELAY": float(cfg.get("FAKE_DELAY", 0.001)),
        "IDLE_TIMEOUT_S": float(cfg.get("IDLE_TIMEOUT_S", DEFAULT_RELAY_IDLE_TIMEOUT_S)),
        "DATA_MODE": "tls",
    }
    return out


args = parse_args()
logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")


class _OverlappedCancelFilter(logging.Filter):
    """Drop Windows asyncio noise: 'Cancelling an overlapped future failed'
    with WinError 6. Happens when relay sockets close while a sock_recv /
    sock_accept is still pending — harmless, but spams the GUI console."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage().lower()
        except Exception:
            return True
        if "cancelling an overlapped future failed" in msg:
            return False
        if "overlappedfuture" in msg and ("winerror 6" in msg or "handle is invalid" in msg):
            return False
        return True


try:
    logging.getLogger("asyncio").addFilter(_OverlappedCancelFilter())
except Exception:
    pass
config_path = os.path.abspath(args.config) if args.config else os.path.join(get_exe_dir(), "config.json")
if args.self_test:
    # --self-test never touches the real config: it must pass on a clean
    # checkout / missing config.json. Real startup keeps strict load-or-exit.
    config = {"ENDPOINTS": [{"ip": "127.0.0.1", "port": 443}],
              "FAKE_SNIS": ["example.com"],
              "LISTEN_HOST": "127.0.0.1",
              "LISTEN_PORT": 0,
              "BYPASS_METHOD": "auto",
              "HANDSHAKE_TIMEOUT": 2.0,
              "MAX_CONNECTIONS": 200,
              "FAKE_DELAY": 0.001,
              "IDLE_TIMEOUT_S": DEFAULT_RELAY_IDLE_TIMEOUT_S}
else:
    try:
        config = load_config(config_path)
    except Exception as exc:
        print(f"FATAL: cannot load config {config_path}: {exc}", flush=True)
        sys.exit(2)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
ENDPOINTS: list[dict] = config["ENDPOINTS"]
FAKE_SNIS: list[str] = config["FAKE_SNIS"]
BYPASS_METHOD = config["BYPASS_METHOD"]
HANDSHAKE_TIMEOUT = config["HANDSHAKE_TIMEOUT"]
MAX_CONNECTIONS = config["MAX_CONNECTIONS"]
FAKE_DELAY = config["FAKE_DELAY"]
IDLE_TIMEOUT_S = config["IDLE_TIMEOUT_S"]
RELAY_IDLE_TIMEOUT_S = IDLE_TIMEOUT_S
DATA_MODE = "tls"

# Round-robin endpoint picker with failover in handle().
_endpoint_cycle = itertools.cycle(range(len(ENDPOINTS)))
_cycle_lock = threading.Lock()


def pick_endpoints() -> list[dict]:
    """Return endpoints ordered for this connection (round-robin start, then rest)."""
    with _cycle_lock:
        start = next(_endpoint_cycle)
    return [ENDPOINTS[(start + i) % len(ENDPOINTS)] for i in range(len(ENDPOINTS))]


def pick_sni() -> str:
    # Rotate SNIs to spread fingerprint; random choice per connection.
    import random
    return random.choice(FAKE_SNIS)


def ep_key(ep: dict) -> str:
    return f"{ep['ip']}:{ep['port']}"


def note_fail(conn, endpoint: str, sni: str, reason: str = ""):
    """Record a failed attempt without double-counting injector stats.

    If the injector already counted this connection (finish_failed via
    on_unexpected_packet), only the scoreboard needs updating. Otherwise
    the engine owns the failure counter. `reason` is only for DEBUG logs.
    """
    try:
        method = getattr(conn, "bypass_method", "") or ""
    except Exception:
        method = ""
    if reason:
        try:
            log.debug("note_fail %s %s: %s", endpoint, method, reason)
        except Exception:
            pass
    # Feed the sticky auto rotation: this connection's method came from the
    # auto window whenever the configured method was "auto".
    auto_resolved = (BYPASS_METHOD == "auto")
    record_result(endpoint, sni, False, method=method, auto_resolved=auto_resolved)
    try:
        if conn is not None and getattr(conn, "counted", False):
            conn.monitor = False
            finish_failed()
            conn.counted = False
        else:
            increment_failed()
    except Exception:
        pass


INTERFACE_IPV4 = get_default_interface_ipv4(ENDPOINTS[0]["ip"])
if not INTERFACE_IPV4:
    print("FATAL: cannot determine default interface IPv4 (no route?)", flush=True)
    sys.exit(2)

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}
shutdown_event = threading.Event()
conn_sem = threading.BoundedSemaphore(MAX_CONNECTIONS)


def _drop_conn(conn) -> None:
    """Idempotent evict: clear monitor flag and remove dict entry. Never raises."""
    if conn is None:
        return
    try:
        conn.monitor = False
    except Exception:
        pass
    try:
        fake_injective_connections.pop(getattr(conn, "id", None), None)
    except Exception:
        pass


def _close_sock_quiet(sock) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


async def connection_reaper(interval: float = 60.0, max_age: float = 120.0):
    """Safety net: evict stale monitor=False entries older than max_age.

    Normal paths already pop the dict in handle()/_close_conn; this only
    catches entries missed due to an exception between register and pop.
    Success paths pop within milliseconds, so a 120s threshold never
    touches live handshakes.
    """
    while not shutdown_event.is_set():
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
        try:
            now = time.time()
            try:
                items = list(fake_injective_connections.items())
            except Exception:
                continue
            stale = []
            for key, c in items:
                try:
                    if not getattr(c, "monitor", True) and \
                            (now - getattr(c, "created_at", now)) > max_age:
                        stale.append(key)
                except Exception:
                    continue
            for key in stale:
                try:
                    fake_injective_connections.pop(key, None)
                except Exception:
                    pass
            if stale:
                log.debug("reaped %d stale connection(s)", len(stale))
        except asyncio.CancelledError:
            break
        except Exception:
            log.debug("reaper error", exc_info=True)
            continue


def set_keepalive(sock: socket.socket):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for level, opt, val in (
        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPIDLE", None), 11),
        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPINTVL", None), 2),
        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPCNT", None), 3),
    ):
        if opt is None:
            continue
        try:
            sock.setsockopt(level, opt, val)
        except OSError:
            pass


RELAY_RECV_BUF_SIZE = 65575  # 64 KiB + slack recv window (same as old literal)
RELAY_SOCK_BUFSIZE = 262144  # 256 KiB kernel send/recv buffers for burst throughput
# Active-list lock is touched every N relay chunks (GUI live-byte granularity
# vs lock contention trade-off). 16 chunks ~= 1 MiB at full 64 KiB chunks.
RELAY_ACTIVE_FLUSH_CHUNKS = 16


def tune_relay_socket(sock: socket.socket):
    """Low-latency + throughput tuning for relay sockets. Best effort."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    for opt in (socket.SO_SNDBUF, socket.SO_RCVBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, RELAY_SOCK_BUFSIZE)
        except OSError:
            pass


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                           first_prefix_data: bytes, direction: str = "",
                           idle_timeout: float | None = None,
                           conn_id: str = ""):
    """Forward sock_1 -> sock_2. direction 'up' (clients->net) / 'down' feeds the traffic tracker.

    Performance notes (hot path — runs per 64 KiB chunk, both directions of
    every connection):
    - Zero-copy receive via loop.sock_recv_into() into ONE reusable buffer,
      then send a memoryview slice. No per-chunk bytes objects are allocated
      (the old loop allocated per chunk: recv() bytes + prefix concat).
    - Active-list updates are batched: the stats lock is touched every
      RELAY_ACTIVE_FLUSH_CHUNKS chunks (and once on exit) instead of per chunk.
      Traffic totals (add_traffic) still update per chunk.

    Each direction has its own idle timeout: if THIS side sees no bytes for
    `idle_timeout` seconds the loop breaks and cleanup runs (the peer task is
    cancelled as before). A silently dead peer can no longer pin the socket,
    the semaphore slot and the connection entry forever.
    """
    loop = asyncio.get_running_loop()
    if idle_timeout is None:
        idle_timeout = RELAY_IDLE_TIMEOUT_S
    # Zero-copy receive: Proactor (Windows) and epoll (Linux) loops both expose
    # sock_recv_into. Fall back silently to sock_recv if unavailable.
    _recv_into = getattr(loop, "sock_recv_into", None)
    buf = bytearray(RELAY_RECV_BUF_SIZE)
    _prefix = bytes(first_prefix_data)
    chunk_count = 0
    pending_up = 0
    pending_down = 0
    try:
        while True:
            try:
                try:
                    if _recv_into is not None:
                        # NOTE: loop.sock_recv_into is a BOUND method —
                        # call it as (sock, buffer), not (loop, sock, buffer).
                        nread = await asyncio.wait_for(
                            _recv_into(sock_1, buf), timeout=idle_timeout)
                    else:
                        data = await asyncio.wait_for(loop.sock_recv(sock_1, RELAY_RECV_BUF_SIZE),
                                                      timeout=idle_timeout)
                        nread = len(data)
                except asyncio.TimeoutError:
                    try:
                        log.debug("relay idle timeout after %gs, closing connection %s (%s)",
                                  idle_timeout, conn_id or "?", direction or "?")
                    except Exception:
                        pass
                    break
                if not nread:
                    raise ConnectionError("eof")
                chunk_count += 1
                # Zero-copy send: view into the reusable buffer. The prefix
                # (pre-relay leftover bytes) is spliced in ONLY on the first
                # chunk, then the fast path resumes.
                if _prefix:
                    data = _prefix + bytes(memoryview(buf)[:nread])
                    _prefix = b""
                    n = len(data)
                    await loop.sock_sendall(sock_2, data)
                else:
                    n = nread
                    await loop.sock_sendall(sock_2, memoryview(buf)[:nread])
                if direction == "up":
                    add_traffic(up=n)
                elif direction == "down":
                    add_traffic(down=n)
                if conn_id:
                    # Batch the lock: accumulate deltas, flush every N chunks.
                    if direction == "up":
                        pending_up += n
                    else:
                        pending_down += n
                    if chunk_count % RELAY_ACTIVE_FLUSH_CHUNKS == 0:
                        update_active(conn_id, up=pending_up, down=pending_down,
                                      state="relaying")
                        pending_up = 0
                        pending_down = 0
            except (ConnectionError, OSError):
                break
            except asyncio.CancelledError:
                break
            except Exception:
                log.debug("relay error", exc_info=True)
                break
    finally:
        if conn_id:
            update_active(conn_id, up=pending_up, down=pending_down,
                          state="closing")
        for s in (sock_1, sock_2):
            try:
                s.close()
            except Exception:
                pass
        if peer_task and not peer_task.done():
            peer_task.cancel()


async def try_connect(loop: asyncio.AbstractEventLoop, sock: socket.socket,
                     ordered: list[dict]) -> dict | None:
    """Try endpoints in order; return the one that connected, else None."""
    last_err: Exception | None = None
    for ep in ordered:
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ep["ip"], ep["port"])), timeout=5)
            return ep
        except Exception as exc:
            last_err = exc
            continue
    log.debug("all endpoints failed: %s", last_err)
    return None


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    loop = asyncio.get_running_loop()
    if not conn_sem.acquire(blocking=False):
        log.warning("connection limit reached, dropping %s", incoming_remote_addr)
        try:
            incoming_sock.close()
        except Exception:
            pass
        increment_failed()
        return
    outgoing_sock: socket.socket | None = None
    conn: FakeInjectiveConnection | None = None
    sni_str = ""
    cur_ep_key = ""
    active_id = ""          # uuid key into the GUI active-connections list
    bytes_before = (0, 0)   # traffic totals captured right before the relay
    relay_started = False
    handshake_ok = False
    try:
        sni_str = pick_sni()
        fake_sni = sni_str.encode()
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), fake_sni, os.urandom(32))
        else:
            log.error("impossible DATA_MODE=%s", DATA_MODE)
            incoming_sock.close()
            return

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        tune_relay_socket(outgoing_sock)
        try:
            outgoing_sock.bind((INTERFACE_IPV4, 0))
        except OSError as exc:
            log.error("bind failed: %s", exc)
            incoming_sock.close()
            outgoing_sock.close()
            return
        set_keepalive(outgoing_sock)
        try:
            src_port = outgoing_sock.getsockname()[1]
        except OSError:
            incoming_sock.close()
            outgoing_sock.close()
            return

        ordered = pick_endpoints()
        # Pre-register with the FIRST endpoint; on failover we re-key below.
        first = ordered[0]
        conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, first["ip"], src_port, first["port"],
                                       fake_data, BYPASS_METHOD, incoming_sock)
        fake_injective_connections[conn.id] = conn
        # Show the resolved wire method (not "auto") + hashed SNI in the GUI.
        active_id = register_active(uuid.uuid4().hex, ep_key(first), sni_str,
                                    getattr(conn, "bypass_method", "") or BYPASS_METHOD,
                                    state="connecting")

        connected_ep = await try_connect(loop, outgoing_sock, ordered)
        if connected_ep is None:
            conn.monitor = False
            fake_injective_connections.pop(conn.id, None)
            note_fail(None, ep_key(first), sni_str, reason="all endpoints refused/timeout")
            outgoing_sock.close()
            incoming_sock.close()
            return
        cur_ep_key = ep_key(connected_ep)
        if connected_ep is not first:
            # Re-key dict to the real endpoint so WinDivert filter matches.
            fake_injective_connections.pop(conn.id, None)
            conn.dst_ip = connected_ep["ip"]
            conn.dst_port = connected_ep["port"]
            conn.id = (conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port)
            fake_injective_connections[conn.id] = conn
            update_active(active_id, endpoint=cur_ep_key)
        update_active(active_id, state="handshake")

        if BYPASS_METHOD in SUPPORTED_METHODS:
            try:
                await asyncio.wait_for(conn.t2a_event.wait(), HANDSHAKE_TIMEOUT)
                if conn.t2a_msg != "fake_data_ack_recv":
                    raise ConnectionError(f"bypass failed: {conn.t2a_msg or 'timeout'}")
            except Exception as exc:
                conn.monitor = False
                fake_injective_connections.pop(conn.id, None)
                # Injector already recorded stats via finish_failed() when it
                # saw the unexpected packet; note_fail() avoids double count.
                note_fail(conn, cur_ep_key or ep_key(first), sni_str, reason=str(exc))
                try:
                    outgoing_sock.close()
                except Exception:
                    pass
                try:
                    incoming_sock.close()
                except Exception:
                    pass
                return
            else:
                # Advisory only: t2a no longer decides success/fail — bytes do.
                handshake_ok = True
        else:
            log.error("unknown bypass method: %s", BYPASS_METHOD)
            conn.monitor = False
            fake_injective_connections.pop(conn.id, None)
            note_fail(conn, cur_ep_key or ep_key(first), sni_str,
                      reason="unsupported bypass method")
            outgoing_sock.close()
            incoming_sock.close()
            return

        conn.monitor = False
        fake_injective_connections.pop(conn.id, None)

        # ---- success = bytes moved during the relay (Rust-reference fix).
        # Capture the traffic totals RIGHT BEFORE the relay starts; the
        # per-connection delta (not global counters) decides the outcome.
        bytes_before = get_traffic_snapshot()
        relay_started = True
        update_active(active_id, state="relaying")

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b"", "down",
                            idle_timeout=RELAY_IDLE_TIMEOUT_S, conn_id=active_id))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"", "up",
                              idle_timeout=RELAY_IDLE_TIMEOUT_S, conn_id=active_id)
    except Exception:
        log.error("handle error", exc_info=True)
        try:
            incoming_sock.close()
        except Exception:
            pass
        if outgoing_sock is not None:
            try:
                outgoing_sock.close()
            except Exception:
                pass
        if conn is not None:
            try:
                if conn.monitor:
                    note_fail(conn, cur_ep_key, sni_str)
                conn.monitor = False
                fake_injective_connections.pop(conn.id, None)
            except Exception:
                pass
    finally:
        # ---- bytes-moved decision (runs on EVERY path: normal EOF, error,
        # cancellation, idle timeout) ----
        try:
            if relay_started:
                up_b, down_b = get_traffic_snapshot()
                moved = (up_b - bytes_before[0]) + (down_b - bytes_before[1])
                ok = moved >= SUCCESS_BYTES_THRESHOLD
                method_used = getattr(conn, "bypass_method", "") or "" if conn else ""
                if ok:
                    record_result(cur_ep_key, sni_str, True, method=method_used,
                                  auto_resolved=(BYPASS_METHOD == "auto"))
                elif not handshake_ok:
                    # Pre-relay handshake failures already reported via
                    # note_fail(); do not double count them here.
                    pass
                else:
                    record_result(cur_ep_key, sni_str, False, method=method_used,
                                  auto_resolved=(BYPASS_METHOD == "auto"))
                log.debug("conn %s: moved=%d ok=%s", active_id or "?", moved,
                          "yes" if ok else "no")
            elif handshake_ok and conn is not None:
                # Handshake passed but the relay never began (rare exception
                # window): bytes are 0 -> count as fail for the scoreboard.
                try:
                    record_result(cur_ep_key, sni_str, False,
                                  method=getattr(conn, "bypass_method", "") or "",
                                  auto_resolved=(BYPASS_METHOD == "auto"))
                except Exception:
                    pass
            elif not handshake_ok and conn is not None and conn.monitor:
                # Exception between register and the handshake wait: count it.
                note_fail(conn, cur_ep_key or "", sni_str, reason="error before handshake wait")
        except Exception:
            pass
        if active_id:
            unregister_active(active_id)
        # Safety net: every path (return, exception, cancellation) evicts
        # the dict entry and releases sockets. Manual pops above are
        # idempotent, so double-pop here is harmless but closes the leak
        # when an exception happens before/after `conn` is assigned.
        _drop_conn(conn)
        _close_sock_quiet(outgoing_sock)
        # incoming_sock is owned by handle() until relay finishes; by the
        # time finally runs the relay is done (or never started), so this
        # is safe and covers early-error paths that forgot to close it.
        # Note: relay_main_loop already closes both sockets on success.
        try:
            incoming_sock.close()
        except Exception:
            pass
        try:
            conn_sem.release()
        except ValueError:
            pass
        # Safety net: every path (return, exception, cancellation) evicts
        # the dict entry and releases sockets. Manual pops above are
        # idempotent, so double-pop here is harmless but closes the leak
        # when an exception happens before/after `conn` is assigned.
        _drop_conn(conn)
        _close_sock_quiet(outgoing_sock)
        # incoming_sock is owned by handle() until relay finishes; by the
        # time finally runs the relay is done (or never started), so this
        # is safe and covers early-error paths that forgot to close it.
        # Note: relay_main_loop already closes both sockets on success.
        try:
            incoming_sock.close()
        except Exception:
            pass
        try:
            conn_sem.release()
        except ValueError:
            pass


async def stats_reporter(interval: float = 2.0):
    failures = 0
    while True:
        try:
            print(json.dumps(get_snapshot()), flush=True)
            failures = 0
        except (BrokenPipeError, OSError):
            # GUI is gone and the stdout pipe has no readers: exit instead of
            # lingering headless forever as an orphan holding the port.
            failures += 1
            if failures >= 3:
                try:
                    shutdown_event.set()
                except Exception:
                    pass
                os._exit(3)
        except Exception:
            pass
        await asyncio.sleep(interval)


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as exc:
        print(f"FATAL: cannot bind {LISTEN_HOST}:{LISTEN_PORT}: {exc}", flush=True)
        sys.exit(2)
    set_keepalive(mother_sock)
    mother_sock.listen(256)
    loop = asyncio.get_running_loop()

    print(f"Server started on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"Fake SNIs: {', '.join(FAKE_SNIS)}", flush=True)
    print(f"Endpoints: {', '.join(e['ip'] + ':' + str(e['port']) for e in ENDPOINTS)}", flush=True)
    print(f"Bypass method: {BYPASS_METHOD} (timeout={HANDSHAKE_TIMEOUT}s, max_conn={MAX_CONNECTIONS})", flush=True)
    if BYPASS_METHOD == "auto":
        print(f"Auto-rotate pool: {', '.join(REAL_METHODS)}", flush=True)

    asyncio.create_task(stats_reporter())
    asyncio.create_task(connection_reaper(interval=60.0, max_age=120.0))

    while not shutdown_event.is_set():
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            if shutdown_event.is_set():
                break
            log.warning("accept failed: %s", exc)
            await asyncio.sleep(0.05)
            continue
        incoming_sock.setblocking(False)
        tune_relay_socket(incoming_sock)
        set_keepalive(incoming_sock)
        asyncio.create_task(handle(incoming_sock, addr))

    try:
        mother_sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    def signal_handler(sig, frame):
        print("\nShutting down...", flush=True)
        shutdown_event.set()

    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    except Exception:
        pass

    # Self-test runs AFTER all module defs (it exercises relay_main_loop)
    # and BEFORE anything privileged (no Admin/WinDivert/mutex needed).
    if args.self_test:
        sys.exit(run_self_test(config_path))

    reset_stats()

    # Single-instance guard per listen port (Windows): SO_REUSEADDR lets a
    # second backend bind the SAME port silently, stacking orphans that steal
    # traffic while the GUI tracks only the newest one (frozen-looking
    # tracker). Fail fast with a clear message instead.
    if sys.platform == "win32":
        try:
            import ctypes as _ctypes
            _k32 = _ctypes.windll.kernel32
            _mutex_name = "SNI-Spoofer-Backend-%d" % int(LISTEN_PORT)
            _handle = _k32.CreateMutexW(None, True, _mutex_name)
            _err = _k32.GetLastError()
            if not _handle or _err == 183:  # ERROR_ALREADY_EXISTS
                try:
                    if _handle:
                        _k32.CloseHandle(_handle)
                except Exception:
                    pass
                print("FATAL: another SNI backend is already running for port %d. "
                      "Stop it first (or kill stale sni-backend.exe processes) "
                      "before starting a new one." % int(LISTEN_PORT), flush=True)
                sys.exit(2)
            # Keep the handle open until process exit (do NOT close it).
            globals()["_single_instance_mutex"] = _handle
        except SystemExit:
            raise
        except Exception:
            pass

    filt = "tcp and (" + " or ".join(
        f"(ip.SrcAddr == {INTERFACE_IPV4} and ip.DstAddr == {e['ip']})"
        f" or (ip.SrcAddr == {e['ip']} and ip.DstAddr == {INTERFACE_IPV4})"
        for e in ENDPOINTS) + ")"
    injector = FakeTcpInjector(filt, fake_injective_connections, fake_delay=FAKE_DELAY)
    # Pre-flight WinDivert open: fail fast with a clear message instead of
    # starting the relay with a dead injector thread (silent bypass failure).
    def _windivert_hint(exc: BaseException) -> str:
        txt = str(exc)
        low = txt.lower()
        code = getattr(exc, "winerror", None)
        if code == 1058 or "1058" in txt or "1058" in low:
            return (
                "FATAL: WinDivert open failed: [WinError 1058] driver service cannot start.\n"
                "This happens even as Administrator when the driver is DISABLED or BLOCKED.\n"
                "Fix (run in Admin cmd, in order):\n"
                "  1) sc qc WinDivert  -> StartType must NOT be DISABLED; if it is:\n"
                "       sc config WinDivert start= demand\n"
                "  2) Reinstall driver files: pip install --force-reinstall pydivert\n"
                "  3) Reboot (required after first install / service fix).\n"
                "  4) Disable interfering VPN/antivirus packet filter; check\n"
                "     Windows Security > Device security > Core isolation > Memory integrity\n"
                "     (WinDivert can be blocked when it is ON; test with reboot).\n"
                "  5) Use matching bitness: 64-bit Python on 64-bit Windows.\n"
                f"Detail: {txt}"
            )
        if isinstance(exc, PermissionError) or "access is denied" in low:
            return (f"FATAL: WinDivert open failed: {txt}. "
                    "Run as Administrator (right-click -> Run as administrator).")
        return f"FATAL: WinDivert open failed: {txt}"
    try:
        injector.w.open()
    except PermissionError as exc:
        print(_windivert_hint(exc), flush=True)
        sys.exit(2)
    except OSError as exc:
        print(_windivert_hint(exc), flush=True)
        sys.exit(2)
    except Exception as exc:
        print(_windivert_hint(exc), flush=True)
        sys.exit(2)
    try:
        injector.w.close()
    except Exception:
        pass
    injector_thread = threading.Thread(target=injector.run, daemon=True)
    injector_thread.start()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    finally:
        shutdown_event.set()
        try:
            injector.stop()
        except Exception:
            pass
