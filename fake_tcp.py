# fake_tcp.py — WinDivert-based fake-SNI injector (hardened).
from __future__ import annotations

import asyncio
import logging
import random
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

try:
    from pydivert import Packet
except Exception:  # offline self-test without WinDivert
    class Packet:  # type: ignore
        pass

from monitor_connection import (
    MonitorConnection,
    increment_active,
    increment_total,
    finish_success,
    finish_failed,
)
from injecter import TcpInjector

log = logging.getLogger("fake_tcp")

SUPPORTED_METHODS = ("auto", "wrong_seq", "wrong_seq_ttl", "split_seq", "fragmented", "padding", "delayed_retry", "double_sni")
# Real wire methods — "auto" rotates one of these per connection.
REAL_METHODS = ("wrong_seq", "wrong_seq_ttl", "split_seq", "fragmented", "padding", "delayed_retry", "double_sni")


def resolve_method(name: str) -> str:
    """Map a configured method to the wire method for one connection.

    "auto" is sticky: AutoState.next_method() returns the SAME method for a
    window (rotating on failures/attempts/time) instead of re-randomizing
    every connection. Real methods bypass auto entirely.
    """
    name = str(name or "").strip() or "auto"
    if name == "auto":
        from utils.auto_state import get_auto_state
        return get_auto_state().next_method()
    if name in REAL_METHODS:
        return name
    raise ValueError("unsupported bypass method: %r (expected one of %s)" % (name, SUPPORTED_METHODS))


def split_plan(syn_seq: int, total_len: int, first_len: int) -> tuple[int, int]:
    """Pure helper: wrong-seq base offsets for a 2-segment split send.

    Both segments live in 'old' sequence space so the real server ignores
    them (same idea as wrong_seq), while DPI still parses the fake SNI.
    Returns (seq1, seq2).
    """
    base = (syn_seq + 1 - total_len) & 0xFFFFFFFF
    return base, (base + first_len) & 0xFFFFFFFF


class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str, peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.counted = False  # True once increment_active() was called
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        # "auto" is resolved per connection so every method gets tried.
        self.bypass_method = resolve_method(bypass_method)
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()


class FakeTcpInjector(TcpInjector):

    def __init__(self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection],
                 fake_delay: float = 0.001,
                 on_event: Callable[[str, str], None] | None = None):
        super().__init__(w_filter)
        self.connections = connections
        self.fake_delay = fake_delay
        self.on_event = on_event
        # Bounded pool: one thread per connection (200+ short-lived threads)
        # caused CPU/memory pressure. 50 workers queue excess work instead.
        self._executor = ThreadPoolExecutor(max_workers=50, thread_name_prefix="fake-send")

    def _emit(self, level: str, msg: str):
        try:
            if self.on_event:
                self.on_event(level, msg)
            else:
                print(msg, flush=True)
        except Exception:
            pass

    def _remove_connection(self, connection: FakeInjectiveConnection):
        """Drop a connection from the shared dict. Never raises."""
        try:
            self.connections.pop(getattr(connection, "id", None), None)
        except Exception:
            pass

    def stop(self):
        try:
            super().stop()
        finally:
            try:
                self._executor.shutdown(wait=False)
            except Exception:
                pass

    def _close_conn(self, connection: FakeInjectiveConnection, msg: str, counted: bool,
                     quiet: bool = False):
        try:
            connection.sock.close()
        except Exception:
            pass
        try:
            connection.peer_sock.close()
        except Exception:
            pass
        connection.monitor = False
        # Fix leak: previously the dict entry survived _close_conn, so failed
        # connections accumulated until main.py popped them (which could be
        # skipped on exception paths). Always evict here; main.py pops are
        # idempotent (pop with default) so double-removal is safe.
        self._remove_connection(connection)
        if counted and connection.counted:
            finish_failed()
            connection.counted = False
        try:
            connection.t2a_msg = "unexpected_close"
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        except Exception:
            pass
        # Routine bypass failures happen per connection (esp. on strict DPI)
        # and would flood the GUI console — keep them at debug level.
        # Real errors (unsupported method, send failures) still print.
        if quiet:
            log.debug("%s %s", msg, connection.id)
        else:
            self._emit("warning", f"{msg} {connection.id}")

    def _send_delayed_retry(self, packet: Packet, connection: FakeInjectiveConnection):
        """delayed_retry: wrong_seq now, split_seq retry after 1.5s if still monitored."""
        time.sleep(self.fake_delay)
        with connection.thread_lock:
            if not connection.monitor:
                return
            try:
                data = bytes(connection.fake_data)
                try:
                    base_len = int(packet.ip.packet_len)
                except Exception:
                    base_len = 0
                try:
                    base_ident = int(packet.ipv4.ident) if packet.ipv4 else 0
                except Exception:
                    base_ident = 0
                # Attempt 1: wrong_seq.
                packet.tcp.psh = True
                packet.ip.packet_len = base_len + len(data)
                packet.tcp.payload = data
                if packet.ipv4:
                    try:
                        packet.ipv4.ident = (base_ident + 1) & 0xFFFF
                    except Exception:
                        pass
                packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xFFFFFFFF
                connection.fake_sent = True
                self.w.send(packet, True)
                first_len = len(data)
            except Exception as exc:
                self._emit("error", f"fake_send failed: {exc}")
                self._close_conn(connection, "fake_send failed,", connection.counted)
                return
        time.sleep(1.5)
        with connection.thread_lock:
            if not connection.monitor:
                return
            # Only retry if the first attempt was sent but handshake not done.
            if not connection.fake_sent:
                return
            try:
                data = bytes(connection.fake_data)
                if len(data) != first_len:
                    data = bytes(connection.fake_data)
                half = max(1, len(data) // 2)
                seq1, seq2 = split_plan(connection.syn_seq, len(data), half)
                try:
                    base_len = int(packet.ip.packet_len)
                    # packet_len was mutated by attempt 1; recover original base
                    # if it grew (best-effort: subtract last payload len).
                    base_len = base_len - len(packet.tcp.payload)
                except Exception:
                    pass
                try:
                    base_ident = (int(packet.ipv4.ident) if packet.ipv4 else 0)
                except Exception:
                    base_ident = 0
                try:
                    orig_len = base_len
                except Exception:
                    orig_len = 0
                # Attempt 2: split_seq on the same packet.
                packet.tcp.psh = False
                packet.ip.packet_len = orig_len + half
                packet.tcp.payload = data[:half]
                if packet.ipv4:
                    try:
                        packet.ipv4.ident = (base_ident + 1) & 0xFFFF
                    except Exception:
                        pass
                packet.tcp.seq_num = seq1
                self.w.send(packet, True)
                time.sleep(min(0.005, self.fake_delay + 0.001))
                if not connection.monitor:
                    return
                packet.tcp.psh = True
                packet.ip.packet_len = orig_len + (len(data) - half)
                packet.tcp.payload = data[half:]
                if packet.ipv4:
                    try:
                        packet.ipv4.ident = (base_ident + 2) & 0xFFFF
                    except Exception:
                        pass
                packet.tcp.seq_num = seq2
                connection.fake_sent = True
                self.w.send(packet, True)
            except Exception as exc:
                self._emit("error", f"fake_send failed: {exc}")
                self._close_conn(connection, "fake_send failed,", connection.counted)

    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        if getattr(connection, "bypass_method", "") == "delayed_retry":
            self._send_delayed_retry(packet, connection)
            return
        time.sleep(self.fake_delay)
        with connection.thread_lock:
            if not connection.monitor:
                return
            try:
                data = bytes(connection.fake_data)
                if connection.bypass_method in ("wrong_seq", "wrong_seq_ttl"):
                    packet.tcp.psh = True
                    packet.ip.packet_len = packet.ip.packet_len + len(data)
                    packet.tcp.payload = data
                    if packet.ipv4:
                        try:
                            packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xFFFF
                        except Exception:
                            pass
                    # Optional TTL trick for stronger DPI evasion (best-effort).
                    if connection.bypass_method == "wrong_seq_ttl":
                        try:
                            if packet.ipv4:
                                packet.ipv4.ttl = max(1, min(int(getattr(packet.ipv4, "ttl", 64)) - 1, 255))
                        except Exception:
                            pass
                    packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xFFFFFFFF
                    connection.fake_sent = True
                    self.w.send(packet, True)
                elif connection.bypass_method == "split_seq":
                    # Send the fake ClientHello as 2 out-of-window segments.
                    half = max(1, len(data) // 2)
                    seq1, seq2 = split_plan(connection.syn_seq, len(data), half)
                    try:
                        base_ident = int(packet.ipv4.ident) if packet.ipv4 else 0
                    except Exception:
                        base_ident = 0
                    try:
                        base_len = int(packet.ip.packet_len)
                    except Exception:
                        base_len = 0
                    # segment 1 (no PSH — looks like middle of a split)
                    packet.tcp.psh = False
                    packet.ip.packet_len = base_len + half
                    packet.tcp.payload = data[:half]
                    if packet.ipv4:
                        try:
                            packet.ipv4.ident = (base_ident + 1) & 0xFFFF
                        except Exception:
                            pass
                    packet.tcp.seq_num = seq1
                    self.w.send(packet, True)
                    time.sleep(min(0.005, self.fake_delay + 0.001))
                    # NOTE: already holding connection.thread_lock here —
                    # just re-check the flag, do NOT re-acquire (deadlocked
                    # split_seq before: nested Lock.acquire blocks forever).
                    if not connection.monitor:
                        return
                    # segment 2 (PSH set)
                    packet.tcp.psh = True
                    packet.ip.packet_len = base_len + (len(data) - half)
                    packet.tcp.payload = data[half:]
                    if packet.ipv4:
                        try:
                            packet.ipv4.ident = (base_ident + 2) & 0xFFFF
                        except Exception:
                            pass
                    packet.tcp.seq_num = seq2
                    connection.fake_sent = True
                    self.w.send(packet, True)
                elif connection.bypass_method == "fragmented":
                    # Tear into 3 unequal pieces (40/30/30), old seq space.
                    n = len(data)
                    if n < 3:
                        # Too small to fragment — fall back to single wrong_seq.
                        packet.tcp.psh = True
                        packet.ip.packet_len = packet.ip.packet_len + n
                        packet.tcp.payload = data
                        if packet.ipv4:
                            try:
                                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xFFFF
                            except Exception:
                                pass
                        packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xFFFFFFFF
                        connection.fake_sent = True
                        self.w.send(packet, True)
                    else:
                        len1 = max(1, int(n * 0.4))
                        len2 = max(1, int(n * 0.3))
                        if len1 + len2 >= n:
                            len2 = max(1, (n - len1) // 2)
                        len3 = n - len1 - len2
                        if len3 < 1:
                            len3 = 1
                            len2 = n - len1 - len3
                        parts = (data[:len1], data[len1:len1 + len2], data[len1 + len2:])
                        base = (connection.syn_seq + 1 - n) & 0xFFFFFFFF
                        seqs = (base, (base + len1) & 0xFFFFFFFF,
                                (base + len1 + len2) & 0xFFFFFFFF)
                        try:
                            base_ident = int(packet.ipv4.ident) if packet.ipv4 else 0
                        except Exception:
                            base_ident = 0
                        try:
                            base_len = int(packet.ip.packet_len)
                        except Exception:
                            base_len = 0
                        gap = max(0.0, self.fake_delay * 2)
                        for i, (part, seq) in enumerate(zip(parts, seqs)):
                            if not connection.monitor:
                                return
                            if i > 0 and gap:
                                time.sleep(gap)
                            packet.tcp.psh = (i == len(parts) - 1)
                            packet.ip.packet_len = base_len + len(part)
                            packet.tcp.payload = part
                            if packet.ipv4:
                                try:
                                    packet.ipv4.ident = (base_ident + i + 1) & 0xFFFF
                                except Exception:
                                    pass
                            packet.tcp.seq_num = seq
                            if i == len(parts) - 1:
                                connection.fake_sent = True
                            self.w.send(packet, True)
                elif connection.bypass_method == "padding":
                    # Junk leading bytes, wrong_seq numbers.
                    pad_len = random.randint(16, 64)
                    padded = b"\x00" * pad_len + data
                    packet.tcp.psh = True
                    packet.ip.packet_len = packet.ip.packet_len + len(padded)
                    packet.tcp.payload = padded
                    if packet.ipv4:
                        try:
                            packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xFFFF
                        except Exception:
                            pass
                    packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xFFFFFFFF
                    connection.fake_sent = True
                    self.w.send(packet, True)
                elif connection.bypass_method == "double_sni":
                    # Simplified nested SNI: fake hello + delimiter + real marker.
                    try:
                        real = str(getattr(connection, "dst_ip", "") or "")
                    except Exception:
                        real = ""
                    real_b = real.encode() if real else b"real"
                    payload = data + b"|" + real_b
                    packet.tcp.psh = True
                    packet.ip.packet_len = packet.ip.packet_len + len(payload)
                    packet.tcp.payload = payload
                    if packet.ipv4:
                        try:
                            packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xFFFF
                        except Exception:
                            pass
                    packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xFFFFFFFF
                    connection.fake_sent = True
                    self.w.send(packet, True)
                else:
                    self._emit("error", f"unsupported bypass method: {connection.bypass_method}")
                    self._close_conn(connection, "unsupported bypass method,", connection.counted)
            except Exception as exc:
                self._emit("error", f"fake_send failed: {exc}")
                self._close_conn(connection, "fake_send failed,", connection.counted)

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        try:
            # quiet=True: routine DPI mismatch — stats already count it,
            # no need to spam the live console with one line per failure.
            self._close_conn(connection, info_m, True, quiet=True)
        finally:
            try:
                self.w.send(packet, False)
            except Exception as exc:
                self._emit("error", f"reinject after unexpected failed: {exc}")

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
            return
        if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound syn-ack packet, seq change! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound syn-ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(connection.syn_seq))
                return
            connection.syn_ack_seq = seq_num
            try:
                self.w.send(packet, False)
            except Exception as exc:
                self.on_unexpected_packet(packet, connection, f"reinject syn-ack failed: {exc}")
            return
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (
                not packet.tcp.fin) and (len(packet.tcp.payload) == 0) and connection.fake_sent:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xFFFFFFFF) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound ack packet, seq not matched! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound ack packet, ack not matched! " + str(ack_num) + " " + str(
                                              connection.syn_seq))
                return
            # SUCCESS — bypass handshake complete. Release from monitor + stats.
            # Evict from the shared dict now: main.py also pops (idempotent),
            # so a missed pop there can no longer leak the entry.
            connection.monitor = False
            if connection.counted:
                finish_success()
                connection.counted = False
            self._remove_connection(connection)
            connection.t2a_msg = "fake_data_ack_recv"
            try:
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            except Exception:
                pass
            return
        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")
        return

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet, recv packet after fake sent!")
            return
        if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, ack_num is not zero!")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, seq not matched! " + str(
                    seq_num) + " " + str(connection.syn_seq))
                return
            connection.syn_seq = seq_num
            try:
                self.w.send(packet, False)
            except Exception as exc:
                self.on_unexpected_packet(packet, connection, f"reinject syn failed: {exc}")
            return
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xFFFFFFFF) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected outbound ack packet, seq not matched! " + str(
                                              seq_num) + " " + str(
                                              connection.syn_seq))
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xFFFFFFFF):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected outbound ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            try:
                self.w.send(packet, False)
            except Exception as exc:
                self.on_unexpected_packet(packet, connection, f"reinject ack failed: {exc}")
                return
            connection.sch_fake_sent = True
            increment_total()
            increment_active()
            connection.counted = True
            try:
                self._executor.submit(self.fake_send_thread, packet, connection)
            except RuntimeError:
                # Executor already shut down (injector stopping): fall back
                # to a short-lived daemon thread so the send is not lost.
                threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            return
        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")
        return

    def inject(self, packet: Packet):
        try:
            if packet.is_inbound:
                c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
                try:
                    connection = self.connections[c_id]
                except KeyError:
                    self.w.send(packet, False)
                else:
                    with connection.thread_lock:
                        if not connection.monitor:
                            self.w.send(packet, False)
                            return
                        self.on_inbound_packet(packet, connection)
            elif packet.is_outbound:
                c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
                try:
                    connection = self.connections[c_id]
                except KeyError:
                    self.w.send(packet, False)
                else:
                    with connection.thread_lock:
                        if not connection.monitor:
                            self.w.send(packet, False)
                            return
                        self.on_outbound_packet(packet, connection)
            else:
                # Never kill the injector thread on a weird packet — just forward.
                self._emit("warning", "packet with unknown direction, forwarding")
                try:
                    self.w.send(packet, False)
                except Exception as exc:
                    self._emit("error", f"forward unknown-direction packet failed: {exc}")
        except Exception as exc:
            # Per-packet guard: injector must survive.
            self._emit("error", f"inject error (surviving): {exc}")
            try:
                self.w.send(packet, False)
            except Exception:
                pass
