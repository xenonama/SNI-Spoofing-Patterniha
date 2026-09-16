# utils/quic.py — minimal QUIC (UDP/443) helpers for DPI evasion.
#
# Stdlib only, Windows-safe, import-safe without Admin/WinDivert/pydivert.
# No external QUIC stack (no aioquic): only the few byte-level helpers the
# injector needs — detect, peek SNI, same-length SNI swap, fake Initial stub.
#
# Design notes (RFC 9000 §17):
#  - QUIC Initial packets use the long header (bit7=1, bits5-4==00) with a
#    version field; legacy gQUIC used ASCII "Q..." + version. Real Initial
#    payloads are AEAD-encrypted with per-version initial keys, so a full
#    SNI parse requires QUIC crypto — deliberately out of scope. The helpers
#    below do a best-effort *cleartext scan* for the TLS server_name
#    extension, which works on our own build_fake_quic_initial() stubs and
#    on any DPI-visible cleartext copy, and safely returns None otherwise.
#  - Performance: QUIC is high-volume; every helper is a single linear scan
#    with early exits, no regex, no allocation beyond slices. Keep parsing
#    minimal — the hot path (is_quic_packet) touches at most a few bytes.
from __future__ import annotations

import os
import random
import struct

# Magic bytes documented in the project spec for QUIC detection.
# 0x50/0x51/0x52/0x53 are ASCII 'P'..'S' (gQUIC "Q..." family versions like
# Q009 expose 'Q'=0x51 at offset 0); 'Q' is checked explicitly as well.
QUIC_MAGIC = (0x50, 0x51, 0x52, 0x53)
QUIC_PORT = 443


def is_quic_packet(data: bytes | bytearray | None) -> bool:
    """True if `data` (a UDP payload) looks like QUIC. Never raises.

    Heuristic (cheap, hot-path safe):
      1. len >= 5 (need header + version at minimum).
      2. RFC 9000 long-header Initial: bit7 set and packet-type bits == 00.
      3. Legacy gQUIC / spec magic: first byte is 'Q' or in QUIC_MAGIC.
    Port filtering (UDP 443) is done by the caller/WinDivert filter — this
    function inspects bytes only so unit tests stay socket-free.
    """
    try:
        if data is None:
            return False
        buf = bytes(data) if not isinstance(data, (bytes, bytearray)) else data
        if len(buf) < 5:
            return False
        first = buf[0]
        # RFC 9000 §17.2 long header, Initial packet (type bits 00).
        if (first & 0x80) and ((first & 0x30) == 0x00):
            return True
        # Legacy gQUIC magic + project-spec magic set.
        if buf[:1] == b"Q" or first in QUIC_MAGIC:
            return True
        return False
    except Exception:
        return False


def _find_sni_span(data: bytes) -> tuple | None:
    """Locate the SNI string inside `data` -> (sni_start, sni_len) or None.

    Scans for the TLS server_name extension shape:
        00 00 <ext_len:2> <list_len:2> 00 <sni_len:2> <sni>
    Never raises; returns None when absent/ambiguous.
    """
    try:
        buf = bytes(data or b"")
        n = len(buf)
        if n < 15:
            return None
        # Bound the scan: SNI extensions live early in a ClientHello; for
        # QUIC stubs the whole payload is small. Cap at 8K to bound CPU.
        limit = min(n - 9, 8192)
        i = 0
        while i < limit:
            try:
                if buf[i] == 0x00 and buf[i + 1] == 0x00:
                    ext_len = (buf[i + 2] << 8) | buf[i + 3]
                    if 7 <= ext_len <= 260 and i + 4 + ext_len <= n:
                        lst_len = (buf[i + 4] << 8) | buf[i + 5]
                        if lst_len == ext_len - 2 and buf[i + 6] == 0x00:
                            sni_len = (buf[i + 7] << 8) | buf[i + 8]
                            if 1 <= sni_len <= 253 and sni_len == ext_len - 5:
                                start = i + 9
                                cand = buf[start:start + sni_len]
                                if len(cand) == sni_len and b"." in cand:
                                    return (start, sni_len)
            except Exception:
                pass
            i += 1
        return None
    except Exception:
        return None


def extract_sni_from_quic(data: bytes | bytearray | None) -> str | None:
    """Best-effort SNI string from a QUIC payload, else None. Never raises.

    Works on cleartext/stub payloads (see build_fake_quic_initial). Real
    encrypted Initials return None — callers must treat None as "unknown",
    never as an error.
    """
    try:
        buf = bytes(data or b"")
        span = _find_sni_span(buf)
        if not span:
            return None
        start, sni_len = span
        try:
            return buf[start:start + sni_len].decode("ascii", "replace")
        except Exception:
            return None
    except Exception:
        return None


def replace_sni_in_quic(data: bytes | bytearray | None, new_sni: str | bytes) -> bytes:
    """Return a copy of `data` with the SNI replaced by `new_sni`.

    Same-length swap is exact (framing preserved). Different-length SNI
    also updates the two inner length fields (ext_len, list_len, sni_len)
    on a best-effort basis, but outer QUIC/TLS length prefixes are left
    untouched (documented stub limitation — prefer same-length decoys, as
    hostfakesplit does). Returns the original bytes unchanged when no SNI
    is found or inputs are invalid. Never raises.
    """
    try:
        buf = bytes(data or b"")
    except Exception:
        try:
            return bytes(data or b"")
        except Exception:
            return b""
    try:
        if isinstance(new_sni, str):
            new_b = new_sni.encode("ascii", "ignore")
        else:
            new_b = bytes(new_sni or b"")
    except Exception:
        return buf
    if not new_b or b"." not in new_b or len(new_b) > 253 or b" " in new_b:
        return buf
    try:
        span = _find_sni_span(buf)
        if not span:
            return buf
        start, old_len = span
        # Header base: ext starts 9 bytes before the SNI string.
        ext_at = start - 9
        if ext_at < 0:
            return buf
        if len(new_b) == old_len:
            out = bytearray(buf)
            out[start:start + old_len] = new_b
            return bytes(out)
        # Different length: splice + fix the three inner lengths.
        # ext layout: [00 00][ext_len:2][list_len:2][00][sni_len:2][sni]
        try:
            new_ext_len = 5 + len(new_b)
            new_list_len = 3 + len(new_b)
            out = (buf[:ext_at + 2]
                   + struct.pack("!H", new_ext_len)
                   + struct.pack("!H", new_list_len)
                   + b"\x00"
                   + struct.pack("!H", len(new_b))
                   + new_b
                   + buf[start + old_len:])
            return bytes(out)
        except Exception:
            return buf
    except Exception:
        return buf


def build_fake_quic_initial(dest_ip: str = "127.0.0.1", dest_port: int = 443,
                            sni: str | bytes = "example.com") -> bytes:
    """Build a stub QUIC Initial packet carrying `sni` (for DPI spoofing).

    This is NOT a valid encrypted QUIC Initial (real crypto needs the
    version-specific initial keys + HPKE) — it is a long-header-shaped
    decoy whose payload embeds a cleartext server_name extension holding
    `sni`, so a DPI box string-matching SNI on UDP/443 sees the fake name.
    Layout (RFC 9000 §17.2.2 shape, unencrypted stub):
        [flags:1=0xC0][version:4=0x00000001][dcid_len:1][dcid:8]
        [scid_len:1][scid:8][token_len:varint=0][length:varint]
        [pn:1][payload: server_name ext + random pad]
    Raises ValueError on bad SNI; never returns empty.
    """
    try:
        s = sni.decode("ascii", "ignore") if isinstance(sni, (bytes, bytearray)) else str(sni or "")
    except Exception:
        raise ValueError("bad SNI")
    s = s.strip().rstrip(".")
    if not s or "." not in s or " " in s or "/" in s or len(s) > 253:
        raise ValueError("bad SNI: %r" % (str(sni)[:64],))
    try:
        sni_b = s.encode("ascii")
    except Exception:
        raise ValueError("SNI must be ASCII")
    if len(sni_b) > 219:
        raise ValueError("SNI too long (%d > 219)" % len(sni_b))
    try:
        port = int(dest_port)
        if not 1 <= port <= 65535:
            raise ValueError("bad port")
    except (TypeError, ValueError) as exc:
        raise ValueError("bad dest_port: %s" % exc) from exc
    # dest_ip is informational for the stub (no IP header built here);
    # validate loosely so typos fail fast instead of emitting decoys.
    try:
        parts = str(dest_ip or "").strip().split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            raise ValueError("bad dest_ip")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("bad dest_ip: %s" % exc) from exc

    try:
        dcid = os.urandom(8)
    except Exception:
        dcid = bytes(random.getrandbits(8) for _ in range(8))
    try:
        scid = os.urandom(8)
    except Exception:
        scid = bytes(random.getrandbits(8) for _ in range(8))
    # Cleartext server_name extension so DPI string-matches the fake SNI.
    entry = b"\x00" + struct.pack("!H", len(sni_b)) + bytes(sni_b)
    sni_ext = (b"\x00\x00" + struct.pack("!H", len(entry) + 2)
               + struct.pack("!H", len(entry)) + entry)
    try:
        pad = os.urandom(64)
    except Exception:
        pad = bytes(random.getrandbits(8) for _ in range(64))
    payload = sni_ext + pad
    # Minimal varint encoder (values here are < 64 → single byte).
    def _varint(v: int) -> bytes:
        v = int(v) & 0x3FFFFFFF
        if v < 64:
            return bytes((v,))
        if v < 16384:
            return struct.pack("!H", v | 0x4000)
        return struct.pack("!I", v | 0x80000000)
    try:
        pn = os.urandom(1)
    except Exception:
        pn = b"\x01"
    header = (b"\xC0" + struct.pack("!I", 1) + bytes((len(dcid),)) + bytes(dcid)
              + bytes((len(scid),)) + bytes(scid) + _varint(0))
    header += _varint(len(pn) + len(payload)) + bytes(pn)
    return header + payload
