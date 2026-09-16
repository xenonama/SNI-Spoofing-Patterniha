# utils/tls_fingerprint.py — parameterized TLS ClientHello builder (JA3-oriented).
#
# Stdlib only, Windows-safe. Generates raw ClientHello bytes for a given SNI
# under a named browser profile so fake-SNI injections don't all share one
# static JA3 fingerprint (see utils/packet_templates.py).
#
# Why no `tls_client` dependency?
#   `pip install tls-client` gives a full HTTP client that mimics browsers on
#   *real sockets*, but it cannot emit raw ClientHello *bytes* for WinDivert
#   packet injection — which is all this injector needs. This module is the
#   "lightweight alternative": a small struct-based builder producing valid
#   ClientHello records with per-profile cipher/extension ordering.
#   Optional cross-check only:
#       pip install tls-client
#   then compare ja3_hash(profile) below against the JA3 your DPI box reports
#   for a real tls_client session with the same identifier.
#
# Profiles: "legacy" (old static 517B template via ClientHelloMaker),
# "chrome_120", "chrome_124", "firefox_122", "firefox_124",
# "custom" (chrome-like, different GREASE).
# JA3 strings are close approximations of the real browsers — verify with
# Wireshark/JA3 before relying on exact equality.
from __future__ import annotations

import hashlib
import os
import struct
import threading

try:
    from utils.security import is_valid_sni as _is_valid_sni
except Exception:  # pragma: no cover
    def _is_valid_sni(s) -> bool:  # type: ignore
        s = str(s or "").strip()
        return bool(s) and "." in s and " " not in s

FINGERPRINTS = ("legacy", "chrome_120", "chrome_124", "firefox_122",
                "firefox_124", "custom")

FINGERPRINT_LABELS = {
    "legacy": "Legacy (static template)",
    "chrome_120": "Chrome 120",
    "chrome_124": "Chrome 124",
    "firefox_122": "Firefox 122",
    "firefox_124": "Firefox 124",
    "custom": "Custom",
}

MAX_SNI_BYTES = 219  # same cap as the legacy template / input validation

_GREASE = (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
           0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA)


def _is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and 0x0A0A <= v <= 0xFAFA


def _u16(v: int) -> bytes:
    return struct.pack("!H", v & 0xFFFF)


def _u24(v: int) -> bytes:
    return bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def _u32(v: int) -> bytes:
    return struct.pack("!I", v & 0xFFFFFFFF)


def _ext(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(data)) + bytes(data)


# --------------------------------------------------------------------------
# Extension type constants
# --------------------------------------------------------------------------
# NOTE on ALPS: the real IANA codepoint for
# application_layer_protocol_settings (RFC 8870 / draft-vvv-tls-alps) is
# 17513 (0x4469). This project historically documents ALPS as 0x001C (28,
# which IANA assigns to record_size_limit). We follow the project spec and
# emit 0x001C so DPI-test expectations match, and expose the real codepoint
# as ALPS_REAL_TYPE for future migration.
ALPS_EXT_TYPE = 0x001C
ALPS_REAL_TYPE = 17513  # 0x4469 — real IANA ALPS codepoint (informational)
ECH_EXT_TYPE = 0xFE0D  # 65037 — encrypted_client_hello (draft-ietf-tls-esni)

# Common TLS 1.2 cipher-suite core (AES-GCM / ChaCha + CBC fallbacks).
_CIPHER_CORE = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F,
                0x0035, 0x000A)

# Chrome 124 refresh: same wire core as 120 (TLS 1.3 + ECDHE + CBC
# fallbacks); CCM suites (0xC0AC etc.) are still not offered by real
# Chrome, so the suite list is unchanged — the fingerprint delta is the
# GREASE seed + ALPS/ECH extensions + padding. Kept as a separate tuple
# so future captures can diverge the lists without touching chrome_120.
_CIPHER_CORE_CHROME_124 = _CIPHER_CORE

# Firefox 124 refresh: Firefox 122 core + TLS_AES_128_CCM_SHA256 (0x1304)
# and CCM_8 (0x1305) which newer Firefox builds negotiate. Order matches
# NSS preference (GCM/ChaCha first, CCM last, then ECDHE + CBC).
_CIPHER_CORE_FF124 = (0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
                      0xC02B, 0xC02F, 0xC02C, 0xC030,
                      0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D,
                      0x002F, 0x0035, 0x000A)

_SIG_ALGS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
             0x0201)


def _sni_ext(sni: bytes) -> bytes:
    entry = b"\x00" + _u16(len(sni)) + bytes(sni)
    return _ext(0, _u16(len(entry)) + entry)


def _alpn_ext(protos: tuple = (b"h2", b"http/1.1")) -> bytes:
    body = b"".join(bytes((len(p),)) + bytes(p) for p in protos)
    return _ext(16, _u16(len(body)) + body)


def _groups_ext(curves: tuple) -> bytes:
    body = b"".join(_u16(c) for c in curves)
    return _ext(10, _u16(len(body)) + body)


def _sigalgs_ext() -> bytes:
    body = b"".join(_u16(a) for a in _SIG_ALGS)
    return _ext(13, _u16(len(body)) + body)


def _versions_ext(supported: tuple) -> bytes:
    body = b"".join(_u16(v) for v in supported)
    return _ext(43, bytes((len(body),)) + body)


def _key_share_ext(shares: list) -> bytes:
    """shares: list of (group_id, key_bytes)."""
    body = b"".join(_u16(g) + _u16(len(k)) + bytes(k) for g, k in shares)
    return _ext(51, _u16(len(body)) + body)


def _status_request_ext() -> bytes:
    return _ext(5, b"\x01\x00\x00\x00\x00")


# --------------------------------------------------------------------------
# ALPS (Application-Layer Protocol Settings, RFC 8870)
# --------------------------------------------------------------------------
def build_alps_ext(alpn_values: dict | None = None) -> bytes:
    """Build the ALPS extension (type ALPS_EXT_TYPE == 0x001C per spec).

    alpn_values: {proto_bytes: alp_value_bytes}. Default mirrors what
    Chrome sends for h2: the ALPS value carries the HTTP/2 SETTINGS the
    client would use (setting-id:2B + value:4B tuples), so a DPI box that
    parses ALPS sees a coherent h2 fingerprint.
    Wire format (draft-vvv-tls-alps):
        extension_data = opaque<0..2^16-1> containing
          ALPSEntry[]: { proto_len(1B) + proto + value_len(2B) + value }
    Pure stub otherwise — values are static, no crypto.
    """
    if alpn_values is None:
        # Default h2 SETTINGS mirror (HEADER_TABLE_SIZE=65536,
        # INITIAL_WINDOW_SIZE=6291456) encoded as ALPS value.
        alpn_values = {b"h2": _u16(0x01) + _u32(65536) + _u16(0x04) + _u32(6291456)}
    body = b""
    try:
        items = dict(alpn_values).items()
    except Exception:
        items = [(b"h2", b"")]
    for proto, val in items:
        try:
            p = bytes(proto or b"")
            v = bytes(val or b"")
        except Exception:
            continue
        if not p or len(p) > 255:
            continue
        body += bytes((len(p),)) + p + _u16(len(v)) + v
    return _ext(ALPS_EXT_TYPE, body)


# --------------------------------------------------------------------------
# ECH (Encrypted ClientHello, draft-ietf-tls-esni) — stub
# --------------------------------------------------------------------------
def build_ech_ext(enc: bytes | None = None, payload: bytes | None = None) -> bytes:
    """Build a dummy ECH extension (type 0xFE0D / 65037).

    Real ECH needs the server's ECHConfig (HPKE seal of an inner
    ClientHello) — impossible offline. This stub emits a well-formed
    outer-type placeholder so DPI that merely checks "ECH present" is
    satisfied, while a real server ignores it (falls back to the cleartext
    SNI in extension 0). Format (draft-ietf-tls-esni §5):
        ECHClientHello { uint8 type=0 (outer); opaque enc<0..255>;
                         opaque payload<0..2^16-1>; }
    enc/payload default to fresh randomness (32B/16B) so each template
    looks unique; pass fixed bytes for deterministic tests.
    """
    try:
        enc_b = bytes(enc) if enc is not None else os.urandom(32)
    except Exception:
        enc_b = b"\x11" * 32
    try:
        pay_b = bytes(payload) if payload is not None else os.urandom(16)
    except Exception:
        pay_b = b"\x22" * 16
    if len(enc_b) > 255:
        enc_b = enc_b[:255]
    if len(pay_b) > 65535:
        pay_b = pay_b[:65535]
    body = b"\x00" + bytes((len(enc_b),)) + enc_b + _u16(len(pay_b)) + pay_b
    return _ext(ECH_EXT_TYPE, body)


# --------------------------------------------------------------------------
# HTTP/2 fingerprint (SETTINGS / WINDOW_UPDATE)
# --------------------------------------------------------------------------
# Browser HTTP/2 preface fingerprints. SETTINGS ids per RFC 7540 §6.5.2:
#   0x1 HEADER_TABLE_SIZE, 0x2 ENABLE_PUSH, 0x3 MAX_CONCURRENT_STREAMS,
#   0x4 INITIAL_WINDOW_SIZE, 0x5 MAX_FRAME_SIZE, 0x6 MAX_HEADER_LIST_SIZE.
# Values below mirror public captures (akamai h2 fingerprint datasets,
# curl-impersonate ff/chrome tables):
#   Chrome:  SETTINGS 1:65536;2:0;4:6291456;6:262144, WINDOW_UPDATE 15663105
#   Firefox: SETTINGS 1:65536;4:131072;5:16384,       WINDOW_UPDATE 12517377
# HPACK behavior note (informational, used by the future Trojan+Xray proxy
# mode): Chrome uses dynamic table 4096 with Huffman-heavy literal indexing;
# Firefox uses table 65536 w/ incremental indexing on a smaller header set.
# For now we only generate bytes and cache them — the injector still sends
# just the TLS ClientHello.
HTTP2_SETTINGS_DEFS: dict = {
    "chrome_120": {
        "settings": ((0x01, 65536), (0x02, 0), (0x04, 6291456), (0x06, 262144)),
        "window_update": 15663105,
        "hpack_dynamic_table": 4096,
        "order": ("settings", "window_update"),
    },
    "chrome_124": {
        "settings": ((0x01, 65536), (0x02, 0), (0x04, 6291456), (0x06, 262144)),
        "window_update": 15663105,
        "hpack_dynamic_table": 4096,
        "order": ("settings", "window_update"),
    },
    "firefox_122": {
        "settings": ((0x01, 65536), (0x04, 131072), (0x05, 16384)),
        "window_update": 12517377,
        "hpack_dynamic_table": 65536,
        "order": ("settings", "window_update"),
    },
    "firefox_124": {
        "settings": ((0x01, 65536), (0x04, 131072), (0x05, 16384)),
        "window_update": 12517377,
        "hpack_dynamic_table": 65536,
        "order": ("settings", "window_update"),
    },
    "custom": {
        "settings": ((0x01, 65536), (0x02, 0), (0x04, 6291456), (0x06, 262144)),
        "window_update": 15663105,
        "hpack_dynamic_table": 4096,
        "order": ("settings", "window_update"),
    },
    "legacy": {
        "settings": ((0x01, 4096), (0x04, 65535)),
        "window_update": 65535,
        "hpack_dynamic_table": 4096,
        "order": ("settings", "window_update"),
    },
}

_h2_cache: dict = {}
_h2_lock = threading.Lock()
_H2_CACHE_CAP = 64


def build_http2_settings_frame(settings: tuple | list) -> bytes:
    """Raw HTTP/2 SETTINGS frame (type 0x4, empty flags, stream 0).

    settings: iterable of (id:u16, value:u32). Returns the full 9-byte
    header + payload so callers can queue it straight onto the wire.
    """
    try:
        pairs = list(settings or [])
    except Exception:
        pairs = []
    payload = b""
    for sid, sval in pairs:
        try:
            payload += _u16(int(sid)) + _u32(int(sval))
        except Exception:
            continue
    # Frame header: length:u24 | type:u8(0x4) | flags:u8(0x0) | stream:u32(0).
    return _u24(len(payload)) + b"\x04\x00" + _u32(0) + payload


def build_http2_window_update_frame(increment: int) -> bytes:
    """Raw HTTP/2 WINDOW_UPDATE frame (type 0x8) for stream 0."""
    try:
        inc = int(increment) & 0x7FFFFFFF
    except Exception:
        inc = 0
    if inc == 0:
        inc = 65535
    return _u24(4) + b"\x08\x00" + _u32(0) + _u32(inc)


def get_http2_settings(profile: str = "chrome_124") -> bytes:
    """Browser-specific HTTP/2 SETTINGS frame bytes (cached per profile).

    Unknown profile -> chrome_124 table (never raises on profile).
    """
    prof = str(profile or "chrome_124").strip().lower() or "chrome_124"
    if prof not in HTTP2_SETTINGS_DEFS:
        prof = "chrome_124"
    try:
        with _h2_lock:
            hit = _h2_cache.get(prof)
        if hit is not None:
            return hit
    except Exception:
        pass
    try:
        settings = HTTP2_SETTINGS_DEFS[prof]["settings"]
    except Exception:
        settings = HTTP2_SETTINGS_DEFS["chrome_124"]["settings"]
    data = build_http2_settings_frame(settings)
    try:
        with _h2_lock:
            if len(_h2_cache) >= _H2_CACHE_CAP:
                try:
                    _h2_cache.pop(next(iter(_h2_cache)), None)
                except Exception:
                    pass
            _h2_cache[prof] = data
    except Exception:
        pass
    return data


def get_http2_preface(profile: str = "chrome_124") -> bytes:
    """SETTINGS + WINDOW_UPDATE in the browser's frame order (cached).

    For future Trojan+Xray proxy mode; the current injector only needs
    get_http2_settings(), this is a convenience for later.
    """
    prof = str(profile or "chrome_124").strip().lower() or "chrome_124"
    if prof not in HTTP2_SETTINGS_DEFS:
        prof = "chrome_124"
    key = ("preface", prof)
    try:
        with _h2_lock:
            hit = _h2_cache.get(key)
        if hit is not None:
            return hit
    except Exception:
        pass
    d = HTTP2_SETTINGS_DEFS.get(prof) or HTTP2_SETTINGS_DEFS["chrome_124"]
    data = build_http2_settings_frame(d["settings"]) + build_http2_window_update_frame(d.get("window_update", 65535))
    try:
        with _h2_lock:
            if len(_h2_cache) >= _H2_CACHE_CAP:
                try:
                    _h2_cache.pop(next(iter(_h2_cache)), None)
                except Exception:
                    pass
            _h2_cache[key] = data
    except Exception:
        pass
    return data


def find_client_hello_extensions(hello: bytes) -> list:
    """Parse a raw ClientHello record -> list of extension-type ints.

    Tolerant: returns [] on any parse error (never raises). Used by
    self-tests to assert ALPS/ECH presence without a TLS stack.
    """
    try:
        data = bytes(hello or b"")
        if len(data) < 5 or data[0] != 0x16:
            return []
        rec_len = struct.unpack("!H", data[3:5])[0]
        if len(data) < 5 + rec_len:
            return []
        hs = data[5:5 + rec_len]
        if len(hs) < 4 or hs[0] != 0x01:
            return []
        hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
        body = hs[4:4 + hs_len]
        if len(body) < hs_len:
            return []
        # body: version(2) + random(32) + sess_len(1)+sess + cipher_len(2)+ciphers
        #       + comp_len(1)+comps + ext_len(2)+exts
        pos = 2 + 32
        if pos + 1 > len(body):
            return []
        sess_len = body[pos]
        pos += 1 + sess_len
        if pos + 2 > len(body):
            return []
        cipher_len = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2 + cipher_len
        if pos + 1 > len(body):
            return []
        comp_len = body[pos]
        pos += 1 + comp_len
        if pos + 2 > len(body):
            return []
        ext_total = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        exts = body[pos:pos + ext_total]
        out: list = []
        i = 0
        while i + 4 <= len(exts):
            et, el = struct.unpack("!HH", exts[i:i + 4])
            out.append(int(et))
            i += 4 + el
            if el < 0 or i > len(exts):
                break
        return out
    except Exception:
        return []


_PROFILE_DEFS: dict = {
    "chrome_120": {
        "ciphers": (0x2A2A,) + _CIPHER_CORE,
        "curves": (0x2A2A, 29, 23, 24),
        "points": (0,),
        "alpn": (b"h2", b"http/1.1"),
        "versions": (0x2A2A, 0x0304, 0x0303),
        "session_len": 32,
        # Extension *order* is the fingerprint-relevant part.
        "ext_order": ("grease", "sni", "ems", "reneg", "groups", "points",
                      "ticket", "alpn", "status", "sigalgs", "sct", "alps",
                      "keyshare", "pskmode", "versions", "ech", "padding"),
        "keyshare_grease": True,
        "pad_to": 512,  # Chrome pads the record with ext 21
    },
    "chrome_124": {
        # Refreshed 2024 capture: new GREASE seed 0xAAAA, same suite core,
        # ALPS + ECH now offered, padding target unchanged (512B record).
        "ciphers": (0xAAAA,) + _CIPHER_CORE_CHROME_124,
        "curves": (0xAAAA, 29, 23, 24),
        "points": (0,),
        "alpn": (b"h2", b"http/1.1"),
        "versions": (0xAAAA, 0x0304, 0x0303),
        "session_len": 32,
        "ext_order": ("grease", "sni", "ems", "reneg", "groups", "points",
                      "ticket", "alpn", "status", "sigalgs", "sct", "alps",
                      "keyshare", "pskmode", "versions", "ech", "padding"),
        "keyshare_grease": True,
        "pad_to": 512,
    },
    "firefox_122": {
        "ciphers": _CIPHER_CORE,
        "curves": (29, 23, 24, 25, 256, 257),
        "points": (0,),
        "alpn": (b"h2", b"http/1.1"),
        "versions": (0x0304, 0x0303),
        "session_len": 0,
        "ext_order": ("sni", "groups", "points", "sigalgs", "alpn", "ems",
                      "ticket", "versions", "pskmode", "keyshare", "status",
                      "reneg", "alps", "ech"),
        "keyshare_grease": False,
        "pad_to": 0,
    },
    "firefox_124": {
        # Firefox 124: CCM suites appended, extra secp521r1/secp384r1
        # already present, ALPS + ECH appended (NSS sends them last).
        "ciphers": _CIPHER_CORE_FF124,
        "curves": (29, 23, 24, 25, 256, 257),
        "points": (0,),
        "alpn": (b"h2", b"http/1.1"),
        "versions": (0x0304, 0x0303, 0x0302),
        "session_len": 0,
        "ext_order": ("sni", "groups", "points", "sigalgs", "alpn", "ems",
                      "ticket", "versions", "pskmode", "keyshare", "status",
                      "reneg", "alps", "ech"),
        "keyshare_grease": False,
        "pad_to": 0,
    },
    "custom": {
        "ciphers": (0x5A5A,) + _CIPHER_CORE,
        "curves": (0x5A5A, 29, 23, 24, 25),
        "points": (0,),
        "alpn": (b"h2",),
        "versions": (0x5A5A, 0x0304, 0x0303),
        "session_len": 32,
        "ext_order": ("grease", "sni", "groups", "points", "alpn", "sigalgs",
                      "ems", "ticket", "versions", "keyshare", "pskmode",
                      "status", "sct", "reneg", "alps", "ech", "padding"),
        "keyshare_grease": True,
        "pad_to": 512,
    },
}

# Public alias (prompt deliverable names it PROFILE_DEFS).
PROFILE_DEFS = _PROFILE_DEFS


def _build_extensions(profile: str, sni: bytes, x25519_key: bytes,
                      secp256_key: bytes | None) -> bytes:
    d = _PROFILE_DEFS[profile]
    grease_cipher = d["ciphers"][0] if d["ciphers"] and _is_grease(d["ciphers"][0]) else 0x2A2A
    shares = []
    if d["keyshare_grease"]:
        shares.append((grease_cipher, b"\x00"))
    shares.append((29, x25519_key))
    if profile in ("firefox_122", "firefox_124") and secp256_key is not None:
        shares.append((23, secp256_key))
    parts: dict = {
        "grease": _ext(grease_cipher, b""),
        "sni": _sni_ext(sni),
        "ems": _ext(23, b""),
        "reneg": _ext(65281, b"\x00"),
        "groups": _groups_ext(tuple(c for c in d["curves"])),
        "points": _ext(11, bytes((len(d["points"]),)) + bytes(d["points"])),
        "ticket": _ext(35, b""),
        "alpn": _alpn_ext(d["alpn"]),
        "status": _status_request_ext(),
        "sigalgs": _sigalgs_ext(),
        "sct": _ext(18, b""),
        "alps": build_alps_ext(),
        "keyshare": _key_share_ext(shares),
        "pskmode": _ext(45, b"\x01\x01"),
        "versions": _versions_ext(d["versions"]),
        "ech": build_ech_ext(),
    }
    out = b"".join(parts[k] for k in d["ext_order"] if k not in ("padding",))
    if d.get("pad_to"):
        # Pad the *record* with extension 21 (Chrome behavior).
        # record overhead: 5B header + 4B handshake header; hello so far
        # contributes its own length — compute after assembly instead.
        pass
    return out


def _build_client_hello_bytes(sni: bytes, profile: str) -> bytes:
    d = _PROFILE_DEFS[profile]
    rnd = os.urandom(32)
    sess_len = int(d["session_len"])
    sess = os.urandom(sess_len) if sess_len else b""
    x25519_key = os.urandom(32)
    secp256_key = os.urandom(65) if profile in ("firefox_122", "firefox_124") else None

    ciphers = b"".join(_u16(c) for c in d["ciphers"])
    exts = _build_extensions(profile, sni, x25519_key, secp256_key)

    body = (b"\x03\x03" + rnd + bytes((len(sess),)) + sess
            + _u16(len(ciphers)) + ciphers + b"\x01\x00"
            + _u16(len(exts)) + exts)
    hello = b"\x01" + _u24(len(body)) + body
    record = b"\x16\x03\x01" + _u16(len(hello)) + hello

    pad_to = int(d.get("pad_to") or 0)
    if pad_to and len(record) < pad_to:
        # Extension 21 (padding): fill so the whole record hits pad_to.
        need = pad_to - len(record) - 4  # ext header
        if need > 0:
            pad_ext = _ext(21, b"\x00" * need)
            exts = exts + pad_ext
            body = (b"\x03\x03" + rnd + bytes((len(sess),)) + sess
                    + _u16(len(ciphers)) + ciphers + b"\x01\x00"
                    + _u16(len(exts)) + exts)
            hello = b"\x01" + _u24(len(body)) + body
            record = b"\x16\x03\x01" + _u16(len(hello)) + hello
    return record


class TlsFingerprintGenerator:
    """Cached, fingerprint-parameterized ClientHello factory.

    Cache key is (profile, sni): repeated connections reuse one template
    (fast path, stable fingerprint). "legacy" delegates to the original
    ClientHelloMaker with fresh randomness per call (uncached, as before).
    """

    PROFILES = FINGERPRINTS

    _cache: dict = {}
    _lock = threading.Lock()
    _CACHE_CAP = 512

    @classmethod
    def _check_sni(cls, sni: bytes | str) -> bytes:
        if isinstance(sni, str):
            sni = sni.encode("ascii", "ignore")
        sni = bytes(sni or b"")
        if not sni:
            raise ValueError("SNI must not be empty")
        if len(sni) > MAX_SNI_BYTES:
            raise ValueError("SNI too long (%d > %d)" % (len(sni), MAX_SNI_BYTES))
        try:
            if not _is_valid_sni(sni.decode("ascii", "replace")):
                raise ValueError("bad SNI: %r" % (sni[:64],))
        except ValueError:
            raise
        except Exception:
            raise ValueError("bad SNI")
        return sni

    @classmethod
    def get_client_hello(cls, sni: bytes | str, profile: str = "chrome_120") -> bytes:
        """Raw ClientHello record bytes for SNI under profile.

        Unknown profile -> legacy template (never raises on profile).
        """
        sni_b = cls._check_sni(sni)
        prof = str(profile or "legacy").strip().lower() or "legacy"
        if prof not in _PROFILE_DEFS:
            prof = "legacy"
        if prof == "legacy":
            from utils.packet_templates import ClientHelloMaker
            return ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32), sni_b, os.urandom(32))
        key = (prof, bytes(sni_b))
        try:
            with cls._lock:
                hit = cls._cache.get(key)
            if hit is not None:
                return hit
        except Exception:
            pass
        data = _build_client_hello_bytes(bytes(sni_b), prof)
        try:
            with cls._lock:
                if len(cls._cache) >= cls._CACHE_CAP:
                    try:
                        cls._cache.pop(next(iter(cls._cache)), None)
                    except Exception:
                        pass
                cls._cache[key] = data
        except Exception:
            pass
        return data

    @classmethod
    def get_http2_settings(cls, profile: str = "chrome_124") -> bytes:
        """Browser-specific HTTP/2 SETTINGS frame bytes (cached).

        The injector currently only sends the TLS ClientHello; these bytes
        are generated now and cached for the future Trojan+Xray proxy mode.
        Unknown profile -> chrome_124 table (never raises).
        """
        return get_http2_settings(profile)

    @classmethod
    def get_http2_preface(cls, profile: str = "chrome_124") -> bytes:
        """SETTINGS + WINDOW_UPDATE in browser frame order (cached)."""
        return get_http2_preface(profile)

    @classmethod
    def ja3(cls, profile: str = "chrome_120") -> str:
        """JA3 string (version,ciphers,extensions,curves,points), GREASE-free."""
        prof = str(profile or "").strip().lower()
        if prof == "legacy" or prof not in _PROFILE_DEFS:
            return "771,4865-4866-4867,0-10-11,29-23-24,0"
        d = _PROFILE_DEFS[prof]
        ciphers = "-".join(str(c) for c in d["ciphers"] if not _is_grease(c))
        order = [k for k in d["ext_order"] if k != "padding"]
        _ids = {"grease": None, "sni": 0, "ems": 23, "reneg": 65281,
                "groups": 10, "points": 11, "ticket": 35, "alpn": 16,
                "status": 5, "sigalgs": 13, "sct": 18, "alps": ALPS_EXT_TYPE,
                "keyshare": 51, "pskmode": 45, "versions": 43,
                "ech": ECH_EXT_TYPE}
        exts = "-".join(str(_ids[k]) for k in order if _ids.get(k) is not None)
        curves = "-".join(str(c) for c in d["curves"] if not _is_grease(c))
        points = "-".join(str(p) for p in d["points"])
        return "771,%s,%s,%s,%s" % (ciphers, exts, curves, points)

    @classmethod
    def ja3_hash(cls, profile: str = "chrome_120") -> str:
        return hashlib.md5(cls.ja3(profile).encode()).hexdigest()

    @classmethod
    def clear_cache(cls) -> None:
        try:
            with cls._lock:
                cls._cache.clear()
        except Exception:
            pass
        try:
            with _h2_lock:
                _h2_cache.clear()
        except Exception:
            pass


def build_fake_client_hello(sni: bytes | str, profile: str = "legacy") -> bytes:
    """Drop-in replacement for ClientHelloMaker.get_client_hello_with(...).

    Kept outside the class so main.py/fake_tcp.py don't need class imports.
    """
    return TlsFingerprintGenerator.get_client_hello(sni, profile)
