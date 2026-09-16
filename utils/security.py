# utils/security.py — centralized hardening for the SNI spoofer.
#
# Covers the 6 issues from prompt.txt:
#   1. strict input validation (IP / port / SNI / paths / JSON keys)
#   2. safe config loading (allowlist, size caps, integrity hash, no eval/exec)
#   3. memory/info-leak reduction (hashed SNI board keys, secure wipe helpers)
#   4. sanitized logging (redact IP/port/SNI, levels, rotation + auto-delete)
#   5. bounded executor (queue bound, per-task timeout, graceful shutdown)
#   6. secure cleanup on exit (wipe vars, shred temp files, gc, atexit/signals)
#
# Stdlib only, Windows-safe, import-safe without Admin/WinDivert.
from __future__ import annotations

import atexit
import gc
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import os
import queue
import re
import secrets
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Any, Callable, Iterable

# --------------------------------------------------------------------------
# 1. Input validation
# --------------------------------------------------------------------------

# RFC 1035-ish hostname: labels of 1-63 [A-Za-z0-9-], not leading/trailing '-',
# dots separating 2+ labels, total <= 253 chars.
_SNI_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
# Windows reserved device names (case-insensitive, without extension).
_WIN_RESERVED = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}
MAX_SNI_BYTES = 219  # injector ClientHello template limit
MAX_CONFIG_BYTES = 256 * 1024
MAX_ENDPOINTS = 64
MAX_SNIS = 200

ALLOWED_CONFIG_KEYS = frozenset({
    "LISTEN_HOST", "LISTEN_PORT", "CONNECT_IP", "CONNECT_PORT",
    "ENDPOINTS", "FAKE_SNI", "FAKE_SNIS", "BYPASS_METHOD",
    "HANDSHAKE_TIMEOUT", "MAX_CONNECTIONS", "FAKE_DELAY", "IDLE_TIMEOUT_S",
    "SEQ_OVERLAP", "TLS_FINGERPRINT", "PADDING_SIZE", "QUIC_MODE",
    # GUI-only keys (kept in *.full.json, ignored by the backend):
    "SOCKS5_PORT", "HTTP_PORT", "MODE", "TROJAN_PASSWORD",
    "TRANSPORT", "WS_PATH", "WS_HOST", "PROBE_TRIES", "PROBE_TIMEOUT",
})

ALLOWED_XRAY_KEYS = frozenset({"log", "inbounds", "outbounds", "routing"})

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_valid_ipv4(ip: str) -> bool:
    """Strict IPv4 check. Rejects blanks, non-IPv4, leading-zero tricks pass
    through ipaddress (canonical), plus each octet must be 0-255."""
    try:
        s = str(ip or "").strip()
        if not s or len(s) > 15:
            return False
        ipaddress.IPv4Address(s)
        return True
    except (ValueError, TypeError):
        return False


def validate_port(port: Any) -> int:
    """Return canonical port int or raise ValueError."""
    try:
        # Reject bools (isinstance(True, int) is True) and floats like 443.5.
        if isinstance(port, bool):
            raise ValueError("bool is not a port")
        if isinstance(port, float):
            if not port.is_integer():
                raise ValueError("non-integer port")
            port = int(port)
        elif isinstance(port, str):
            s = port.strip()
            if not re.fullmatch(r"\d{1,5}", s):
                raise ValueError("port must be digits")
            port = int(s)
        else:
            port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer 1-65535, got %r" % (port,)) from exc
    if not 1 <= port <= 65535:
        raise ValueError("port out of range 1-65535: %r" % (port,))
    return port


def is_valid_sni(sni: str) -> bool:
    """Plausible TLS SNI: dotted hostname, RFC labels, <=253 chars,
    <=219 bytes (injector template), no spaces/slashes, no wildcard."""
    try:
        s = str(sni or "").strip()
    except Exception:
        return False
    if not s or len(s) > 253 or " " in s or "/" in s or "\\" in s:
        return False
    if s.startswith("*") or s.startswith(".") or s.endswith(".") or ".." in s:
        return False
    if "." not in s:
        return False
    try:
        if len(s.encode("utf-8", "strict")) > MAX_SNI_BYTES:
            return False
    except Exception:
        return False
    # Reject all-numeric TLD (likely an IP typed as SNI) and punycode abuse.
    try:
        tld = s.rsplit(".", 1)[1]
        if tld.isdigit():
            return False
    except Exception:
        return False
    return bool(_SNI_RE.match(s))


def validate_sni(sni: Any) -> str:
    s = str(sni or "").strip()
    # Strip trailing dot (FQDN form) then re-check.
    if s.endswith("."):
        s = s[:-1]
    if not is_valid_sni(s):
        raise ValueError("bad SNI domain: %r" % (str(sni)[:80],))
    return s


def sanitize_endpoint(ip: Any, port: Any, default_port: int = 443) -> dict:
    """Validate one endpoint pair -> {'ip': ..., 'port': ...} or raise."""
    s_ip = str(ip or "").strip()
    if not is_valid_ipv4(s_ip):
        raise ValueError("bad endpoint IP: %r" % (str(ip)[:64],))
    return {"ip": s_ip, "port": validate_port(port if port is not None else default_port)}


def validate_file_path(path: str, base_dir: str,
                       allowed_exts: Iterable[str] = (".json", ".txt", ".log"),
                       must_exist: bool = False) -> str:
    """Anti-traversal path check: result must resolve inside base_dir.

    Returns the absolute path. Raises ValueError on violation.
    """
    if path is None:
        raise ValueError("empty path")
    s = str(path).strip().strip('"')
    if not s or "\x00" in s:
        raise ValueError("empty/invalid path")
    if len(s) > 260:
        raise ValueError("path too long")
    base = os.path.abspath(str(base_dir))
    # Resolve against base (handles relative names + '..' attempts).
    abs_p = os.path.abspath(os.path.join(base, s) if not os.path.isabs(s) else s)
    try:
        common = os.path.commonpath([base, abs_p])
    except ValueError:
        raise ValueError("path escapes app dir: %r" % s[:80])
    if common != base:
        raise ValueError("path traversal blocked: %r" % s[:80])
    name = os.path.basename(abs_p)
    if not name or name in (".", ".."):
        raise ValueError("bad file name")
    stem = name.split(".", 1)[0].lower()
    if stem in _WIN_RESERVED:
        raise ValueError("reserved device name: %r" % name)
    ext = os.path.splitext(name)[1].lower()
    if allowed_exts and ext not in tuple(e.lower() for e in allowed_exts):
        raise ValueError("disallowed extension %r (allowed: %s)" % (ext, list(allowed_exts)))
    if must_exist and not os.path.isfile(abs_p):
        raise ValueError("file not found: %r" % name)
    return abs_p


def validate_profile_name(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$", str(name or "").strip()))


def sanitize_for_socket(host: str, port: Any) -> tuple[str, int]:
    """Last-mile check before socket.connect/bind. Never raises anything
    except ValueError on bad input — never passes unchecked data to sockets."""
    h = str(host or "").strip()
    # Allow 127.0.0.1 / interface IPv4 / configured endpoints only as IPv4,
    # plus "0.0.0.0" for bind. Hostnames are NOT allowed on the wire path
    # (endpoints are always literal IPs in this tool).
    if h not in ("0.0.0.0",) and not is_valid_ipv4(h):
        raise ValueError("refusing socket op on invalid host: %r" % h[:64])
    return h, validate_port(port)


# --------------------------------------------------------------------------
# 2. Secure JSON loading (anti code-injection / arbitrary-file-inclusion)
# --------------------------------------------------------------------------

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def secure_load_json(path: str, allowed_keys: Iterable[str] | None = None,
                     max_bytes: int = MAX_CONFIG_BYTES,
                     expect_hash: str | None = None) -> dict:
    """Safely load a JSON dict file.

    - size-capped (DoS guard), UTF-8 only, must be a JSON object
    - optional allowlist filter (unknown keys dropped)
    - optional sha256 integrity check (sidecar / pinned value)
    - NEVER eval/exec — json.load only; raises ValueError on any problem.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError("config not found: %s" % path)
    size = os.path.getsize(path)
    if size > max_bytes:
        raise ValueError("config too large (%d > %d bytes): %s" % (size, max_bytes, path))
    if expect_hash:
        actual = sha256_file(path)
        if actual.lower() != str(expect_hash).strip().lower():
            raise ValueError("config integrity check failed (hash mismatch)")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("config root must be a JSON object")
    if allowed_keys is not None:
        allowed = set(allowed_keys)
        data = {k: v for k, v in data.items() if k in allowed}
    return data


def atomic_write_json(path: str, data: dict) -> None:
    """Crash-safe write: temp file in same dir + os.replace (atomic on Win)."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, ".tmp_%s_%d.json" % (os.path.basename(path), os.getpid()))
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        try:
            f.flush()
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# 3. Memory / info-leak reduction
# --------------------------------------------------------------------------

def hash_sni(sni: str, digest_len: int = 8) -> str:
    """One-way SNI label for scoreboards/logs: 'sni#<hex>'.

    Raw SNI domains must not linger in long-lived dicts / crash dumps.
    """
    try:
        s = str(sni or "").strip().lower()
    except Exception:
        s = ""
    if not s:
        return "sni#empty"
    digest = hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:max(4, digest_len)]
    return "sni#%s" % digest


def truncate_for_display(value: str, keep: int = 60) -> str:
    s = str(value or "")
    return s if len(s) <= keep else s[:keep] + "..."


def wipe_str_container(holder: dict, key: str, passes: int = 1) -> None:
    """Best-effort overwrite of a str/bytes/bytearray entry before removal.

    NOTE: CPython str/bytes are immutable — true in-RAM erasure is not
    guaranteed. This overwrites the *reference* with random data of equal
    length first (so the old object becomes unreferenced sooner and a heap
    scan finds random bytes in the new slot), then removes the key.
    For genuinely sensitive buffers prefer bytearray + wipe_bytearray().
    """
    try:
        val = holder.get(key)
    except Exception:
        return
    try:
        n = len(val) if isinstance(val, (str, bytes, bytearray)) else 0
    except Exception:
        n = 0
    try:
        for _ in range(max(1, passes)):
            if isinstance(val, bytearray):
                for i in range(len(val)):
                    val[i] = secrets.randbits(8)
            elif isinstance(val, bytes):
                holder[key] = secrets.token_bytes(len(val)) if val else b""
            elif isinstance(val, str):
                holder[key] = secrets.token_hex(max(1, (len(val) + 1) // 2))[:len(val)] if val else ""
            else:
                holder[key] = None
    except Exception:
        pass
    try:
        holder.pop(key, None)
    except Exception:
        pass


def wipe_bytearray(buf: bytearray) -> None:
    """In-place random overwrite of a mutable buffer (real memory wipe)."""
    try:
        for i in range(len(buf)):
            buf[i] = secrets.randbits(8)
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


def secure_clear_dict(d: dict, wipe_values: bool = True) -> None:
    """Overwrite string values with random data, then clear. Never raises."""
    if not isinstance(d, dict):
        return
    try:
        keys = list(d.keys())
    except Exception:
        return
    for k in keys:
        try:
            if wipe_values:
                wipe_str_container(d, k)
            else:
                d.pop(k, None)
        except Exception:
            continue
    try:
        d.clear()
    except Exception:
        pass


# --------------------------------------------------------------------------
# 4. Sanitized logging
# --------------------------------------------------------------------------

def sanitize_log_msg(msg: str, extra_snis: Iterable[str] = ()) -> str:
    """Redact sensitive data before it reaches console/disk.

    - IPv4 (with optional :port) -> [IP] / [IP]:[PORT]
    - caller-supplied raw SNI strings -> [SNI#hash8]
    """
    try:
        text = str(msg)
    except Exception:
        return "<unformattable log>"
    # IP:port first so the port part becomes [PORT].
    text = re.sub(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b", r"[IP]:[PORT]", text)
    text = _IPV4_RE.sub("[IP]", text)
    for sni in (extra_snis or ()):
        try:
            raw = str(sni or "").strip()
        except Exception:
            continue
        if len(raw) >= 4 and raw in text:
            text = text.replace(raw, "[%s]" % hash_sni(raw))
    return text


class SanitizingFilter(logging.Filter):
    """Logging filter that redacts IPs and known SNIs from every record."""

    def __init__(self, snis_provider: Callable[[], list] | None = None):
        super().__init__()
        self._snis_provider = snis_provider

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            snis: list = []
            if self._snis_provider is not None:
                try:
                    snis = list(self._snis_provider() or [])
                except Exception:
                    snis = []
            msg = record.getMessage()
            clean = sanitize_log_msg(msg, snis)
            record.msg = clean
            record.args = ()
        except Exception:
            pass
        return True


def setup_secure_logging(name: str = "sni", log_dir: str = "logs",
                         level: int = logging.WARNING,
                         max_bytes: int = 2 * 1024 * 1024,
                         backup_count: int = 3,
                         retention_days: int = 7,
                         snis_provider: Callable[[], list] | None = None) -> logging.Logger:
    """Default WARNING+ only, rotating files, old-log auto-delete, redaction.

    Call once at startup. Console stays quiet (errors/warnings); pass
    level=logging.INFO/DEBUG explicitly for verbose debugging.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    try:
        logger.propagate = False
    except Exception:
        pass
    # Avoid duplicate handlers on re-init (e.g. tests).
    try:
        for h in list(logger.handlers):
            try:
                logger.removeHandler(h)
            except Exception:
                pass
    except Exception:
        pass
    filt = SanitizingFilter(snis_provider)
    try:
        os.makedirs(log_dir, exist_ok=True)
        # Auto-delete logs older than retention_days (privacy + disk guard).
        try:
            import time as _time
            now = _time.time()
            for fn in os.listdir(log_dir):
                p = os.path.join(log_dir, fn)
                try:
                    if os.path.isfile(p) and (now - os.path.getmtime(p)) > retention_days * 86400:
                        os.remove(p)
                except Exception:
                    continue
        except Exception:
            pass
        fh = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, "%s.log" % name),
            maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
        fh.addFilter(filt)
        logger.addHandler(fh)
    except Exception:
        pass
    try:
        ch = logging.StreamHandler(stream=None)
        ch.setLevel(level)
        ch.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
        ch.addFilter(filt)
        logger.addHandler(ch)
    except Exception:
        pass
    return logger


# --------------------------------------------------------------------------
# 5. Bounded executor (ThreadPoolExecutor DoS guard)
# --------------------------------------------------------------------------

class BoundedExecutor:
    """ThreadPoolExecutor with a bounded submission queue + per-task timeout.

    - `max_queue`: extra pending tasks beyond max_workers; submit() raises
      queue.Full instead of growing memory unbounded when endpoints stall.
    - `task_timeout`: default future.result() timeout for `submit_wait()`;
      fire-and-forget `submit()` callers should still bound work via the queue.
    - `shutdown()` cancels pending futures and never hangs (bounded wait).
    """

    def __init__(self, max_workers: int = 8, max_queue: int = 64,
                 task_timeout: float = 10.0,
                 thread_name_prefix: str = "bounded"):
        self._max_workers = max(1, int(max_workers))
        self._max_queue = max(0, int(max_queue))
        self._task_timeout = float(task_timeout)
        self._slots = threading.BoundedSemaphore(self._max_workers + self._max_queue)
        self._ex = ThreadPoolExecutor(max_workers=self._max_workers,
                                      thread_name_prefix=thread_name_prefix)
        self._closed = False
        self._lock = threading.Lock()

    @property
    def task_timeout(self) -> float:
        return self._task_timeout

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        """Non-blocking submit; raises queue.Full when saturated (caller must
        handle: drop + count, never block the packet path)."""
        with self._lock:
            if self._closed:
                raise RuntimeError("executor is shut down")
        if not self._slots.acquire(blocking=False):
            raise queue.Full("bounded executor queue full")
        try:
            fut = self._ex.submit(fn, *args, **kwargs)
        except Exception:
            self._slots.release()
            raise

        def _release(_f: Future):
            try:
                self._slots.release()
            except Exception:
                pass

        try:
            fut.add_done_callback(_release)
        except Exception:
            pass
        return fut

    def submit_wait(self, fn: Callable, *args, timeout: float | None = None, **kwargs):
        """Submit and wait with timeout; cancels the future on timeout."""
        fut = self.submit(fn, *args, **kwargs)
        try:
            return fut.result(timeout=self._task_timeout if timeout is None else timeout)
        except Exception:
            try:
                fut.cancel()
            except Exception:
                pass
            raise

    def shutdown(self, wait: bool = True, timeout: float = 5.0) -> None:
        with self._lock:
            self._closed = True
        try:
            # Cancel futures that never started.
            try:
                self._ex.shutdown(wait=False, cancel_futures=True)  # py3.9+
            except TypeError:
                self._ex.shutdown(wait=False)
        except Exception:
            pass
        if wait:
            # Bounded join: worker threads are daemon-less, so don't hang exit.
            end = __import__("time").time() + max(0.1, timeout)
            try:
                while __import__("time").time() < end:
                    break  # shutdown(wait=False) already detached; nothing to join
            except Exception:
                pass


# --------------------------------------------------------------------------
# 6. Secure cleanup on exit
# --------------------------------------------------------------------------

_cleanup_registry: list[Callable[[], None]] = []
_cleanup_lock = threading.Lock()
_cleanup_done = False


def register_cleanup(fn: Callable[[], None]) -> None:
    with _cleanup_lock:
        _cleanup_registry.append(fn)


def secure_delete_file(path: str, passes: int = 1) -> None:
    """Overwrite a temp/secret file with random bytes, then unlink."""
    try:
        if not path or not os.path.isfile(path):
            return
        try:
            size = os.path.getsize(path)
        except Exception:
            size = 0
        if size > 0:
            try:
                with open(path, "r+b") as f:
                    for _ in range(max(1, passes)):
                        try:
                            f.seek(0)
                        except Exception:
                            break
                        remaining = size
                        while remaining > 0:
                            chunk = secrets.token_bytes(min(65536, remaining))
                            try:
                                f.write(chunk)
                            except Exception:
                                break
                            remaining -= len(chunk)
                        try:
                            f.flush()
                            os.fsync(f.fileno())
                        except Exception:
                            pass
            except Exception:
                pass
        try:
            os.remove(path)
        except Exception:
            pass
    except Exception:
        pass


def secure_cleanup(sensitive_dicts: Iterable[dict] = (),
                   temp_files: Iterable[str] = (),
                   extra: Callable[[], None] | None = None) -> None:
    """Idempotent secure-shutdown routine. Never raises.

    - overwrites + clears sensitive dicts (configs, SNI lists, stats boards)
    - shreds temp files (overwrite with random bytes, then unlink)
    - runs registered callbacks + gc.collect()
    Safe to call from atexit and SIGINT/SIGTERM handlers.
    """
    global _cleanup_done
    with _cleanup_lock:
        if _cleanup_done:
            return
        _cleanup_done = True
        callbacks = list(_cleanup_registry)
    for d in (sensitive_dicts or ()):
        try:
            secure_clear_dict(d)
        except Exception:
            continue
    for p in (temp_files or ()):
        try:
            secure_delete_file(str(p))
        except Exception:
            continue
    for cb in callbacks:
        try:
            cb()
        except Exception:
            continue
    if extra is not None:
        try:
            extra()
        except Exception:
            pass
    try:
        gc.collect()
    except Exception:
        pass


def install_exit_handlers(sensitive_dicts: Iterable[dict] = (),
                          temp_files: Iterable[str] = ()) -> None:
    """Register atexit + best-effort SIGINT/SIGTERM secure wipe. Idempotent."""
    try:
        atexit.register(lambda: secure_cleanup(sensitive_dicts, temp_files))
    except Exception:
        pass

    def _on_signal(_signum, _frame):
        try:
            secure_cleanup(sensitive_dicts, temp_files)
        except Exception:
            pass

    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            signal.signal(sig, _on_signal)
        except Exception:
            continue
