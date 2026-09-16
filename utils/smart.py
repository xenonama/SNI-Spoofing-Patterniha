# utils/smart.py — smart helpers: latency ranking, TLS reachability, health checks.
# Stdlib only, safe to run without Admin/WinDivert.
from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Curated candidate SNIs that are often allowed through DPI (user can edit).
SUGGESTED_SNIS = [
    "auth.vercel.com",
    "hcaptcha.com",
    "cloudflare.com",
    "www.cloudflare.com",
    "ajax.cloudflare.com",
    "cdn.jsdelivr.net",
    "www.gstatic.com",
    "www.google.com",
    "azureedge.net",
    "www.microsoft.com",
]

# Some well-known Cloudflare-ish endpoints to try when user has none.
SUGGESTED_ENDPOINTS = [
    {"ip": "188.114.98.0", "port": 443},
    {"ip": "188.114.96.0", "port": 443},
    {"ip": "104.21.0.0", "port": 443},
    {"ip": "172.67.0.0", "port": 443},
]


def tcp_ping(ip: str, port: int, timeout: float = 3.0, tries: int = 2) -> float | None:
    """Average TCP connect time in ms, or None if unreachable."""
    best: float | None = None
    for _ in range(max(1, tries)):
        t0 = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, int(port)))
            dt = (time.perf_counter() - t0) * 1000.0
            best = dt if best is None else min(best, dt)
        except OSError:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass
    return best


def rank_endpoints(endpoints: list[dict], timeout: float = 3.0,
                   tries: int = 2, max_workers: int = 8) -> list[dict]:
    """Return [{ip, port, latency_ms|None, ok}] sorted reachable-first by latency.

    Invalid IPs / empty lists are handled gracefully: they simply never
    become results (or fail individually), so callers can rank anything.
    """
    eps: list[dict] = []
    for e in (endpoints or []):
        try:
            ip = str((e or {}).get("ip", "")).strip()
            if not ip:
                continue
            eps.append({"ip": ip, "port": int((e or {}).get("port", 443))})
        except (TypeError, ValueError, AttributeError):
            continue
    results: list[dict] = []

    def probe(ep: dict) -> dict:
        lat = tcp_ping(ep["ip"], ep["port"], timeout=timeout,
                       tries=max(1, int(tries)))
        return {"ip": ep["ip"], "port": ep["port"],
                "latency_ms": round(lat, 1) if lat is not None else None,
                "ok": lat is not None}

    if not eps:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(eps))) as ex:
        futs = {ex.submit(probe, ep): ep for ep in eps}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception:
                ep = futs[fut]
                results.append({"ip": ep["ip"], "port": ep["port"], "latency_ms": None, "ok": False})
    results.sort(key=lambda r: (not r["ok"], r["latency_ms"] if r["latency_ms"] is not None else 1e9))
    return results


def tls_handshake_test(ip: str, port: int, sni: str, timeout: float = 5.0) -> dict:
    """Plain TLS handshake (no injector). Tells reachability, NOT DPI bypass success."""
    t0 = time.perf_counter()
    try:
        # Unverified context on purpose: endpoint IPs (e.g. Cloudflare ranges)
        # usually serve a cert that won't match the probed SNI/IP, and the
        # default verified context would report failure even when TCP+TLS
        # reachability is fine. We only care about reachability here.
        ctx = ssl._create_unverified_context()
        try:
            ctx.check_hostname = False
        except Exception:
            pass
        try:
            ctx.verify_mode = ssl.CERT_NONE
        except Exception:
            pass
        raw = socket.create_connection((ip, int(port)), timeout=timeout)
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=sni or None) as tls:
            tls.do_handshake()
            dt = (time.perf_counter() - t0) * 1000.0
            return {"ok": True, "latency_ms": round(dt, 1),
                    "tls_version": getattr(tls, "version", lambda: "?")(), "error": ""}
    except Exception as exc:
        return {"ok": False, "latency_ms": None, "tls_version": "", "error": str(exc)[:200]}


def rank_snis(ip: str, port: int, snis: list[str], timeout: float = 4.0,
              max_workers: int = 10) -> list[dict]:
    """TLS-handshake each SNI against ip:port ("ping the SNIs").

    Returns [{sni, latency_ms|None, ok, tls_version, error}] sorted
    reachable-first by latency. Plain TLS only (no injector) — it tells
    which SNIs the endpoint actually serves, NOT DPI bypass success.
    """
    names: list[str] = []
    seen: set[str] = set()
    for s in (snis or []):
        s = str(s).strip()
        if s and s not in seen:
            seen.add(s)
            names.append(s)

    def probe(sni: str) -> dict:
        res = tls_handshake_test(ip, int(port), sni, timeout=timeout)
        return {"sni": sni, "latency_ms": res["latency_ms"], "ok": res["ok"],
                "tls_version": res["tls_version"], "error": res["error"]}

    if not names or not str(ip or "").strip():
        return []
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(names))) as ex:
        futs = {ex.submit(probe, s): s for s in names}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append({"sni": futs[fut], "latency_ms": None,
                                "ok": False, "tls_version": "", "error": str(exc)[:200]})
    results.sort(key=lambda r: (not r["ok"], r["latency_ms"] if r["latency_ms"] is not None else 1e9))
    return results


def is_port_free(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def check_local_relay(host: str, port: int, timeout: float = 3.0) -> dict:
    """Is something accepting on the relay port? (run after START)."""
    lat = tcp_ping("127.0.0.1" if host == "0.0.0.0" else host, int(port), timeout=timeout, tries=1)
    return {"ok": lat is not None, "latency_ms": lat}
