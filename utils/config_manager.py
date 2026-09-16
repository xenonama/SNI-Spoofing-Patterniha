# utils/config_manager.py — v1/v2 config load, validate, migrate, save.
from __future__ import annotations

import copy
import ipaddress
import json
import os

DEFAULTS: dict = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "188.114.98.0",
    "CONNECT_PORT": 443,
    "ENDPOINTS": [],  # optional; if empty, built from CONNECT_IP/PORT
    "FAKE_SNI": "auth.vercel.com",
    "FAKE_SNIS": [],  # optional; if empty, built from FAKE_SNI
    "BYPASS_METHOD": "auto",
    "HANDSHAKE_TIMEOUT": 2.0,
    "MAX_CONNECTIONS": 200,
    "FAKE_DELAY": 0.001,
    "IDLE_TIMEOUT_S": 300.0,
    # GUI-only:
    "SOCKS5_PORT": 10808,
    "HTTP_PORT": 10809,
    "MODE": "SNI Only",
    "TROJAN_PASSWORD": "humanity",
    "TRANSPORT": "ws",
    "WS_PATH": "/assignment",
    "WS_HOST": "www.creationlong.org",
}

INJECTOR_KEYS = ("LISTEN_HOST", "LISTEN_PORT", "CONNECT_IP", "CONNECT_PORT",
                 "ENDPOINTS", "FAKE_SNI", "FAKE_SNIS", "BYPASS_METHOD",
                 "HANDSHAKE_TIMEOUT", "MAX_CONNECTIONS", "FAKE_DELAY",
                 "IDLE_TIMEOUT_S")

SUPPORTED_METHODS = ("auto", "wrong_seq", "wrong_seq_ttl", "split_seq", "fragmented", "padding", "delayed_retry", "double_sni")


def _as_int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _as_float(v, default):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def migrate(cfg: dict) -> dict:
    """Fill defaults + derive ENDPOINTS/FAKE_SNIS from legacy single values."""
    out = copy.deepcopy(DEFAULTS)
    out.update(cfg or {})
    # endpoints
    eps = out.get("ENDPOINTS")
    if not isinstance(eps, list) or not eps:
        ip = str(out.get("CONNECT_IP", "")).strip()
        port = _as_int(out.get("CONNECT_PORT", 443), 443)
        out["ENDPOINTS"] = [{"ip": ip, "port": port}] if ip else []
    else:
        norm = []
        for e in eps:
            if isinstance(e, dict) and e.get("ip"):
                norm.append({"ip": str(e["ip"]).strip(),
                             "port": _as_int(e.get("port", out.get("CONNECT_PORT", 443)), 443)})
            elif isinstance(e, str) and e.strip():
                norm.append({"ip": e.strip(), "port": _as_int(out.get("CONNECT_PORT", 443), 443)})
        out["ENDPOINTS"] = norm
    # snis
    snis = out.get("FAKE_SNIS")
    if not isinstance(snis, list) or not snis:
        s = str(out.get("FAKE_SNI", "")).strip()
        out["FAKE_SNIS"] = [s] if s else []
    else:
        out["FAKE_SNIS"] = [str(s).strip() for s in snis if str(s).strip()]
    out["BYPASS_METHOD"] = str(out.get("BYPASS_METHOD", "auto")).strip() or "auto"
    out["HANDSHAKE_TIMEOUT"] = _as_float(out.get("HANDSHAKE_TIMEOUT", 2.0), 2.0)
    out["MAX_CONNECTIONS"] = _as_int(out.get("MAX_CONNECTIONS", 200), 200)
    out["FAKE_DELAY"] = _as_float(out.get("FAKE_DELAY", 0.001), 0.001)
    out["IDLE_TIMEOUT_S"] = _as_float(out.get("IDLE_TIMEOUT_S", 300.0), 300.0)
    return out


def validate(cfg: dict) -> list[str]:
    errs: list[str] = []
    lh = str(cfg.get("LISTEN_HOST", "0.0.0.0")).strip()
    if lh != "0.0.0.0":
        try:
            ipaddress.IPv4Address(lh)
        except ValueError:
            errs.append(f"LISTEN_HOST invalid: {lh}")
    for key in ("LISTEN_PORT", "CONNECT_PORT", "SOCKS5_PORT", "HTTP_PORT"):
        try:
            n = int(cfg.get(key, 0))
            if not 1 <= n <= 65535:
                errs.append(f"{key} out of range 1-65535")
        except (TypeError, ValueError):
            errs.append(f"{key} must be a number")
    eps = cfg.get("ENDPOINTS") or []
    if not eps:
        errs.append("No endpoints (set CONNECT_IP or ENDPOINTS)")
    else:
        for e in eps:
            try:
                ipaddress.IPv4Address(str(e.get("ip", "")).strip())
            except ValueError:
                errs.append(f"Bad endpoint IP: {e}")
            try:
                p = int(e.get("port", 0))
                if not 1 <= p <= 65535:
                    errs.append(f"Bad endpoint port: {e}")
            except (TypeError, ValueError):
                errs.append(f"Bad endpoint port: {e}")
    snis = cfg.get("FAKE_SNIS") or []
    if not snis:
        errs.append("No FAKE_SNI set")
    else:
        for s in snis:
            s = str(s).strip()
            if not s or " " in s or "/" in s or "." not in s:
                errs.append(f"Bad SNI: {s}")
    if cfg.get("BYPASS_METHOD") not in SUPPORTED_METHODS:
        errs.append(f"BYPASS_METHOD must be one of {SUPPORTED_METHODS}")
    try:
        t = float(cfg.get("HANDSHAKE_TIMEOUT", 2.0))
        if not 0.5 <= t <= 10:
            errs.append("HANDSHAKE_TIMEOUT should be 0.5..10s")
    except (TypeError, ValueError):
        errs.append("HANDSHAKE_TIMEOUT must be a number")
    try:
        m = int(cfg.get("MAX_CONNECTIONS", 200))
        if not 10 <= m <= 2000:
            errs.append("MAX_CONNECTIONS should be 10..2000")
    except (TypeError, ValueError):
        errs.append("MAX_CONNECTIONS must be a number")
    try:
        it = float(cfg.get("IDLE_TIMEOUT_S", 300.0))
        if not 0 < it <= 3600:
            errs.append("IDLE_TIMEOUT_S should be 0 < s <= 3600")
    except (TypeError, ValueError):
        errs.append("IDLE_TIMEOUT_S must be a number")
    return errs


def load(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raw = {}
    except Exception:
        raw = {}
    # also merge .full.json GUI extras if present
    full_path = path + ".full.json"
    if os.path.exists(full_path):
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                extra = json.load(f)
            merged = dict(extra)
            merged.update(raw if isinstance(raw, dict) else {})
            # raw (config.json) wins for injector keys; extras fill GUI keys
            tmp = dict(raw if isinstance(raw, dict) else {})
            for k, v in (extra if isinstance(extra, dict) else {}).items():
                tmp.setdefault(k, v)
            raw = tmp
        except Exception:
            pass
    return migrate(raw if isinstance(raw, dict) else {})


def injector_dict(cfg: dict) -> dict:
    """Dict to write to config.json (what main.py reads)."""
    cfg = migrate(cfg)
    # Keep legacy single-value keys for compat + new lists.
    primary = cfg["ENDPOINTS"][0] if cfg["ENDPOINTS"] else {"ip": "", "port": 443}
    return {
        "LISTEN_HOST": cfg["LISTEN_HOST"],
        "LISTEN_PORT": int(cfg["LISTEN_PORT"]),
        "CONNECT_IP": primary["ip"],
        "CONNECT_PORT": int(primary["port"]),
        "ENDPOINTS": cfg["ENDPOINTS"],
        "FAKE_SNI": (cfg["FAKE_SNIS"][0] if cfg["FAKE_SNIS"] else ""),
        "FAKE_SNIS": cfg["FAKE_SNIS"],
        "BYPASS_METHOD": cfg["BYPASS_METHOD"],
        "HANDSHAKE_TIMEOUT": float(cfg["HANDSHAKE_TIMEOUT"]),
        "MAX_CONNECTIONS": int(cfg["MAX_CONNECTIONS"]),
        "FAKE_DELAY": float(cfg["FAKE_DELAY"]),
        "IDLE_TIMEOUT_S": float(cfg["IDLE_TIMEOUT_S"]),
    }


def save(path: str, cfg: dict) -> None:
    cfg = migrate(cfg)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(injector_dict(cfg), f, indent=2)
    with open(path + ".full.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
