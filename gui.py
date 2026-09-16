"""SNI Spoofing GUI v4 (Tkinter, Fluent-dark + animations).

Run:  python gui.py   (Windows 10, preferably as Administrator)
Stdlib only — works on Python 3.8+ (Windows 7 builds) through 3.14.
"""
from __future__ import annotations

import ctypes
import glob
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

if getattr(sys, "frozen", False):
    # PyInstaller onefile: __file__ points into the temp bundle dir,
    # but user data (config/lists/logs) lives next to the .exe.
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
XRAY_CONFIG_PATH = os.path.join(APP_DIR, "xray_config.json")
MAIN_PATH = os.path.join(APP_DIR, "main.py")
BACKEND_EXE = os.path.join(APP_DIR, "sni-backend.exe")
PROFILES_DIR = os.path.join(APP_DIR, "profiles")
LOGS_DIR = os.path.join(APP_DIR, "logs")
IP_LIST_PATH = os.path.join(APP_DIR, "ip_list.txt")
SNI_LIST_PATH = os.path.join(APP_DIR, "sni_list.txt")
# Window/taskbar icon: inside a frozen exe, PyInstaller --add-data unpacks
# app.ico into the temp bundle dir (_MEIPASS); otherwise use the copy next
# to the script/exe.
ICON_PATH = os.path.join(APP_DIR, "app.ico")
if getattr(sys, "frozen", False):
    try:
        _bundled_icon = os.path.join(getattr(sys, "_MEIPASS", ""), "app.ico")
        if os.path.isfile(_bundled_icon):
            ICON_PATH = _bundled_icon
    except Exception:
        pass
# Keep the WinDivert filter + failover list small. File lists can hold
# dozens of candidates; only the fastest few are written into config.
MAX_FILE_ENDPOINTS = 8

# Bypass methods shown in the GUI: (key, title, one-line description).
METHODS = (
    ("auto", "Auto  ★ recommended", "Rotates all methods per connection — best first choice"),
    ("wrong_seq", "Wrong sequence", "One fake packet with an old seq — most compatible"),
    ("wrong_seq_ttl", "Wrong seq + TTL", "Low-TTL trick — stronger against some DPI boxes"),
    ("split_seq", "Split sequence", "Fake handshake sent in 2 pieces — strict filters"),
    ("fragmented", "Fragmented (3 parts)", "Tear hello into 3 pieces — breaks weak DPI reassembly"),
    ("padding", "Padding (junk)", "Random leading bytes — abnormal length confuses DPI"),
    ("delayed_retry", "Delayed retry", "Wrong_seq first, split_seq retry after 1.5s"),
    ("double_sni", "Double SNI", "Fake + real SNI with delimiter in one packet"),
)

# Modes shown in the GUI: (key, title, description).
MODES = (
    ("SNI Only", "Direct relay", "Apps connect straight to the listen port."),
    ("Trojan + Xray", "Via Xray", "Needs xray.exe — adds SOCKS5 + HTTP proxy ports."),
)

from utils import config_manager as cm
from utils import smart
from utils import lists as lists_mod

# --------------------------------------------------------------------------
# Theme (Fluent-inspired dark)
# --------------------------------------------------------------------------
THEME = {
    "bg": "#0A0C10",        # window (deeper black)
    "sidebar": "#0D0F14",   # nav rail
    "card": "#181C24",       # cards
    "card_edge": "#2A2F3A",  # card border
    "input": "#1E232E",      # entries
    "input_edge": "#4FC3F7",  # entry focus ring
    "header": "#11141A",
    "accent": "#4FC3F7",
    "accent_dim": "#2A6FA0",
    "primary": "#2B88D8",
    "primary_hover": "#3D9CE8",
    "primary_press": "#1E6CB0",
    "success": "#3DDC84",
    "success_dim": "#1E7A4C",
    "danger": "#E5534B",
    "danger_hover": "#F26D66",
    "danger_press": "#B93A34",
    "warning": "#F5B544",
    "fg": "#FFFFFF",
    "muted": "#A0AAB8",
    "faint": "#5C6575",
    "disabled_bg": "#2A2F38",
    "disabled_fg": "#6B7280",
    "stats_bg": "#141922",
    "console_bg": "#10131A",
    "toggle_off": "#3A4150",
    "toggle_off_hover": "#454E60",
    "toggle_on": "#1FA055",
    "toggle_on_hover": "#27B563",
    "toggle_on_border": "#157A40",
    "toggle_text_on": "#FFFFFF",
    "toggle_text_off": "#8B95A7",
    "scroll_thumb": "#5C6575",
    "scroll_thumb_hover": "#7A8598",
    "scroll_thumb_press": "#9AA4B5",
    "scroll_thumb_disabled": "#2A2F3A",
    "selector_selected": "#1E2A36",
    "selector_hover": "#232A36",
    "btn_hover": "#252B36",
    "btn_press": "#22262E",
    "btn_border": "#343B49",
    "btn_shadow": "#04060A",
    "glow": "#4FC3F7",
}

# Modern font stack with graceful fallback (Win10/Win11, Python 3.8+).
# Tk falls back silently for missing families, so prefer newer names first.
# NOTE: Tk weight must be "bold"/"normal" — "semibold" raises TclError.
FONT_TITLE = ("Segoe UI Variable", 16, "bold")
FONT_SUB = ("Segoe UI Variable", 10)
FONT_H = ("Segoe UI Semibold", 10)
FONT_N = ("Segoe UI Variable", 10)
FONT_BTN = ("Segoe UI Semibold", 10)
FONT_MONO = ("Cascadia Code", 10)
FONT_MONO_FALLBACK = ("JetBrains Mono", 10)
FONT_STATUS = ("Segoe UI", 10, "bold")


# --------------------------------------------------------------------------
# Small helpers (unchanged behavior)
# --------------------------------------------------------------------------
def set_app_icon(window) -> None:
    """Apply app.ico to a Tk window (title bar, Alt-Tab, taskbar button).

    Also used as the DEFAULT for every Toplevel created later. Best-effort:
    a missing/invalid icon must never block startup. Never raises.
    """
    try:
        if os.path.isfile(ICON_PATH):
            window.iconbitmap(ICON_PATH)          # this window's title bar
            window.iconbitmap(default=ICON_PATH)  # default for child toplevels
    except Exception:
        pass


def set_windows_appusermodelid() -> None:
    """Give the process a stable AppUserModelID (Windows taskbar).

    Keeps the taskbar button separate from other python(w).exe windows so the
    embedded app icon is used for pinning/grouping. Only needed when running
    from source (a frozen exe is already identified by its own icon). Must be
    called BEFORE the first window is created. Never raises.
    """
    if sys.platform != "win32" or getattr(sys, "frozen", False):
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SNI.Spoofer.GUI")
    except Exception:
        pass


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(script: str) -> None:
    if getattr(sys, "frozen", False):
        # Frozen exe already carries a requireAdministrator manifest;
        # just restart the exe itself (no script arg exists in a bundle).
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, None, APP_DIR, 1)
    else:
        params = '"%s"' % script
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, APP_DIR, 1)
    sys.exit(0)


def check_pydivert():
    try:
        import pydivert  # noqa: F401
    except Exception as exc:
        return "pydivert import failed: %s" % exc
    return None


def find_xray_exe() -> str | None:
    """Search for xray.exe in likely locations. Returns full path or None.

    Order: XRAY_PATH env var -> APP_DIR -> APP_DIR subfolders
    (xray/, bin/) -> current working dir -> PATH (shutil.which).
    """
    try:
        env = (os.environ.get("XRAY_PATH") or "").strip().strip('"')
        if env and os.path.isfile(env):
            return os.path.abspath(env)
    except Exception:
        pass
    candidates: list = []
    try:
        candidates.append(os.path.join(APP_DIR, "xray.exe"))
        for sub in ("xray", "bin", "Xray"):
            candidates.append(os.path.join(APP_DIR, sub, "xray.exe"))
        candidates.append(os.path.join(os.getcwd(), "xray.exe"))
    except Exception:
        pass
    for path in candidates:
        try:
            if path and os.path.isfile(path):
                return os.path.abspath(path)
        except Exception:
            continue
    # PATH lookup (+ current dir on Windows via which).
    for name in ("xray.exe", "xray"):
        try:
            found = shutil.which(name)
        except Exception:
            found = None
        if found and os.path.isfile(found):
            return os.path.abspath(found)
    return None


def windivert_hint_for_error(err_text: str, already_admin: bool) -> str:
    """One-line actionable hint for a WinDivert open failure."""
    low = (err_text or "").lower()
    if "1058" in low or "cannot be started" in low or "disabled" in low:
        return ("WinDivert driver service cannot start (WinError 1058) — the "
                "driver is disabled/blocked, not just a rights issue. Fix: "
                "1) keep WinDivert64.sys next to pydivert, "
                "2) run 'sc qc WinDivert' — StartType must not be DISABLED "
                "('sc config WinDivert start= demand'), "
                "3) reboot after first install, "
                "4) disable VPN/antivirus filtering or Core-isolation Memory-integrity "
                "blocking the driver, 5) use matching bitness (64-bit Python on 64-bit Windows).")
    if "access is denied" in low or "5" in low and "denied" in low:
        if already_admin:
            return ("WinDivert: Access denied even as Administrator — driver blocked "
                    "(antivirus / GPO / Memory integrity) or another WinDivert handle holds it. "
                    "Reboot, then try again.")
        return "WinDivert failed — relaunch GUI as Administrator (RUN AS ADMIN) and press START again."
    if already_admin:
        return ("WinDivert open failed while Administrator — driver blocked/missing. "
                "Reinstall pydivert (pip install --force-reinstall pydivert), reboot, "
                "and check antivirus / Memory integrity settings.")
    return "WinDivert failed — run GUI as Administrator (RUN AS ADMIN) and press START again."


def diagnose_windivert_driver() -> str | None:
    """Return a warning string if WinDivert driver files/service look broken, else None."""
    try:
        import pydivert  # noqa: F401
        import pydivert.windrivert_dll  # noqa
    except Exception:
        pass
    try:
        import os as _os
        import pydivert as _pd
        base = _os.path.dirname(_pd.__file__)
        dll_dir = _os.path.join(base, "windivert_dll")
        has_sys = (_os.path.isfile(_os.path.join(dll_dir, "WinDivert64.sys"))
                   or _os.path.isfile(_os.path.join(dll_dir, "WinDivert32.sys")))
        if not has_sys:
            return "WinDivert driver files (.sys) missing from pydivert package — reinstall pydivert."
    except Exception:
        pass
    # Service stuck in Stop-Pending / Disabled is the classic 1058 cause.
    if sys.platform == "win32":
        try:
            out = subprocess.run(["sc", "qc", "WinDivert"], capture_output=True,
                                 text=True, timeout=5)
            txt = (out.stdout or "") + (out.stderr or "")
            if "DISABLED" in txt.upper():
                return ("WinDivert service is DISABLED (sc qc WinDivert) — "
                        "run 'sc config WinDivert start= demand' as Administrator, then reboot.")
        except Exception:
            pass
    return None


def backend_cmd(*args: str) -> list:
    """Command to launch the injector backend.

    Source runs: [python, main.py, ...]. Frozen exe runs: the sibling
    sni-backend.exe (a frozen GUI must not re-exec itself as backend).
    """
    if getattr(sys, "frozen", False):
        return [BACKEND_EXE] + list(args)
    return [sys.executable, MAIN_PATH] + list(args)


def _is_noise_line(line: str) -> bool:
    """True for harmless-but-spammy injector output that should not hit the console."""
    low = line.lower()
    if "cancelling an overlapped future failed" in low:
        return True
    if "_overlappedfuture" in low and ("winerror 6" in low or "handle is invalid" in low):
        return True
    if "asyncio/windows_events.py" in low and "cancel" in low:
        return True
    if low.strip() in ("future: <_overlappedfuture pending cb=[task.task_wakeup()]>",):
        return True
    return False


def _is_overlapped_tail(line: str) -> bool:
    """Companion lines of the overlapped-cancel spam burst (traceback body)."""
    low = line.lower().strip()
    if low.startswith("future: <_overlappedfuture"):
        return True
    if low == "traceback (most recent call last):":
        return True
    if low.startswith('file "') and "windows_events.py" in low:
        return True
    if low == "self._ov.cancel()":
        return True
    s = low.replace(" ", "")
    if s and set(s) <= set("~^"):
        return True
    if low.startswith("oserror: [winerror 6]"):
        return True
    return False


def _is_routine_injector_line(line: str) -> bool:
    """True for routine per-packet injector chatter that is always hidden.

    These lines are correct but extremely repetitive (one per failed bypass):
    'unexpected ... packet ...', 'reinject ...', 'fake_send failed', etc.
    Stats counters (OK/Fail) + traffic already summarize them, so the console
    never shows them (Verbose toggle removed). Startup lines, FATAL errors and
    smart-tool output are NOT routine and always pass through.
    """
    low = line.lower()
    if "unexpected " in low and "packet" in low:
        return True
    for pat in ("reinject ", "fake_send failed",
                "packet with unknown direction",
                "forward unknown-direction",
                "inject error (surviving)"):
        if pat in low:
            return True
    return False


def save_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def build_xray_config(listen_port: int, socks_port: int, http_port: int,
                       password: str, transport: str, ws_path: str, ws_host: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"port": socks_port, "protocol": "socks",
             "settings": {"udp": True, "auth": "noauth"},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"port": http_port, "protocol": "http",
             "settings": {"accounts": [], "allowTransparent": False},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
        ],
        "outbounds": [
            {"protocol": "trojan",
             "settings": {"servers": [
                 {"address": "127.0.0.1", "port": listen_port, "password": password}]},
             "streamSettings": {
                 "network": transport,
                 "wsSettings": {"path": ws_path, "headers": {"Host": ws_host}}}},
            {"protocol": "freedom", "tag": "direct", "settings": {}},
        ],
        "routing": {"rules": [
            {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]}]},
    }


def parse_host_list(text: str, default_port: int) -> list:
    """Parse 'ip, ip:port, ...' separated by comma/space/newline."""
    out: list = []
    tokens = text.replace(",", " ").replace(";", " ").split()
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        if ":" in tok:
            ip, _, port_s = tok.partition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
        else:
            ip, port = tok, default_port
        out.append({"ip": ip.strip(), "port": port})
    return out


def parse_sni_list(text: str) -> list:
    parts = text.replace(",", " ").replace(";", " ").split()
    seen, out = set(), []
    for p in parts:
        p = p.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def list_profiles() -> list:
    try:
        os.makedirs(PROFILES_DIR, exist_ok=True)
        names = []
        for path in glob.glob(os.path.join(PROFILES_DIR, "*.json")):
            base = os.path.basename(path)
            if base.endswith(".full.json"):
                continue
            names.append(os.path.splitext(base)[0])
        return sorted(names)
    except Exception:
        return []


def valid_profile_name(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$", name.strip()))


def fmt_bytes(n) -> str:
    """Human size: 0 B, 1.5 KB, 23.4 MB, 2.0 GB."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0 B"
    if n < 0:
        n = 0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024
    return "%.1f TB" % n


# --------------------------------------------------------------------------
# Animated widgets
# --------------------------------------------------------------------------
def _round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    """Draw a rounded rectangle; returns item id."""
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
           x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1, x1 + r, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


def _hex_to_rgb(h: str) -> tuple:
    """'#RRGGBB' -> (r, g, b). Falls back to mid-gray on bad input."""
    try:
        h = str(h).strip().lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
    except Exception:
        return (128, 128, 128)


def _rgb_to_hex(rgb: tuple) -> str:
    try:
        r, g, b = (max(0, min(255, int(v))) for v in rgb)
        return "#%02X%02X%02X" % (r, g, b)
    except Exception:
        return "#808080"


def _mix_hex(a: str, b: str, t: float) -> str:
    """Linear blend of two hex colors. t=0 -> a, t=1 -> b."""
    try:
        t = max(0.0, min(1.0, float(t)))
    except Exception:
        t = 1.0
    ar, ag, ab = _hex_to_rgb(a)
    br, bg, bb = _hex_to_rgb(b)
    return _rgb_to_hex((ar + (br - ar) * t, ag + (bg - ag) * t, ab + (bb - ab) * t))


class ModernButton(tk.Canvas):
    """Rounded button with border, shadow, tweened hover/press + disabled state.

    Compatible subset: .config(state=...), .pack/.grid/.place as usual.
    """

    STYLES = {
        "primary": (THEME["primary"], THEME["primary_hover"], THEME["primary_press"], "#FFFFFF"),
        "danger": (THEME["danger"], THEME["danger_hover"], THEME["danger_press"], "#FFFFFF"),
        "ghost": (THEME["card"], THEME["btn_hover"], THEME["btn_press"], THEME["fg"]),
        "accent": ("#1F6F9B", "#2A86B8", "#185A7D", "#FFFFFF"),
    }
    # Per-style 1px edge color for the resting state (subtle premium border).
    BORDERS = {
        "primary": "#5AB4EE",
        "danger": "#F2847E",
        "ghost": THEME["btn_border"],
        "accent": "#3FA9D6",
    }

    def __init__(self, parent, text="", command=None, style="ghost", height=34,
                 font=FONT_BTN, align="center", radius=9, focusable=True):
        super().__init__(parent, height=height, bg=THEME["card"] if style == "ghost" else THEME["bg"],
                         highlightthickness=0, bd=0, cursor="hand2")
        try:
            self.configure(takefocus=1 if focusable else 0)
        except Exception:
            pass
        self._focusable = bool(focusable)
        self._text = text
        self._command = command
        self._style = style
        self._font = font
        self._align = align
        self._radius = radius
        self._enabled = True
        self._hover = False
        self._press = False
        self._focused = False
        self._fill = self.STYLES[style][0]
        # Displayed fill animates toward the target for a smooth hover fade.
        self._disp_fill = self.STYLES[style][0]
        self._tween_id = None
        self._draw_pending = None
        self._body = None
        self._label = None
        self.bind("<Configure>", lambda e: self._request_draw())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        try:
            self.bind("<FocusIn>", lambda e: self._on_focus(True))
            self.bind("<FocusOut>", lambda e: self._on_focus(False))
            self.bind("<Return>", lambda e: self._keyboard_activate())
            self.bind("<space>", lambda e: self._keyboard_activate())
            self.bind("<Destroy>", lambda e: (self._cancel_tween(), self._cancel_pending_draw()), add="+")
        except Exception:
            pass
        self._draw()

    def set_style(self, style: str, animate: bool = False):
        """Switch style cleanly: snap tween state + redraw. Never raises."""
        try:
            if style not in self.STYLES:
                return
            if style == getattr(self, "_style", None):
                self._draw()
                return
            self._style = style
            self._cancel_tween()
            try:
                self._disp_fill = self.STYLES[style][0]
                self._fill = self._disp_fill
            except Exception:
                pass
            if animate and self._enabled:
                self._refresh(animate=True)
            else:
                self._draw()
        except Exception:
            pass

    def _cancel_tween(self):
        try:
            if getattr(self, "_tween_id", None) is not None:
                try:
                    self.after_cancel(self._tween_id)
                except Exception:
                    pass
                self._tween_id = None
        except Exception:
            pass
        self._cancel_pending_draw()

    def _cancel_pending_draw(self):
        try:
            if getattr(self, "_draw_pending", None) is not None:
                try:
                    self.after_cancel(self._draw_pending)
                except Exception:
                    pass
                self._draw_pending = None
        except Exception:
            pass

    def _request_draw(self, delay: int = 10):
        """Collapse rapid <Configure> bursts into a single repaint.

        Without this, initial packing fires dozens of resizes and every
        button redraws synchronously, stalling cold start.
        """
        try:
            if getattr(self, "_draw_pending", None) is not None:
                return
            self._draw_pending = self.after(
                max(0, int(delay)), self._flush_draw)
        except Exception:
            pass

    def _flush_draw(self):
        try:
            self._draw_pending = None
        except Exception:
            pass
        try:
            if not self.winfo_exists():
                return
            self._draw()
        except Exception:
            pass

    # -- compat ------------------------------------------------------
    def config(self, **kw):
        if "state" in kw:
            st = kw.pop("state")
            self._enabled = (st == tk.NORMAL)
            self.configure(cursor="hand2" if self._enabled else "arrow")
            # Snap fill on enable/disable to avoid a grey flash; hover fades
            # resume via tween on the next enter/leave.
            self._refresh(animate=False)
        if "text" in kw:
            self._text = kw.pop("text")
            self._draw()
        if "command" in kw:
            self._command = kw.pop("command")
        if kw:
            super().config(**kw)

    def cget(self, key):
        if key == "state":
            return tk.NORMAL if self._enabled else tk.DISABLED
        return super().cget(key)

    # -- rendering ---------------------------------------------------
    def _colors(self):
        base, hov, press, fg = self.STYLES[self._style]
        if not self._enabled:
            return THEME["disabled_bg"], THEME["disabled_fg"]
        if self._press:
            return press, fg
        if self._hover:
            return hov, fg
        return base, fg

    def _border_color(self):
        if not self._enabled:
            return THEME["card_edge"]
        if self._focused or self._hover:
            if self._style == "primary":
                return "#7CC6F5"
            if self._style == "danger":
                return "#F5A09B"
            if self._style == "accent":
                return THEME["accent"]
            return "#4A5263"
        return self.BORDERS.get(self._style, THEME["btn_border"])

    def _draw(self):
        try:
            ww = self.winfo_width()
        except Exception:
            return
        # No deferred retry loop here: hidden pages (place_forget) keep
        # width==1 until first shown, and an after(15,_draw) reschedule
        # would flood the event queue at startup (the observed freeze).
        # Draw a cheap placeholder at any size; <Configure> repaints us
        # via _request_draw once real geometry arrives.
        w = max(2, ww)
        h = max(2, self.winfo_height())
        _fill_target, fg = self._colors()
        # Use the tweened fill so hover fades smoothly; snap on first draw
        # or when disabled to avoid a grey flash.
        try:
            fill = self._disp_fill if self._enabled else _fill_target
        except Exception:
            fill = _fill_target
        border = self._border_color()
        self.delete("all")
        bg = self.cget("bg")
        # Soft drop shadow fully inside the canvas so nothing peeks above
        # the button (previous dy=+2 box was clipped and read as a line).
        if self._enabled:
            try:
                _round_rect(self, 1, 2, w - 1, h - 1, self._radius,
                            fill=THEME["btn_shadow"], outline="")
            except Exception:
                pass
        self._body = _round_rect(self, 1, 1, w - 1, h - 1,
                                 self._radius, fill=fill, outline=border)
        # Single solid inner sheen (no stipple: stippled lines render as
        # dotted "-----" dashes on Windows). Inset by radius so it never
        # touches the rounded corners, skipped on tiny/pre-layout sizes.
        try:
            if self._enabled and w >= 60 and h >= 20:
                sheen = _mix_hex(fill, "#FFFFFF", 0.10)
                x0 = min(max(self._radius + 2, 10), w // 2)
                x1 = max(min(w - self._radius - 2, w - 10), w // 2)
                if x1 > x0:
                    self.create_line(x0, 2, x1, 2, fill=sheen)
        except Exception:
            pass
        # Keyboard focus ring (sidebar buttons opt out via focusable=False).
        if self._focused and self._enabled and getattr(self, "_focusable", True):
            try:
                _round_rect(self, 0, 0, w, h - 1, self._radius + 1,
                            fill="", outline=THEME["accent"])
            except Exception:
                pass
        anchor = "w" if self._align == "left" else "center"
        x = 14 if self._align == "left" else w / 2
        # 1px pressed dip for tactile click feel.
        try:
            y = h / 2 + (1 if self._press else 0)
        except Exception:
            y = h / 2
        self._label = self.create_text(x, y, text=self._text, font=self._font,
                                       fill=fg, anchor=anchor)
        self.configure(bg=bg)

    def _tween_to(self, target: str, steps: int = 5, delay: int = 12):
        """Animate displayed fill toward target hex color."""
        self._cancel_tween()
        try:
            start = self._disp_fill
        except Exception:
            start = target
        # Hidden buttons (inactive pages) must never animate: snap so no
        # after() chain runs offscreen during startup.
        try:
            hidden = not self.winfo_ismapped()
        except Exception:
            hidden = False
        if hidden or start == target or not self._enabled:
            try:
                self._disp_fill = target
            except Exception:
                pass
            self._draw()
            return

        def _step(i: int = 1):
            try:
                if not self.winfo_exists():
                    return
                self._disp_fill = _mix_hex(start, target, i / max(1, steps))
                self._draw()
                if i < steps:
                    self._tween_id = self.after(delay, lambda: _step(i + 1))
                else:
                    self._tween_id = None
            except Exception:
                try:
                    self._tween_id = None
                except Exception:
                    pass
        _step(1)

    def _refresh(self, animate: bool = True):
        try:
            target = self._colors()[0]
        except Exception:
            self._draw()
            return
        if animate and self._enabled:
            self._tween_to(target)
        else:
            self._cancel_tween()
            try:
                self._disp_fill = target
            except Exception:
                pass
            self._draw()

    def _on_enter(self, e):
        if not self._enabled:
            return
        self._hover = True
        self._refresh(animate=True)

    def _on_leave(self, e):
        self._hover = False
        self._press = False
        self._refresh(animate=True)

    def _on_press(self, e):
        if not self._enabled:
            return
        if getattr(self, "_focusable", True):
            try:
                self.focus_set()
            except Exception:
                pass
        self._press = True
        self._refresh(animate=False)

    def _on_release(self, e):
        was = self._press
        self._press = False
        self._refresh(animate=True)
        if was and self._enabled and self._command:
            # click animation: quick dip then fire
            self.after(40, lambda: self._command() if self._enabled else None)

    def _on_focus(self, focused: bool):
        if not getattr(self, "_focusable", True):
            self._focused = False
            return
        self._focused = bool(focused)
        self._draw()

    def _keyboard_activate(self):
        if not self._enabled or not self._command:
            return
        if not getattr(self, "_focusable", True):
            return
        self._press = True
        self._draw()
        self.after(80, self._fire_from_keyboard)

    def _fire_from_keyboard(self):
        self._press = False
        self._draw()
        try:
            if self._enabled and self._command:
                self._command()
        except Exception:
            pass


class ToggleSwitch(tk.Canvas):
    """Fluent-style pill toggle with ON/OFF text, focus ring + keyboard.

    Compatible subset: .toggle(), .config(state=...), .cget("state").
    Click, Space/Return and programmatic var.set() all animate the knob.
    """

    def __init__(self, parent, variable, width=52, height=28, command=None,
                 bg=None, state=tk.NORMAL):
        super().__init__(parent, width=width, height=height,
                         bg=bg or THEME["card"], highlightthickness=0, bd=0,
                         cursor="hand2")
        try:
            self.configure(takefocus=1)
        except Exception:
            pass
        self.var = variable
        self._command = command
        self._tw, self._th = width, height
        self._hover = False
        self._press = False
        self._focused = False
        self._enabled = (state == tk.NORMAL)
        self._knob = None  # animated knob center-x; None = snap on next draw
        self._anim_id = None
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        try:
            self.bind("<Enter>", lambda e: self._set_hover(True))
            self.bind("<Leave>", lambda e: self._on_leave())
            self.bind("<FocusIn>", lambda e: self._on_focus(True))
            self.bind("<FocusOut>", lambda e: self._on_focus(False))
            self.bind("<Return>", lambda e: self.toggle())
            self.bind("<space>", lambda e: self.toggle())
            self.bind("<Destroy>", lambda e: self._cancel_anim(), add="+")
        except Exception:
            pass
        self._draw()
        try:
            self.var.trace_add("write", lambda *a: self._animate())
        except Exception:
            pass
        self._sync_cursor()

    # -- public ------------------------------------------------------
    def toggle(self):
        if not self._enabled:
            return
        try:
            self.var.set(not self.var.get())
        except Exception:
            pass
        self._animate()
        if self._command is not None:
            try:
                self._command(bool(self.var.get()))
            except Exception:
                pass

    def config(self, **kw):
        if "state" in kw:
            self._enabled = (kw.pop("state") == tk.NORMAL)
            self._sync_cursor()
            self._draw()
        if "command" in kw:
            self._command = kw.pop("command")
        if kw:
            super().config(**kw)

    configure = config

    def cget(self, key):
        if key == "state":
            return tk.NORMAL if self._enabled else tk.DISABLED
        return super().cget(key)

    # -- events ------------------------------------------------------
    def _sync_cursor(self):
        try:
            self.configure(cursor="hand2" if self._enabled else "arrow")
        except Exception:
            pass

    def _set_hover(self, on: bool):
        if not self._enabled:
            return
        self._hover = bool(on)
        self._draw()

    def _on_leave(self):
        self._hover = False
        self._press = False
        self._draw()

    def _on_focus(self, focused: bool):
        self._focused = bool(focused)
        self._draw()

    def _on_press(self, _e=None):
        if not self._enabled:
            return
        try:
            self.focus_set()
        except Exception:
            pass
        self._press = True
        self._draw()

    def _on_release(self, _e=None):
        if not self._enabled:
            self._press = False
            return
        was = self._press
        self._press = False
        self._draw()
        if was:
            self.toggle()

    def _target_x(self) -> float:
        try:
            on = bool(self.var.get())
        except Exception:
            on = False
        _w, _h, r = self._tw, self._th, self._th / 2
        return (_w - r - 2) if on else (r + 2)

    def _cancel_anim(self):
        try:
            if self._anim_id is not None:
                try:
                    self.after_cancel(self._anim_id)
                except Exception:
                    pass
                self._anim_id = None
        except Exception:
            pass

    def _animate(self, steps: int = 7, delay: int = 12):
        self._cancel_anim()
        try:
            target = self._target_x()
            start = self._knob if self._knob is not None else target
        except Exception:
            self._draw()
            return
        if abs(start - target) < 0.5:
            self._knob = target
            self._draw()
            return

        def _step(i: int = 1):
            try:
                if not self.winfo_exists():
                    return
                try:
                    if not self.winfo_ismapped():
                        self._knob = target
                        self._draw()
                        self._anim_id = None
                        return
                except Exception:
                    pass
                t = i / max(1, steps)
                e = t * t * (3 - 2 * t)  # smoothstep ease
                self._knob = start + (target - start) * e
                self._draw()
                if i < steps:
                    self._anim_id = self.after(delay, lambda: _step(i + 1))
                else:
                    self._anim_id = None
            except Exception:
                try:
                    self._anim_id = None
                except Exception:
                    pass
        _step(1)

    def _track_colors(self, on: bool):
        if not self._enabled:
            return THEME["disabled_bg"], THEME["card_edge"]
        if on:
            base = THEME["toggle_on_hover"] if self._hover else THEME["toggle_on"]
            border = THEME["accent"] if (self._focused or self._hover) \
                else THEME.get("toggle_on_border", THEME["success_dim"])
            return base, border
        base = THEME["toggle_off_hover"] if self._hover else THEME["toggle_off"]
        border = THEME["accent"] if self._focused else THEME["btn_border"]
        return base, border

    def _draw(self):
        self.delete("all")
        try:
            on = bool(self.var.get())
        except Exception:
            on = False
        w, h, r = self._tw, self._th, self._th / 2
        track, border = self._track_colors(on)
        # Keyboard focus ring outside the track.
        if self._focused and self._enabled:
            try:
                _round_rect(self, 0, 0, w, h, r + 1, fill="", outline=THEME["accent"])
            except Exception:
                pass
        _round_rect(self, 1, 1, w - 1, h - 1, r, fill=track, outline=border)
        # Solid top sheen (no stipple: stipple renders as dashes on Windows).
        try:
            self.create_line(10, 2, w - 10, 2, fill=_mix_hex(track, "#FFFFFF", 0.18))
        except Exception:
            pass
        # ON/OFF glyph on the free side of the knob.
        try:
            txt = "ON" if on else "OFF"
            fg = THEME["toggle_text_on"] if on else THEME["toggle_text_off"]
            if not self._enabled:
                fg = THEME["disabled_fg"]
            tx = 13 if on else (w - 14)
            self.create_text(tx, h / 2 + 0.5, text=txt,
                             font=("Segoe UI", 7, "bold"), fill=fg)
        except Exception:
            pass
        if self._knob is None:
            knob_x = self._target_x()
            self._knob = knob_x
        else:
            knob_x = self._knob
        kr = h / 2 - 4
        stretch = 2 if (self._press and self._enabled) else 0
        try:
            cy = h / 2 + (1 if self._press else 0)
        except Exception:
            cy = h / 2
        # Knob shadow (solid, no stipple) + bright knob.
        try:
            self.create_oval(knob_x - kr - stretch, cy - kr + 2,
                             knob_x + kr + stretch, cy + kr + 1,
                             fill=THEME["btn_shadow"], outline="")
        except Exception:
            pass
        self.create_oval(knob_x - kr - stretch, cy - kr,
                         knob_x + kr + stretch, cy + kr,
                         fill="#FFFFFF" if self._enabled else THEME["disabled_fg"],
                         outline="#C9D2DE" if self._enabled else THEME["card_edge"])


SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


class Toast:
    """Fading bottom-right notification."""

    _active: list = []

    def __init__(self, root: tk.Tk, text: str, kind: str = "info"):
        self.root = root
        color = {"info": THEME["accent"], "success": THEME["success"],
                 "warning": THEME["warning"], "error": THEME["danger"]}.get(kind, THEME["accent"])
        self.win = tk.Toplevel(root)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        try:
            self.win.attributes("-alpha", 0.0)
        except Exception:
            pass
        frame = tk.Frame(self.win, bg=THEME["console_bg"], highlightbackground=color,
                         highlightthickness=1)
        frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(frame, text=text, font=FONT_N, fg=THEME["fg"], bg=THEME["console_bg"],
                 wraplength=300, justify=tk.LEFT).pack(padx=14, pady=10)
        Toast._active.append(self.win)
        if len(Toast._active) > 3:
            try:
                Toast._active[0].destroy()
            except Exception:
                pass
            Toast._active = Toast._active[-3:]
        self._place()
        self._fade_in()

    def _place(self):
        try:
            self.root.update_idletasks()
            rx, ry = self.root.winfo_x(), self.root.winfo_y()
            rw, rh = self.root.winfo_width(), self.root.winfo_height()
            self.win.update_idletasks()
            ww, wh = self.win.winfo_width(), self.win.winfo_height()
            stack = Toast._active.index(self.win)
            self.win.geometry("+%d+%d" % (rx + rw - ww - 24, ry + rh - wh - 24 - stack * (wh + 10)))
        except Exception:
            pass

    def _fade_in(self, a=0.0):
        try:
            a = min(0.96, a + 0.16)
            self.win.attributes("-alpha", a)
            if a < 0.96:
                self.win.after(15, lambda: self._fade_in(a))
            else:
                self.win.after(1500, lambda: self._fade_out(0.96))
        except Exception:
            pass

    def _fade_out(self, a):
        try:
            a = max(0.0, a - 0.16)
            self.win.attributes("-alpha", a)
            if a <= 0.0:
                self.win.destroy()
                if self.win in Toast._active:
                    Toast._active.remove(self.win)
            else:
                self.win.after(25, lambda: self._fade_out(a))
        except Exception:
            pass


# --------------------------------------------------------------------------
# Main GUI
# --------------------------------------------------------------------------
class SpooferGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SNI Spoofer")
        self.root.geometry("1060x760")
        self.root.minsize(940, 660)
        self.root.configure(bg=THEME["bg"])
        # Fast startup: show the window immediately at full opacity.
        # (Previous -alpha 0.0 + fade kept the app invisible while the
        # initial layout/animation storm ran, reading as a freeze.)
        try:
            self.root.attributes("-alpha", 1.0)
        except Exception:
            pass

        self._style = ttk.Style()
        try:
            self._style.theme_use("clam")
        except Exception:
            pass
        self._style.configure("Modern.TCombobox", fieldbackground=THEME["input"],
                              background=THEME["input"], foreground=THEME["fg"],
                              arrowcolor=THEME["accent"], borderwidth=0)
        self._style.configure("Modern.Horizontal.TProgressbar", background=THEME["accent"],
                              troughcolor=THEME["header"], borderwidth=0, thickness=4)
        # Windows 10 look: thin (~12px) square thumb blended into the
        # trough, no arrow buttons, grey thumb that lightens on hover.
        # clam cannot do rounded thumbs, so square is the honest match.
        # NOTE: ttk.Scrollbar has no -width option; in clam the bar
        # thickness tracks `arrowsize`, so arrows are dropped from the
        # layout entirely and arrowsize=12 purely sets the ~12px width.
        _win10_layout = [("Vertical.Scrollbar.trough", {
            "sticky": "ns", "children": [
                ("Vertical.Scrollbar.thumb", {"sticky": "nswe"})]})]
        for _sb_style, _trough in (("Modern.Vertical.TScrollbar", THEME["bg"]),
                                   ("Console.Vertical.TScrollbar", THEME["card"])):
            try:
                self._style.layout(_sb_style, _win10_layout)
            except Exception:
                pass
            self._style.configure(
                _sb_style, background=THEME["scroll_thumb"],
                troughcolor=_trough, borderwidth=0, relief="flat",
                arrowsize=12, gripcount=0, lightcolor=_trough,
                darkcolor=_trough, bordercolor=_trough)
            try:
                self._style.map(
                    _sb_style,
                    background=[("pressed", THEME["scroll_thumb_press"]),
                                ("active", THEME["scroll_thumb_hover"]),
                                ("disabled", THEME["scroll_thumb_disabled"])])
            except Exception:
                pass

        self.injector_proc = None
        self.xray_proc = None
        self.injector_reader = None
        self.xray_reader = None
        self._run_id = 0
        self._child_job = None
        self._last_stats_t = 0.0
        self._no_stats_warned = False
        self._traffic_warn_done = False
        self._stats_seen = False
        self.running = False
        self.manual_stop = False
        self.start_time = None
        self.msg_q = queue.Queue()
        self.active_conns = 0
        self.total_conns = 0
        self.success_conns = 0
        self.failed_conns = 0
        self.success_rate = 0.0
        self.best_endpoint = ""
        self.best_method = ""
        self.auto_method = ""   # current sticky auto-mode method (from backend)
        self.auto_stats = {}
        self.method_rate = 0.0
        self.method_runs = 0
        self.up_bytes = 0
        self.down_bytes = 0
        self.up_rate = 0.0
        self.down_rate = 0.0
        self._prev_up = 0
        self._prev_down = 0
        self._prev_traffic_t = 0.0
        self._cards: list = []
        self._method_rows = {}
        self._mode_rows = {}
        self.log_file = None
        self.busy_jobs = 0
        # Autosave (debounced): pending after() id + suppression flags.
        self._autosave_after_id = None
        self._loading_config = False
        self._spin_i = 0
        self._pulse_on = False
        self._page = ""
        self._pages = {}
        self._page_canvases = {}
        self._page_bodies = {}
        self._nav_buttons = {}
        self._toast_ok = True

        cfg = cm.load(CONFIG_PATH)

        self.v_listen_host = tk.StringVar(value=str(cfg.get("LISTEN_HOST", "0.0.0.0")))
        self.v_listen_port = tk.StringVar(value=str(cfg.get("LISTEN_PORT", 40443)))
        self.v_fake_sni = tk.StringVar(value=str((cfg.get("FAKE_SNIS") or [""])[0] if cfg.get("FAKE_SNIS") else cfg.get("FAKE_SNI", "")))
        self.v_endpoint_ip = tk.StringVar(value=str(cfg.get("CONNECT_IP", "")))
        self.v_endpoint_port = tk.StringVar(value=str(cfg.get("CONNECT_PORT", 443)))
        self.v_mode = tk.StringVar(value=str(cfg.get("MODE", "SNI Only")))
        self.v_socks = tk.StringVar(value=str(cfg.get("SOCKS5_PORT", 10808)))
        self.v_http = tk.StringVar(value=str(cfg.get("HTTP_PORT", 10809)))
        self.v_password = tk.StringVar(value=str(cfg.get("TROJAN_PASSWORD", "humanity")))
        self.v_transport = tk.StringVar(value=str(cfg.get("TRANSPORT", "ws")))
        self.v_path = tk.StringVar(value=str(cfg.get("WS_PATH", "/assignment")))
        self.v_host = tk.StringVar(value=str(cfg.get("WS_HOST", "www.creationlong.org")))
        self.v_method = tk.StringVar(value=str(cfg.get("BYPASS_METHOD", "auto")))
        self.v_timeout = tk.StringVar(value=str(cfg.get("HANDSHAKE_TIMEOUT", 2.0)))
        self.v_maxconn = tk.StringVar(value=str(cfg.get("MAX_CONNECTIONS", 200)))
        self.v_idle = tk.StringVar(value=str(cfg.get("IDLE_TIMEOUT_S", 300.0)))
        # Verbose toggle removed: console always behaves as Verbose=OFF.
        try:
            self.v_method.trace_add("write", lambda *a: self._refresh_method_ui())
        except Exception:
            pass
        try:
            self.v_mode.trace_add("write", lambda *a: self._refresh_mode_ui())
        except Exception:
            pass
        try:
            self.file_endpoints: list = lists_mod.load_ip_list(
                IP_LIST_PATH, default_port=int(str(cfg.get("CONNECT_PORT", 443)) or 443))
        except Exception:
            self.file_endpoints = []
        try:
            self.file_snis: list = lists_mod.load_sni_list(SNI_LIST_PATH)
        except Exception:
            self.file_snis = []
        cfg_eps = cfg.get("ENDPOINTS") or []
        cfg_snis = cfg.get("FAKE_SNIS") or []
        if len(cfg_eps) > 1:
            self.extra_eps_text = "; ".join("%s:%s" % (e["ip"], e["port"]) for e in cfg_eps[1:3])
        elif self.file_endpoints:
            self.extra_eps_text = "; ".join(
                "%s:%s" % (e["ip"], e["port"]) for e in self.file_endpoints[:2])
        else:
            self.extra_eps_text = ""
        if len(cfg_snis) > 1:
            self.snis_text = ", ".join(cfg_snis[1:4])
        elif self.file_snis:
            primary = str((cfg_snis or [""])[0] if cfg_snis else cfg.get("FAKE_SNI", ""))
            rest = [s for s in self.file_snis if s != primary][:3]
            self.snis_text = ", ".join(rest)
        else:
            self.snis_text = ""

        self._build()
        # Place nav indicator correctly on first load (no 800ms glitch).
        try:
            self.root.update_idletasks()
            self._slide_indicator("bypass", force=True)
        except Exception:
            pass
        # Keep nav indicator aligned on window resize (see _slide_indicator).
        try:
            self.root.bind(
                "<Configure>",
                lambda e: self._slide_indicator(self._page, force=True)
                if getattr(e, "widget", None) is None
                or str(getattr(e, "widget", "")) == str(self.root) else None,
                add="+")
        except Exception:
            pass
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.after(120, self._poll_queue)
        self.root.after(600, self._pulse_loop)
        self.root.after(300, self._spin_loop)
        self.root.after(800, lambda: self._slide_indicator(self._page))

        self._open_log_file()
        # Wire config-var traces LAST so startup var mutations never trigger
        # a save of a half-built UI.
        self._attach_autosave_vars()
        self._show_window()
        # Defer environment checks until after first paint so cold open
        # never blocks on admin/driver/filesystem probes.
        try:
            self.root.after(250, self._startup_checks)
        except Exception:
            self._startup_checks()

    def _show_window(self):
        """Make sure the window is fully visible (no fade on startup)."""
        try:
            self.root.attributes("-alpha", 1.0)
        except Exception:
            pass

    def _startup_checks(self):
        try:
            self.log("SNI Spoofer ready. Configure, then press START.", "info")
            if self.file_endpoints:
                self.log("Loaded %d endpoint candidate(s) from ip_list.txt "
                         "(sampled, max %d used)." % (len(self.file_endpoints), MAX_FILE_ENDPOINTS), "info")
            elif os.path.exists(IP_LIST_PATH):
                self.log("ip_list.txt found but no usable IPs/CIDRs parsed.", "warning")
            if self.file_snis:
                self.log("Loaded %d SNI candidate(s) from sni_list.txt." % len(self.file_snis), "info")
            elif os.path.exists(SNI_LIST_PATH):
                self.log("sni_list.txt found but no usable SNIs parsed.", "warning")
            if not is_admin():
                self.log("Not Administrator — injector (WinDivert) will fail until restart as admin.", "warning")
            else:
                self.log("Running as Administrator.", "success")
            err = check_pydivert()
            if err:
                self.log("%s — run: pip install -r requirements.txt" % err, "warning")
            else:
                warn = diagnose_windivert_driver()
                if warn:
                    self.log(warn, "warning")
            xray_found = find_xray_exe()
            if xray_found:
                self.log("xray.exe found: %s" % xray_found, "success")
            else:
                self.log("xray.exe not found (APP_DIR, xray/bin subfolders, CWD, PATH, XRAY_PATH) "
                         "— SNI injector still works alone; Trojan+Xray mode needs it.", "warning")
            if getattr(sys, "frozen", False):
                if not os.path.exists(BACKEND_EXE):
                    self.log("sni-backend.exe not found at %s" % BACKEND_EXE, "error")
            elif not os.path.exists(MAIN_PATH):
                self.log("main.py not found at %s" % MAIN_PATH, "error")
        except Exception:
            pass

    # -- animations ------------------------------------------------
    def _fade_window_in(self, a=1.0):
        # Kept for compatibility; startup no longer fades (instant paint).
        try:
            self.root.attributes("-alpha", 1.0)
        except Exception:
            pass

    def _pulse_loop(self):
        try:
            if self.running:
                self._pulse_on = not self._pulse_on
                dot = THEME["success"] if self._pulse_on else THEME["success_dim"]
                self.status_dot.config(fg=dot)
                self.status_pill.config(highlightbackground=dot)
            else:
                self.status_dot.config(fg=THEME["faint"])
                self.status_pill.config(highlightbackground=THEME["card_edge"])
        except Exception:
            pass
        self.root.after(550, self._pulse_loop)

    def _spin_loop(self):
        try:
            if self.busy_jobs > 0:
                self._spin_i = (self._spin_i + 1) % len(SPINNER_FRAMES)
                self.lbl_busy.config(text="%s working…" % SPINNER_FRAMES[self._spin_i])
            else:
                self.lbl_busy.config(text="")
        except Exception:
            pass
        self.root.after(110, self._spin_loop)

    def toast(self, text, kind="info"):
        try:
            Toast(self.root, text, kind)
        except Exception:
            pass

    # -- layout ----------------------------------------------------
    def _build(self):
        self._build_header()
        body = tk.Frame(self.root, bg=THEME["bg"])
        body.pack(fill=tk.BOTH, expand=True)
        self._build_sidebar(body)
        right = tk.Frame(body, bg=THEME["bg"])
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 16), pady=(14, 14))
        self.page_host = tk.Frame(right, bg=THEME["bg"])
        self.page_host.pack(fill=tk.BOTH, expand=True)
        self._build_pages()
        self._build_stats(right)
        self._build_console(right)
        self._show_page("bypass", animate=False)

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=THEME["header"], height=66)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        # accent line
        tk.Frame(self.root, bg=THEME["accent"], height=2).pack(fill=tk.X)
        left = tk.Frame(hdr, bg=THEME["header"])
        left.pack(side=tk.LEFT, padx=18, pady=10)
        tk.Label(left, text="SNI Spoofer", font=FONT_TITLE, fg=THEME["fg"],
                 bg=THEME["header"]).pack(side=tk.LEFT)
        tk.Label(left, text="DPI bypass · failover · scoreboard", font=FONT_SUB,
                 fg=THEME["muted"], bg=THEME["header"]).pack(side=tk.LEFT, padx=(12, 0), pady=(6, 0))
        right = tk.Frame(hdr, bg=THEME["header"])
        right.pack(side=tk.RIGHT, padx=18, pady=10)
        self.lbl_uptime = tk.Label(right, text="--:--", font=FONT_N, fg=THEME["muted"],
                                   bg=THEME["header"])
        self.lbl_uptime.pack(side=tk.RIGHT, padx=(12, 0))
        # status pill with pulsing indicator
        self.status_pill = tk.Frame(right, bg=THEME["header"], highlightbackground=THEME["card_edge"],
                                    highlightthickness=1, padx=12, pady=5)
        self.status_pill.pack(side=tk.RIGHT)
        self.status_dot = tk.Label(self.status_pill, text="●", font=("Segoe UI", 12, "bold"),
                                   fg=THEME["faint"], bg=THEME["header"])
        self.status_dot.pack(side=tk.LEFT)
        self.status_lbl = tk.Label(self.status_pill, text="INACTIVE", font=FONT_STATUS,
                                   fg=THEME["muted"], bg=THEME["header"])
        self.status_lbl.pack(side=tk.LEFT, padx=(6, 0))
        # slim progress bar (visible while starting)
        self.start_bar = ttk.Progressbar(self.root, style="Modern.Horizontal.TProgressbar",
                                         mode="indeterminate", length=200)
        self._bar_running = False

    def _build_sidebar(self, body):
        side = tk.Frame(body, bg=THEME["sidebar"], width=208)
        side.pack(side=tk.LEFT, fill=tk.Y, padx=(16, 12), pady=14)
        side.pack_propagate(False)
        tk.Label(side, text="NAVIGATE", font=("Segoe UI Semibold", 8), fg=THEME["faint"],
                 bg=THEME["sidebar"]).pack(anchor="w", padx=16, pady=(14, 6))
        # Sliding indicator lives in sidebar coords (same parent as the
        # buttons, so winfo_y() lines up). Placed after layout settles.
        self.nav_ind = tk.Frame(side, bg=THEME["accent"], width=4, height=42)
        self.nav_ind.place(x=0, y=40)
        for key, label in (("bypass", "✦   DPI Bypass"),
                           ("proxy", "◈   Proxy / Xray"),
                           ("active", "⌖   Active Conns"),
                           ("tools", "⚒   Smart Tools")):
            b = ModernButton(side, text=label, command=lambda k=key: self._show_page(k),
                             style="ghost", height=42, align="left", focusable=False)
            b.configure(bg=THEME["sidebar"])
            b.pack(fill=tk.X, padx=10, pady=3)
            self._nav_buttons[key] = b
        tk.Frame(side, bg=THEME["card_edge"], height=1).pack(fill=tk.X, padx=16, pady=12)
        tk.Label(side, text="ENGINE", font=("Segoe UI Semibold", 8), fg=THEME["faint"],
                 bg=THEME["sidebar"]).pack(anchor="w", padx=16, pady=(0, 6))
        self.btn_start = ModernButton(side, text="▶   START", command=self.start,
                                       style="primary", height=44, focusable=False)
        self.btn_start.configure(bg=THEME["sidebar"])
        self.btn_start.pack(fill=tk.X, padx=10, pady=3)
        self.btn_stop = ModernButton(side, text="⏹   STOP", command=self.stop,
                                     style="danger", height=40, focusable=False)
        self.btn_stop.configure(bg=THEME["sidebar"])
        self.btn_stop.pack(fill=tk.X, padx=10, pady=3)
        self.btn_stop.config(state=tk.DISABLED)
        for txt, cmd in (("⧉  Copy proxy", self.copy_proxy),
                         ("⬆  Run as admin", lambda: relaunch_as_admin(os.path.abspath(__file__))),
                         ("❖  Save config", self.save_only)):
            b = ModernButton(side, text=txt, command=cmd, style="ghost", height=32, focusable=False)
            b.configure(bg=THEME["sidebar"])
            b.pack(fill=tk.X, padx=10, pady=2)

    def _page_frame(self, name):
        """A scrollable page: outer frame (placed) + canvas + content body."""
        outer = tk.Frame(self.page_host, bg=THEME["bg"])
        canvas = tk.Canvas(outer, bg=THEME["bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview,
                            style="Modern.Vertical.TScrollbar")

        def _page_yscroll(first, last):
            # Win10 feel: dim the thumb when nothing overflows, so short
            # pages don't show an active-looking scrollbar. The bar stays
            # packed (fixed 12px) to avoid layout jumps.
            try:
                vsb.set(first, last)
                if float(first) <= 0.0 and float(last) >= 1.0:
                    vsb.state(["disabled"])
                else:
                    vsb.state(["!disabled"])
            except Exception:
                pass

        canvas.configure(yscrollcommand=_page_yscroll)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        # Wheel over empty canvas area should scroll too (children are
        # bound separately via _bind_wheel_tree).
        try:
            canvas.bind("<MouseWheel>",
                        lambda e, c=canvas: self._wheel_scroll(e, c), add="+")
        except Exception:
            pass
        body = tk.Frame(canvas, bg=THEME["bg"])
        win = canvas.create_window((0, 0), window=body, anchor="nw")

        def _sync(e=None):
            try:
                canvas.configure(scrollregion=canvas.bbox("all"))
                canvas.itemconfig(win, width=max(1, canvas.winfo_width()))
                # Refresh dim state after geometry settles.
                try:
                    first, last = canvas.yview()
                    _page_yscroll(str(first), str(last))
                except Exception:
                    pass
            except Exception:
                pass

        body.bind("<Configure>", _sync)
        canvas.bind("<Configure>", _sync)
        self._pages[name] = outer
        self._page_canvases[name] = canvas
        self._page_bodies[name] = body
        return body

    def _wheel_scroll(self, event, canvas):
        try:
            canvas.yview_scroll(int(-event.delta / 120), "units")
        except Exception:
            pass
        return "break"

    def _bind_wheel_tree(self, widget, canvas):
        # Scroll the page, but leave text editing and dropdowns alone.
        if isinstance(widget, (tk.Entry, ttk.Combobox, scrolledtext.ScrolledText,
                               tk.Text, tk.Listbox, ttk.Scrollbar)):
            return
        try:
            widget.bind("<MouseWheel>", lambda e: self._wheel_scroll(e, canvas), add="+")
        except Exception:
            pass
        try:
            children = widget.winfo_children()
        except Exception:
            children = []
        for ch in children:
            self._bind_wheel_tree(ch, canvas)

    def _show_page(self, name, animate=True):
        if name == self._page:
            return
        for k, pg in self._pages.items():
            pg.place_forget()
        self._page = name
        pg = self._pages[name]
        try:
            self._page_canvases[name].yview_moveto(0)
        except Exception:
            pass
        # refresh nav highlight (clean style switch keeps fill/border in sync)
        for k, b in self._nav_buttons.items():
            try:
                b.set_style("accent" if k == name else "ghost", animate=False)
            except Exception:
                try:
                    b._style = "accent" if k == name else "ghost"
                    b._draw()
                except Exception:
                    pass
        self._slide_indicator(name)
        if animate:
            self._slide_page_in(pg)
        else:
            pg.place(relx=0, rely=0, relwidth=1, relheight=1)

    def _slide_indicator(self, name, step=0, force=False):
        try:
            btn = self._nav_buttons[name]
        except Exception:
            return
        try:
            target = btn.winfo_y()
        except Exception:
            return
        # Pre-layout: button not yet placed (y==0 with zero height) — skip
        # the animated glide so the rail never flashes at the top.
        if not force:
            try:
                if target <= 1 and btn.winfo_height() < 5:
                    return
            except Exception:
                pass
        if force:
            try:
                self.nav_ind.place(x=0, y=target)
            except Exception:
                pass
            return
        try:
            cur = self.nav_ind.winfo_y()
        except Exception:
            cur = target
        if abs(target - cur) < 2 or step > 12:
            self.nav_ind.place(x=0, y=target)
            return
        nxt = cur + (target - cur) * 0.45
        self.nav_ind.place(x=0, y=nxt)
        self.root.after(12, lambda: self._slide_indicator(name, step + 1))

    def _slide_page_in(self, pg, step=0):
        total = 4
        if step >= total:
            pg.place(relx=0, rely=0, relwidth=1, relheight=1)
            return
        t = step / total
        pg.place(relx=0.05 * (1 - t), rely=0, relwidth=0.95 + 0.05 * t, relheight=1)
        self.root.after(12, lambda: self._slide_page_in(pg, step + 1))

    # -- pages -----------------------------------------------------
    def _build_pages(self):
        p1 = self._page_frame("bypass")
        self._card(p1, "Connection").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._row(card, "Listen host", self.v_listen_host)
        self._row(card, "Listen port", self.v_listen_port, w=12)
        self._row(card, "Endpoint IP (primary)", self.v_endpoint_ip)
        self._row(card, "Endpoint port", self.v_endpoint_port, w=12)
        tk.Frame(p1, bg=THEME["card_edge"], height=1).pack(fill=tk.X, pady=(0, 14))
        self._card(p1, "Spoof").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._row(card, "Fake SNI (primary)", self.v_fake_sni)
        tk.Label(card, text="Bypass method — tap a card", bg=THEME["card"],
                 fg=THEME["muted"], font=FONT_N).pack(anchor="w", padx=14, pady=(6, 2))
        self._method_wrap = tk.Frame(card, bg=THEME["card"])
        self._method_wrap.pack(fill=tk.X, padx=14, pady=2)
        for key, title, desc in METHODS:
            self._method_rows[key] = self._selector_row(
                self._method_wrap, title, desc, lambda k=key: self.v_method.set(k))
        self.lbl_method_hint = tk.Label(card, text="", bg=THEME["card"],
                                        fg=THEME["success"], font=("Segoe UI", 8))
        self.lbl_method_hint.pack(anchor="w", padx=14, pady=(0, 4))
        trow = tk.Frame(card, bg=THEME["card"])
        trow.pack(fill=tk.X, padx=14, pady=4)
        tk.Label(trow, text="Timeout", bg=THEME["card"], fg=THEME["muted"],
                 font=FONT_N).pack(side=tk.LEFT)
        self._entry(trow, self.v_timeout, width=6).pack(side=tk.LEFT, padx=(6, 2))
        tk.Label(trow, text="Max conn", bg=THEME["card"], fg=THEME["muted"],
                 font=FONT_N).pack(side=tk.LEFT, padx=(10, 2))
        self._entry(trow, self.v_maxconn, width=7).pack(side=tk.LEFT, padx=2)
        tk.Label(trow, text="Idle timeout (s)", bg=THEME["card"], fg=THEME["muted"],
                 font=FONT_N).pack(side=tk.LEFT, padx=(10, 2))
        self._entry(trow, self.v_idle, width=7).pack(side=tk.LEFT, padx=2)
        self._card(p1, "Failover  ·  extra endpoints + SNIs").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._row(card, "Extra endpoints", None, w=40, text_var_name="extra",
                  hint="ip[:port], comma separated")
        self._row(card, "Extra SNIs", None, w=40, text_var_name="snis",
                  hint="comma separated, rotated")
        self._card(p1, "Profiles").pack(fill=tk.X)
        card = self._cards[-1]
        prow = tk.Frame(card, bg=THEME["card"])
        prow.pack(fill=tk.X, padx=14, pady=8)
        self.v_profile = tk.StringVar(value="")
        self.cbo_profile = ttk.Combobox(prow, textvariable=self.v_profile, width=24,
                                        values=list_profiles(), style="Modern.TCombobox")
        self.cbo_profile.pack(side=tk.LEFT, padx=(0, 6))
        for txt, cmd in (("Load", self.profile_load), ("Save", self.profile_save),
                         ("Delete", self.profile_delete), ("↻", self.profile_refresh)):
            ModernButton(prow, text=txt, command=cmd, style="ghost", height=30).pack(side=tk.LEFT, padx=3)

        p2 = self._page_frame("proxy")
        self._card(p2, "Mode — tap a card").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._mode_wrap = tk.Frame(card, bg=THEME["card"])
        self._mode_wrap.pack(fill=tk.X, padx=14, pady=4)
        for key, title, desc in MODES:
            self._mode_rows[key] = self._selector_row(
                self._mode_wrap, title, desc, lambda k=key: self.v_mode.set(k))
        self.lbl_mode_hint = tk.Label(card, text="", bg=THEME["card"],
                                      fg=THEME["muted"], font=("Segoe UI", 8),
                                      wraplength=640, justify=tk.LEFT)
        self.lbl_mode_hint.pack(anchor="w", padx=14, pady=(0, 8))
        self._card(p2, "Proxy output").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._row(card, "SOCKS5 port", self.v_socks, w=12)
        self._row(card, "HTTP port", self.v_http, w=12)
        self._card(p2, "Trojan / transport").pack(fill=tk.X)
        card = self._cards[-1]
        self._row(card, "Trojan password", self.v_password)
        self._row(card, "Transport", self.v_transport, w=12)
        self._row(card, "WS path", self.v_path)
        self._row(card, "WS host", self.v_host)

        p3 = self._page_frame("active")
        self._build_active_page(p3)

        p4 = self._page_frame("tools")
        self._card(p4, "Smart tools   ·   no Admin needed except START").pack(fill=tk.BOTH, expand=True)
        card = self._cards[-1]
        thead = tk.Frame(card, bg=THEME["card"])
        thead.pack(fill=tk.X, padx=14, pady=(8, 2))
        tk.Label(thead, text="Probes use plain TCP/TLS — DPI success still depends on network.",
                 bg=THEME["card"], fg=THEME["faint"], font=("Segoe UI", 8)).pack(side=tk.LEFT)
        self.lbl_busy = tk.Label(thead, text="", bg=THEME["card"], fg=THEME["accent"], font=FONT_N)
        self.lbl_busy.pack(side=tk.RIGHT)
        for txt, cmd in [
            ("▁▃▅▇  Ping SNIs on primary endpoint", self.smart_rank_snis),
            ("✪  Ping SNIs + use best SNI to spoof", self.smart_use_best_sni),
            ("◈  Ping endpoints (TCP connect)", self.smart_rank_endpoints),
            ("★  Use best endpoint", self.smart_use_best_endpoint),
            ("⟳  Reload ip_list.txt / sni_list.txt", self.smart_reload_lists),
        ]:
            ModernButton(card, text=txt, command=cmd, style="ghost",
                         height=33, align="left").pack(fill=tk.X, padx=14, pady=2)
        self._refresh_method_ui()
        self._refresh_mode_ui()
        for pname, pbody in self._page_bodies.items():
            self._bind_wheel_tree(pbody, self._page_canvases[pname])

    def _card(self, parent, title):
        outer = tk.Frame(parent, bg=THEME["card_edge"])
        inner = tk.Frame(outer, bg=THEME["card"])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        tk.Label(inner, text=title.upper(), font=("Segoe UI Semibold", 8),
                 fg=THEME["accent"], bg=THEME["card"]).pack(anchor="w", padx=14, pady=(10, 2))
        self._cards.append(inner)
        return outer

    def _entry(self, parent, var, width=30):
        e = tk.Entry(parent, textvariable=var, bg=THEME["input"], fg=THEME["fg"],
                     font=FONT_N, relief=tk.FLAT, width=width, insertbackground=THEME["accent"],
                     highlightthickness=1, highlightbackground=THEME["card"],
                     highlightcolor=THEME["input_edge"], selectbackground=THEME["accent_dim"])
        try:
            e.bind("<FocusIn>",
                   lambda ev: ev.widget.config(highlightbackground=THEME["accent"]),
                   add="+")
            e.bind("<FocusOut>",
                   lambda ev: ev.widget.config(highlightbackground=THEME["card"]),
                   add="+")
        except Exception:
            pass
        return e

    def _row(self, parent, label, var, w=30, text_var_name=None, hint=None):
        r = tk.Frame(parent, bg=THEME["card"])
        r.pack(fill=tk.X, padx=14, pady=4)
        tk.Label(r, text=label, width=20, anchor="w", bg=THEME["card"],
                 fg=THEME["muted"], font=FONT_N).pack(side=tk.LEFT)
        if text_var_name == "extra":
            self.v_extra = tk.StringVar(value=self.extra_eps_text)
            self.e_extra = self._entry(r, self.v_extra, width=w)
            self.e_extra.pack(side=tk.LEFT, padx=8, ipady=4, fill=tk.X, expand=True)
        elif text_var_name == "snis":
            self.v_snis = tk.StringVar(value=self.snis_text)
            self.e_snis = self._entry(r, self.v_snis, width=w)
            self.e_snis.pack(side=tk.LEFT, padx=8, ipady=4, fill=tk.X, expand=True)
        elif var is not None:
            self._entry(r, var, width=w).pack(side=tk.LEFT, padx=8, ipady=4)
        if hint:
            tk.Label(r, text=hint, bg=THEME["card"], fg=THEME["faint"],
                     font=("Segoe UI", 8)).pack(side=tk.LEFT)

    # -- selector cards (methods + modes) --------------------------
    def _selector_row(self, parent, title, desc, on_pick):
        outer = tk.Frame(parent, bg=THEME["card_edge"], cursor="hand2")
        outer.pack(fill=tk.X, pady=3)
        inner = tk.Frame(outer, bg=THEME["input"], cursor="hand2")
        inner.pack(fill=tk.X, padx=1, pady=1)
        dot = tk.Label(inner, text="○", font=("Segoe UI", 12), fg=THEME["faint"],
                       bg=THEME["input"], cursor="hand2", width=3)
        dot.pack(side=tk.LEFT, padx=(4, 0))
        txt = tk.Frame(inner, bg=THEME["input"], cursor="hand2")
        txt.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), pady=6)
        t1 = tk.Label(txt, text=title, font=FONT_BTN, fg=THEME["fg"],
                      bg=THEME["input"], anchor="w", cursor="hand2")
        t1.pack(anchor="w")
        t2 = tk.Label(txt, text=desc, font=("Segoe UI", 8), fg=THEME["muted"],
                      bg=THEME["input"], anchor="w", wraplength=560, justify=tk.LEFT,
                      cursor="hand2")
        t2.pack(anchor="w")
        row = {"outer": outer, "inner": inner, "dot": dot, "txt": txt,
               "t1": t1, "t2": t2, "_selected": False}
        for w in (outer, inner, dot, txt, t1, t2):
            w.bind("<Button-1>", lambda e: on_pick())

        def _hover_in(e=None, _row=row):
            try:
                _row["_hover"] = True
                if _row.get("_selected"):
                    # Selected + hover: keep tint, brighten border.
                    _row["outer"].configure(bg=THEME["accent"])
                    for k in ("inner", "txt", "t1", "t2", "dot"):
                        _row[k].configure(bg=_mix_hex(THEME["selector_selected"], "#FFFFFF", 0.06))
                else:
                    _row["outer"].configure(bg="#3A4252")
                    for k in ("inner", "txt", "t1", "t2", "dot"):
                        _row[k].configure(bg=THEME["selector_hover"])
            except Exception:
                pass

        def _hover_out(e=None, _row=row):
            try:
                _row["_hover"] = False
                self._paint_selector_row(_row, _row.get("_selected", False))
            except Exception:
                pass

        for w in (outer, inner, dot, txt, t1, t2):
            try:
                w.bind("<Enter>", _hover_in, add="+")
                w.bind("<Leave>", _hover_out, add="+")
            except Exception:
                pass
        return row

    def _paint_selector_row(self, row, selected):
        # Selected: accent border + tinted body + glowing dot; hover adds sheen.
        try:
            row["_selected"] = bool(selected)
        except Exception:
            pass
        hovered = bool(row.get("_hover"))
        try:
            outer_bg = THEME["accent"] if selected else ("#3A4252" if hovered else THEME["card_edge"])
            row["outer"].configure(bg=outer_bg)
        except Exception:
            pass
        if selected:
            inner_bg = _mix_hex(THEME["selector_selected"], "#FFFFFF", 0.06) if hovered \
                else THEME["selector_selected"]
        else:
            inner_bg = THEME["selector_hover"] if hovered else THEME["input"]
        try:
            row["inner"].configure(bg=inner_bg)
            row["txt"].configure(bg=inner_bg)
            row["t1"].configure(bg=inner_bg)
            row["t2"].configure(bg=inner_bg, fg=THEME["muted"] if not selected else "#C6D3E2")
            row["dot"].configure(bg=inner_bg)
        except Exception:
            pass
        row["dot"].configure(text="◉" if selected else "○",
                             fg=THEME["accent"] if selected else THEME["faint"])
        try:
            row["t1"].configure(fg="#FFFFFF" if selected else THEME["fg"])
        except Exception:
            pass

    def _refresh_method_ui(self):
        rows = getattr(self, "_method_rows", None)
        if not rows:
            return
        try:
            cur = self.v_method.get().strip()
        except Exception:
            return
        if cur not in rows:
            try:
                self.v_method.set("auto")
            except Exception:
                pass
            return
        for k, row in rows.items():
            self._paint_selector_row(row, k == cur)

    def _xray_status(self):
        found = find_xray_exe()
        if found:
            return "xray.exe found: %s" % found
        return ("xray.exe MISSING (searched APP_DIR, xray/bin subfolders, CWD, PATH, "
                "XRAY_PATH) — SNI injector still works alone")

    def _refresh_mode_ui(self):
        rows = getattr(self, "_mode_rows", None)
        if not rows:
            return
        try:
            cur = self.v_mode.get().strip()
        except Exception:
            return
        if cur not in rows:
            try:
                self.v_mode.set("SNI Only")
            except Exception:
                pass
            return
        for k, row in rows.items():
            self._paint_selector_row(row, k == cur)
        try:
            if cur == "Trojan + Xray":
                self.lbl_mode_hint.configure(
                    text="Xray listens SOCKS5 :%s + HTTP :%s and forwards into the injector. %s."
                         % (self.v_socks.get().strip(), self.v_http.get().strip(), self._xray_status()),
                    fg=THEME["muted"])
            else:
                self.lbl_mode_hint.configure(
                    text="Apps connect straight to the injector at the listen host/port above. No extra files needed.",
                    fg=THEME["muted"])
        except Exception:
            pass

    # -- active connections page -----------------------------------
    # Row tint per connection state (subtle, dark-theme friendly).
    ACTIVE_STATE_TAGS = {
        "relaying": ("st_relaying", "●"),
        "handshake": ("st_handshake", "◐"),
        "connecting": ("st_connecting", "○"),
        "closing": ("st_closing", "◑"),
    }

    def _build_active_page(self, p3):
        """Live connection table: updates every stats poll (2s)."""
        self._card(p3, "Active connections   ·   live view (updates every 2s)").pack(fill=tk.BOTH, expand=True)
        card = self._cards[-1]

        # Header row: live count chip + hint + clear/show toggle.
        head = tk.Frame(card, bg=THEME["card"])
        head.pack(fill=tk.X, padx=14, pady=(8, 4))
        self.lbl_active_chip = tk.Label(head, text="● 0 active", font=FONT_STATUS,
                                        fg=THEME["faint"], bg=THEME["card"])
        self.lbl_active_chip.pack(side=tk.LEFT)
        tk.Label(head, text="Click a row to reveal that session's SNI (debug). "
                            "Table shows hashed SNIs for privacy.",
                 bg=THEME["card"], fg=THEME["faint"], font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(12, 0))
        self.btn_clear_active = ModernButton(head, text="Clear display",
                                             command=self._toggle_active_display,
                                             style="ghost", height=26)
        self.btn_clear_active.pack(side=tk.RIGHT)

        cols = ("time", "endpoint", "sni", "method", "up", "down", "state")
        self._active_headings = {"time": "Time", "endpoint": "Endpoint", "sni": "SNI",
                                 "method": "Method", "up": "Up", "down": "Down", "state": "State"}
        widths = {"time": 76, "endpoint": 160, "sni": 120, "method": 120,
                  "up": 90, "down": 90, "state": 110}
        anchors = {"time": "center", "up": "e", "down": "e", "state": "w"}

        # Dark Fluent styling for the tree + its headings (clam base).
        style = self._style
        style.configure("Active.Treeview",
                        background=THEME["console_bg"],
                        fieldbackground=THEME["console_bg"],
                        foreground=THEME["fg"],
                        rowheight=27, borderwidth=0, relief="flat", font=FONT_N)
        style.configure("Active.Treeview.Heading",
                        background=THEME["card"], foreground=THEME["accent"],
                        font=("Segoe UI Semibold", 8), borderwidth=0,
                        relief="flat", padding=(8, 7))
        style.map("Active.Treeview.Heading",
                  background=[("active", THEME["card"]), ("pressed", THEME["card"])],
                  foreground=[("active", THEME["accent"]), ("pressed", THEME["fg"])])
        style.map("Active.Treeview",
                  background=[("selected", THEME["selector_selected"])],
                  foreground=[("selected", THEME["fg"])])

        wrap = tk.Frame(card, bg=THEME["console_bg"], highlightbackground=THEME["card_edge"],
                        highlightthickness=1)
        wrap.pack(fill=tk.BOTH, expand=True, padx=14, pady=(2, 12))
        self.tree_active = ttk.Treeview(wrap, columns=cols, show="headings", height=14,
                                        style="Active.Treeview", selectmode="browse")
        for c in cols:
            self.tree_active.heading(c, text=self._active_headings[c],
                                     command=lambda cc=c: self._sort_active_tree(cc))
            self.tree_active.column(c, width=widths[c], anchor=anchors.get(c, "w"), stretch=True)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree_active.yview,
                            style="Modern.Vertical.TScrollbar")
        self.tree_active.configure(yscrollcommand=vsb.set)
        self.tree_active.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        self.tree_active.bind("<Button-1>", self._on_active_row_click)

        # State-tinted rows (whole-row background, no zebra: the tint IS the state).
        self.tree_active.tag_configure("st_relaying", background="#12271B")
        self.tree_active.tag_configure("st_handshake", background="#11263A")
        self.tree_active.tag_configure("st_connecting", background="#2B2412")
        self.tree_active.tag_configure("st_closing", background=THEME["console_bg"],
                                       foreground=THEME["faint"])
        self.tree_active.tag_configure("st_idle", background=THEME["console_bg"])

        # Empty state overlay (hidden once rows arrive).
        self.lbl_active_empty = tk.Label(
            wrap, text="●  No active connections\n\n"
                       "Start the engine — connections appear here in real time\n"
                       "with endpoint, method, bytes and live state.",
            bg=THEME["console_bg"], fg=THEME["faint"], font=FONT_N, justify=tk.CENTER)
        self.lbl_active_empty.place(relx=0.5, rely=0.5, anchor="center")

        # Sorting state: (column, descending)
        self._active_sort = ("time", True)
        self._paint_active_headings()
        # Rows currently displayed; keyed by conn id -> values tuple.
        self._active_rows: dict[str, tuple] = {}
        self._active_hidden = False  # "Clear display" only hides, not the conns

    def _paint_active_headings(self):
        """Heading text + sort arrow on the active sort column."""
        try:
            col, desc = self._active_sort
            for c, base in self._active_headings.items():
                arrow = "  ▾" if (c == col and desc) else ("  ▴" if c == col else "")
                self.tree_active.heading(c, text=base + arrow)
        except Exception:
            pass

    def _sort_active_tree(self, col):
        try:
            desc = (self._active_sort[0] == col) and not self._active_sort[1]
            self._active_sort = (col, desc)
            self._paint_active_headings()

            def _num(v):
                # "1.5 KB" -> 1536-ish ordering by first token is enough;
                # fall back to 0 for junk.
                try:
                    return float(str(v).split()[0].replace(",", ""))
                except (ValueError, IndexError):
                    return 0.0

            def _key(item):
                v = self.tree_active.set(item).get(col, "")
                if col in ("up", "down"):
                    return _num(v)
                return str(v)

            items = sorted(self.tree_active.get_children(""), key=_key, reverse=desc)
            for i, item in enumerate(items):
                self.tree_active.move(item, "", i)
        except Exception:
            pass

    def _on_active_row_click(self, event):
        """Reveal the raw SNI for one session on click (deliberate debug exception)."""
        try:
            if self.tree_active.identify_region(event.x, event.y) != "cell":
                return
            item = self.tree_active.identify_row(event.y)
            if not item:
                return
            raw = self._active_raw_snis.get(str(item), "")
            if raw:
                messagebox.showinfo("SNI (this session only)", raw)
        except Exception:
            pass

    def _toggle_active_display(self):
        """Clear display hides the live feed; click again to resume."""
        if not self._active_hidden:
            self._active_hidden = True
            try:
                for item in self.tree_active.get_children(""):
                    self.tree_active.delete(item)
            except Exception:
                pass
            try:
                self.btn_clear_active.config(text="Show live")
                self.lbl_active_chip.config(text="◌ display paused", fg=THEME["warning"])
                self.lbl_active_empty.config(
                    text="◌  Display paused\n\nPress “Show live” to resume the feed.")
                self.lbl_active_empty.place(relx=0.5, rely=0.5, anchor="center")
            except Exception:
                pass
        else:
            self._active_hidden = False
            try:
                self.btn_clear_active.config(text="Clear display")
                self.lbl_active_empty.config(
                    text="●  No active connections\n\n"
                         "Start the engine — connections appear here in real time\n"
                         "with endpoint, method, bytes and live state.")
            except Exception:
                pass
            self._update_active_table([])

    def _update_active_table(self, active_list: list):
        """Refresh the Treeview from the backend's active_list snapshot."""
        try:
            if self._active_hidden:
                return
            if not hasattr(self, "_active_raw_snis"):
                self._active_raw_snis = {}
            incoming = {}
            raw_snis = {}
            for e in (active_list or []):
                try:
                    cid = str(e.get("id", ""))
                    if not cid:
                        continue
                    state = str(e.get("state", "") or "idle")
                    glyph = self.ACTIVE_STATE_TAGS.get(state, ("st_idle", "·"))[1]
                    incoming[cid] = (
                        datetime.fromtimestamp(float(e.get("time", 0.0))).strftime("%H:%M:%S"),
                        str(e.get("endpoint", "")),
                        str(e.get("sni_hash", "") or ""),
                        str(e.get("method", "")),
                        fmt_bytes(e.get("up", 0)),
                        fmt_bytes(e.get("down", 0)),
                        "%s %s" % (glyph, state),
                    )
                    raw_snis[cid] = str(e.get("sni", "") or "")
                except Exception:
                    continue
            self._active_raw_snis = raw_snis
            cur_ids = set(incoming)
            # Remove rows for connections that are gone.
            for item in list(self.tree_active.get_children("")):
                if str(item) not in cur_ids:
                    self.tree_active.delete(item)
            # Upsert visible rows (iid = connection id) + state tint tag.
            for cid, vals in incoming.items():
                state = vals[6].split(" ", 1)[1] if " " in vals[6] else "idle"
                tag = self.ACTIVE_STATE_TAGS.get(state, ("st_idle",))[0]
                if self.tree_active.exists(cid):
                    self.tree_active.item(cid, values=vals, tags=(tag,))
                else:
                    try:
                        self.tree_active.insert("", "end", iid=cid, values=vals, tags=(tag,))
                    except Exception:
                        pass
            self._active_rows = incoming
            # Count chip + empty-state overlay.
            n = len(incoming)
            if n > 0:
                self.lbl_active_chip.config(text="● %d active" % n, fg=THEME["success"])
                self.lbl_active_empty.place_forget()
            else:
                self.lbl_active_chip.config(text="● 0 active", fg=THEME["faint"])
                self.lbl_active_empty.place(relx=0.5, rely=0.5, anchor="center")
        except Exception:
            pass

    # -- stats + console -------------------------------------------
    def _build_stats(self, right):
        bar = tk.Frame(right, bg=THEME["stats_bg"], highlightbackground=THEME["card_edge"],
                       highlightthickness=1, pady=6)
        bar.pack(fill=tk.X, pady=(10, 0))
        stats_font = ("Segoe UI Variable", 9)
        self.lbl_active = tk.Label(bar, text="● Active 0", font=stats_font, fg=THEME["accent"], bg=THEME["stats_bg"])
        self.lbl_active.pack(side=tk.LEFT, padx=10)
        self.lbl_total = tk.Label(bar, text="Total 0", font=stats_font, fg=THEME["fg"], bg=THEME["stats_bg"])
        self.lbl_total.pack(side=tk.LEFT, padx=10)
        self.lbl_okfail = tk.Label(bar, text="OK 0 · Fail 0", font=stats_font, fg=THEME["muted"], bg=THEME["stats_bg"])
        self.lbl_okfail.pack(side=tk.LEFT, padx=10)
        self.lbl_best = tk.Label(bar, text="Best —", font=stats_font, fg=THEME["muted"], bg=THEME["stats_bg"])
        self.lbl_best.pack(side=tk.LEFT, padx=10)
        self.lbl_method = tk.Label(bar, text="Method —", font=stats_font, fg=THEME["muted"], bg=THEME["stats_bg"])
        self.lbl_method.pack(side=tk.LEFT, padx=10)
        self.lbl_up = tk.Label(bar, text="▲ 0 B", font=stats_font, fg=THEME["success"], bg=THEME["stats_bg"])
        self.lbl_up.pack(side=tk.LEFT, padx=10)
        self.lbl_down = tk.Label(bar, text="▼ 0 B", font=stats_font, fg=THEME["accent"], bg=THEME["stats_bg"])
        self.lbl_down.pack(side=tk.LEFT, padx=10)

    def _build_console(self, right):
        outer = tk.Frame(right, bg=THEME["card_edge"])
        outer.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.console_outer = outer
        self._console_expanded = True
        box = tk.Frame(outer, bg=THEME["card"])
        box.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        h = tk.Frame(box, bg=THEME["card"])
        h.pack(fill=tk.X, padx=12, pady=(8, 2))
        tk.Label(h, text="LIVE CONSOLE", font=("Segoe UI Semibold", 8),
                 fg=THEME["accent"], bg=THEME["card"]).pack(side=tk.LEFT)
        self.btn_console_toggle = tk.Button(
            h, text="\u25bc", font=("Segoe UI", 8), fg=THEME["accent"],
            bg=THEME["card"], activebackground=THEME["card"],
            activeforeground=THEME["accent"], relief=tk.FLAT, bd=0,
            width=3, cursor="hand2", command=self._toggle_console)
        self.btn_console_toggle.pack(side=tk.LEFT, padx=(6, 0))
        ModernButton(h, text="Export", command=self.export_log, style="ghost", height=26).pack(side=tk.RIGHT, padx=(6, 0))
        ModernButton(h, text="Clear", command=self.clear_log, style="ghost", height=26).pack(side=tk.RIGHT, padx=(0, 6))
        # Fast startup: tkfont.families() enumerates every system font and
        # can block cold open for seconds. Paint with Consolas now and
        # upgrade to the preferred mono font after first paint.
        mono_font = ("Consolas", 10)
        self.console_frame = tk.Frame(box, bg=THEME["card"])
        self.console_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 12))
        self.console = tk.Text(self.console_frame, bg=THEME["console_bg"], fg=THEME["fg"],
                               font=mono_font, relief=tk.FLAT, wrap=tk.WORD, height=8,
                               insertbackground=THEME["accent"],
                               selectbackground=THEME["accent_dim"],
                               highlightthickness=0, bd=0)
        self.console_vsb = ttk.Scrollbar(self.console_frame, orient="vertical",
                                         command=self.console.yview,
                                         style="Console.Vertical.TScrollbar")

        def _console_yscroll(first, last):
            try:
                self.console_vsb.set(first, last)
                if float(first) <= 0.0 and float(last) >= 1.0:
                    self.console_vsb.state(["disabled"])
                else:
                    self.console_vsb.state(["!disabled"])
            except Exception:
                pass

        self.console.configure(yscrollcommand=_console_yscroll)
        self.console.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.console_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        for tag, col in (("info", THEME["accent"]), ("success", THEME["success"]),
                         ("warning", THEME["warning"]), ("error", THEME["danger"])):
            self.console.tag_config(tag, foreground=col)
        try:
            self.root.after(400, self._upgrade_console_font)
        except Exception:
            pass

    def _upgrade_console_font(self):
        """Swap in the preferred mono font after the window is visible."""
        try:
            if not getattr(self, "console", None) or not self.console.winfo_exists():
                return
            import tkinter.font as tkfont
            available = set(tkfont.families())
            if "Cascadia Code" in available:
                mono_font = ("Cascadia Code", 10)
            elif "JetBrains Mono" in available:
                mono_font = ("JetBrains Mono", 10)
            else:
                return
            try:
                self.console.configure(font=mono_font)
            except Exception:
                pass
        except Exception:
            pass

    def _toggle_console(self):
        """Collapse/expand only the console text widget; header stays visible."""
        frame = getattr(self, "console_frame", None) or self.console
        if getattr(self, "_console_expanded", True):
            frame.pack_forget()
            self.console_outer.pack_configure(expand=False, fill=tk.X)
            self.btn_console_toggle.configure(text="\u25b6")
            self._console_expanded = False
        else:
            frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 12))
            self.console_outer.pack_configure(expand=True, fill=tk.BOTH)
            self.btn_console_toggle.configure(text="\u25bc")
            self._console_expanded = True

    # -- config ----------------------------------------------------
    def _collect(self):
        try:
            default_port = int(self.v_endpoint_port.get().strip() or 443)
        except ValueError:
            return None, "Endpoint port must be a number"
        endpoints = [{"ip": self.v_endpoint_ip.get().strip(), "port": default_port}]
        endpoints += parse_host_list(self.v_extra.get(), default_port)
        endpoints = [e for e in endpoints if e["ip"]]
        snis = [self.v_fake_sni.get().strip()] + parse_sni_list(self.v_snis.get())
        snis = [s for s in snis if s]
        try:
            cfg = {
                "LISTEN_HOST": self.v_listen_host.get().strip() or "0.0.0.0",
                "LISTEN_PORT": int(self.v_listen_port.get().strip()),
                "CONNECT_IP": endpoints[0]["ip"] if endpoints else "",
                "CONNECT_PORT": endpoints[0]["port"] if endpoints else 443,
                "ENDPOINTS": endpoints,
                "FAKE_SNI": snis[0] if snis else "",
                "FAKE_SNIS": snis,
                "BYPASS_METHOD": self.v_method.get().strip(),
                "HANDSHAKE_TIMEOUT": float(self.v_timeout.get().strip()),
                "MAX_CONNECTIONS": int(self.v_maxconn.get().strip()),
                "IDLE_TIMEOUT_S": float(self.v_idle.get().strip() or 300.0),
                "FAKE_DELAY": 0.001,
                "SOCKS5_PORT": int(self.v_socks.get().strip()),
                "HTTP_PORT": int(self.v_http.get().strip()),
                "MODE": self.v_mode.get(),
                "TROJAN_PASSWORD": self.v_password.get(),
                "TRANSPORT": self.v_transport.get().strip() or "ws",
                "WS_PATH": self.v_path.get().strip() or "/",
                "WS_HOST": self.v_host.get().strip(),
            }
        except (ValueError, IndexError):
            return None, "Numeric fields (ports/timeout/max-conn) are invalid"
        cfg = cm.migrate(cfg)
        errs = cm.validate(cfg)
        if errs:
            return None, "; ".join(errs[:3])
        return cfg, None

    def save_only(self, silent=False):
        cfg, err = self._collect()
        if err:
            messagebox.showerror("Invalid config", err)
            return
        cm.save(CONFIG_PATH, cfg)
        xray_cfg = build_xray_config(int(cfg["LISTEN_PORT"]), int(cfg["SOCKS5_PORT"]), int(cfg["HTTP_PORT"]),
                                     cfg["TROJAN_PASSWORD"], cfg["TRANSPORT"], cfg["WS_PATH"], cfg["WS_HOST"])
        save_json(XRAY_CONFIG_PATH, xray_cfg)
        self.log("Saved config.json (+.full.json) + xray_config.json", "success")
        if not silent:
            self.toast("Configuration saved", "success")

    # -- profiles --------------------------------------------------
    def _current_cfg_or_warn(self):
        cfg, err = self._collect()
        if err:
            messagebox.showerror("Invalid config", err)
            return None
        return cfg

    def apply_cfg(self, cfg: dict):
        # Suppress autosave while mass-setting vars (profile load).
        self._loading_config = True
        try:
            cfg = cm.migrate(cfg)
            self.v_listen_host.set(str(cfg.get("LISTEN_HOST", "0.0.0.0")))
            self.v_listen_port.set(str(cfg.get("LISTEN_PORT", 40443)))
            snis = cfg.get("FAKE_SNIS") or [cfg.get("FAKE_SNI", "")]
            self.v_fake_sni.set(str(snis[0] if snis else ""))
            self.v_snis.set(", ".join(snis[1:4]))
            eps = cfg.get("ENDPOINTS") or []
            self.v_endpoint_ip.set(str(eps[0]["ip"]) if eps else "")
            self.v_endpoint_port.set(str(eps[0]["port"]) if eps else "443")
            self.v_extra.set("; ".join("%s:%s" % (e["ip"], e["port"]) for e in eps[1:3]))
            self.v_method.set(str(cfg.get("BYPASS_METHOD", "wrong_seq")))
            self.v_timeout.set(str(cfg.get("HANDSHAKE_TIMEOUT", 2.0)))
            self.v_maxconn.set(str(cfg.get("MAX_CONNECTIONS", 200)))
            self.v_idle.set(str(cfg.get("IDLE_TIMEOUT_S", 300.0)))
            self.v_mode.set(str(cfg.get("MODE", "SNI Only")))
            self.v_socks.set(str(cfg.get("SOCKS5_PORT", 10808)))
            self.v_http.set(str(cfg.get("HTTP_PORT", 10809)))
            self.v_password.set(str(cfg.get("TROJAN_PASSWORD", "humanity")))
            self.v_transport.set(str(cfg.get("TRANSPORT", "ws")))
            self.v_path.set(str(cfg.get("WS_PATH", "/assignment")))
            self.v_host.set(str(cfg.get("WS_HOST", "www.creationlong.org")))
        finally:
            self._loading_config = False

    # -- autosave (debounced) ---------------------------------------
    AUTOSAVE_DEBOUNCE_MS = 800

    def _schedule_autosave(self):
        """Debounce-schedule a config save after any config var changes."""
        try:
            if self._loading_config or self.running:
                return
            if self._autosave_after_id is not None:
                try:
                    self.root.after_cancel(self._autosave_after_id)
                except Exception:
                    pass
            self._autosave_after_id = self.root.after(
                self.AUTOSAVE_DEBOUNCE_MS, self._do_autosave)
        except Exception:
            pass

    def _do_autosave(self):
        self._autosave_after_id = None
        if self._loading_config or self.running:
            return
        try:
            cfg, err = self._collect()
            if err or cfg is None:
                # Half-typed values (e.g. empty endpoint while editing) must
                # not pop an error dialog — skip silently.
                return
            cm.save(CONFIG_PATH, cfg)
            try:
                self.log("autosaved config (debounced)", "info")
            except Exception:
                pass
            # Brief "saved" blip in the status pill (subtle feedback).
            try:
                prev = self.status_lbl.cget("text")
                if not self.running:
                    self.status_lbl.config(text="saved")
                    self.root.after(1000, lambda: self.status_lbl.config(text=prev))
            except Exception:
                pass
        except Exception as exc:
            try:
                self.log("autosave failed: %s" % exc, "warning")
            except Exception:
                pass

    def _attach_autosave_vars(self):
        """trace_add on every config StringVar + a pending-flush on close."""
        vars_to_watch = [
            self.v_listen_host, self.v_listen_port, self.v_endpoint_ip,
            self.v_endpoint_port, self.v_fake_sni, self.v_method,
            self.v_timeout, self.v_maxconn, self.v_idle,
            self.v_mode, self.v_socks, self.v_http, self.v_password,
            self.v_transport, self.v_path, self.v_host,
            self.v_extra, self.v_snis,
        ]
        for v in vars_to_watch:
            try:
                v.trace_add("write", lambda *a: self._schedule_autosave())
            except Exception:
                pass

    def profile_refresh(self):
        try:
            self.cbo_profile.config(values=list_profiles())
        except Exception:
            pass

    def profile_save(self):
        cfg = self._current_cfg_or_warn()
        if cfg is None:
            return
        name = (self.v_profile.get() or "").strip()
        if not name:
            messagebox.showinfo("Profile", "Type a profile name first (letters, digits, _ - .).")
            return
        if not valid_profile_name(name):
            messagebox.showerror("Profile", "Invalid name. Use letters/digits/_/-/. (max 41 chars).")
            return
        try:
            os.makedirs(PROFILES_DIR, exist_ok=True)
            with open(os.path.join(PROFILES_DIR, name + ".json"), "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            self.profile_refresh()
            self.log("Profile saved: %s" % name, "success")
            self.toast("Profile '%s' saved" % name, "success")
        except Exception as exc:
            messagebox.showerror("Profile", "Save failed: %s" % exc)

    def profile_load(self):
        name = (self.v_profile.get() or "").strip()
        if not name:
            messagebox.showinfo("Profile", "Select or type a profile name first.")
            return
        path = os.path.join(PROFILES_DIR, name + ".json")
        if not os.path.exists(path):
            messagebox.showerror("Profile", "Not found: %s" % name)
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            self.apply_cfg(cfg)
            self.log("Profile loaded: %s (press SAVE to apply to config.json)" % name, "success")
            self.toast("Profile '%s' loaded" % name, "success")
        except Exception as exc:
            messagebox.showerror("Profile", "Load failed: %s" % exc)

    def profile_delete(self):
        name = (self.v_profile.get() or "").strip()
        if not name:
            return
        path = os.path.join(PROFILES_DIR, name + ".json")
        try:
            if os.path.exists(path):
                if messagebox.askyesno("Profile", "Delete profile '%s'?" % name):
                    os.remove(path)
                    self.profile_refresh()
                    self.log("Profile deleted: %s" % name, "warning")
        except Exception as exc:
            messagebox.showerror("Profile", "Delete failed: %s" % exc)

    # -- smart tools -----------------------------------------------
    def _all_endpoints(self) -> list:
        cfg, _ = self._collect()
        if cfg:
            return cfg["ENDPOINTS"]
        return [{"ip": self.v_endpoint_ip.get().strip(), "port": 443}]

    def _sni_candidates(self, limit: int = 60) -> list:
        if self.file_snis:
            return list(self.file_snis[:limit])
        out = [self.v_fake_sni.get().strip()] + parse_sni_list(self.e_snis.get())
        return [s for s in out if s][:limit]

    def _primary_endpoint(self):
        ip = self.v_endpoint_ip.get().strip()
        try:
            port = int(self.v_endpoint_port.get().strip() or 443)
        except ValueError:
            port = 443
        return ip, port

    def _run_bg(self, fn, *args):
        self.busy_jobs += 1
        def wrapper():
            try:
                fn(*args)
            finally:
                self.msg_q.put(("busy", -1))
        threading.Thread(target=wrapper, args=(), daemon=True).start()

    def smart_rank_snis(self):
        ip, port = self._primary_endpoint()
        snis = self._sni_candidates()
        if not ip:
            self.log("Set a primary Endpoint IP first.", "warning")
            return
        if not snis:
            self.log("No SNIs to ping — fill sni_list.txt or the SNI fields.", "warning")
            return
        self.log("Pinging %d SNI(s) on %s:%s (TLS handshake)..." % (len(snis), ip, port), "info")

        def job():
            ranked = smart.rank_snis(ip, port, snis)
            for r in ranked[:20]:
                status = "%sms %s" % (r["latency_ms"], r["tls_version"]) if r["ok"] else "FAIL (%s)" % r["error"][:60]
                self.msg_q.put(("log", "smart", "%s -> %s" % (r["sni"], status)))
            ok = [r for r in ranked if r["ok"]]
            self.msg_q.put(("log", "smart",
                            "Best SNI: %s (%sms, %d/%d OK)" % (ok[0]["sni"], ok[0]["latency_ms"], len(ok), len(ranked))
                            if ok else "No SNI answered on %s:%s! Try another endpoint." % (ip, port)))
        self._run_bg(job)

    def smart_use_best_sni(self):
        ip, port = self._primary_endpoint()
        snis = self._sni_candidates()
        if not ip:
            self.log("Set a primary Endpoint IP first.", "warning")
            return
        if not snis:
            self.log("No SNIs to ping — fill sni_list.txt or the SNI fields.", "warning")
            return
        self.log("Pinging %d SNI(s) on %s:%s, will use the fastest..." % (len(snis), ip, port), "info")

        def job():
            ranked = smart.rank_snis(ip, port, snis)
            ok = [r for r in ranked if r["ok"]]
            if not ok:
                self.msg_q.put(("log", "smart", "No SNI answered on %s:%s." % (ip, port)))
                return
            best = ok[0]
            self.msg_q.put(("use_best_sni", best))
            self.msg_q.put(("log", "smart",
                            "Best SNI to spoof: %s (%sms). Press SAVE/START." % (best["sni"], best["latency_ms"])))
        self._run_bg(job)

    def smart_rank_endpoints(self):
        """TCP-connect ping every configured endpoint, ranked by latency."""
        eps = self._all_endpoints()
        if not eps:
            self.log("No endpoints configured — set Endpoint IP or ip_list.txt.", "warning")
            return
        try:
            timeout = float(self.v_timeout.get().strip() or 3.0)
        except ValueError:
            timeout = 3.0
        timeout = min(max(timeout, 0.5), 10.0)
        tries = 2
        self.log("Pinging %d endpoint(s) (TCP connect, %.1fs timeout, %d tries)..."
                 % (len(eps), timeout, tries), "info")

        def job():
            ranked = smart.rank_endpoints(eps, timeout=timeout, tries=tries)
            for r in ranked:
                if r["ok"]:
                    self.msg_q.put(("log", "smart",
                                    "endpoint %s:%s -> %sms OK" % (r["ip"], r["port"], r["latency_ms"])))
                else:
                    self.msg_q.put(("log", "smart",
                                    "endpoint %s:%s -> FAIL" % (r["ip"], r["port"])))
            ok = [r for r in ranked if r["ok"]]
            if ok:
                self.msg_q.put(("log", "smart",
                                "Best endpoint: %s:%s (%sms, %d/%d OK)"
                                % (ok[0]["ip"], ok[0]["port"], ok[0]["latency_ms"], len(ok), len(ranked))))
            else:
                self.msg_q.put(("log", "smart", "No endpoint answered."))
        self._run_bg(job)

    def smart_use_best_endpoint(self):
        """Ping endpoints and apply the fastest one as the primary endpoint."""
        eps = self._all_endpoints()
        if not eps:
            self.log("No endpoints configured — set Endpoint IP or ip_list.txt.", "warning")
            return
        try:
            timeout = float(self.v_timeout.get().strip() or 3.0)
        except ValueError:
            timeout = 3.0
        timeout = min(max(timeout, 0.5), 10.0)
        tries = 2
        self.log("Pinging %d endpoint(s), will use the fastest..." % len(eps), "info")

        def job():
            ranked = smart.rank_endpoints(eps, timeout=timeout, tries=tries)
            ok = [r for r in ranked if r["ok"]]
            if not ok:
                self.msg_q.put(("log", "smart", "No endpoint answered — keeping current endpoint."))
                return
            best = ok[0]
            self.msg_q.put(("use_best_endpoint", best))
            self.msg_q.put(("log", "smart",
                            "Primary endpoint set to %s:%s (%sms). Press SAVE/START."
                            % (best["ip"], best["port"], best["latency_ms"])))
        self._run_bg(job)

    def smart_reload_lists(self):
        try:
            port = int(self.v_endpoint_port.get().strip() or 443)
        except ValueError:
            port = 443
        try:
            self.file_endpoints = lists_mod.load_ip_list(IP_LIST_PATH, default_port=port)
        except Exception:
            self.file_endpoints = []
        try:
            self.file_snis = lists_mod.load_sni_list(SNI_LIST_PATH)
        except Exception:
            self.file_snis = []
        self.log("Reloaded: %d endpoint(s) from ip_list.txt, "
                 "%d SNI(s) from sni_list.txt." % (len(self.file_endpoints), len(self.file_snis)), "success")
        try:
            if self.file_endpoints and not self.v_extra.get().strip():
                self.v_extra.set("; ".join(
                    "%s:%s" % (e["ip"], e["port"]) for e in self.file_endpoints[:4]))
            if self.file_snis and not self.v_snis.get().strip():
                primary = self.v_fake_sni.get().strip()
                rest = [s for s in self.file_snis if s != primary][:4]
                self.v_snis.set(", ".join(rest))
        except Exception:
            pass
        self.toast("Lists reloaded", "success")

    # -- process control -------------------------------------------
    def _bar_show(self, show):
        try:
            if show and not self._bar_running:
                self.start_bar.place(relx=0, rely=0, relwidth=1, height=4)
                self.start_bar.start(14)
                self._bar_running = True
                self.root.after(8000, lambda: self._bar_show(False))
            elif not show and self._bar_running:
                self.start_bar.stop()
                self.start_bar.place_forget()
                self._bar_running = False
        except Exception:
            pass

    def start(self):
        if self.running:
            self.log("Already running.", "warning")
            return
        # Drop stale stats/logs from a previous run so counters don't flash
        # old values after restart; also frees queued memory.
        self._drain_queue()
        cfg, err = self._collect()
        if err:
            messagebox.showerror("Invalid config", err)
            self.log("Invalid config: %s" % err, "error")
            return
        if getattr(sys, "frozen", False):
            if not os.path.exists(BACKEND_EXE):
                messagebox.showerror("Missing file", "sni-backend.exe not found:\n%s" % BACKEND_EXE)
                return
        elif not os.path.exists(MAIN_PATH):
            messagebox.showerror("Missing file", "main.py not found:\n%s" % MAIN_PATH)
            return
        try:
            lp = int(cfg["LISTEN_PORT"])
            if not smart.is_port_free("127.0.0.1", lp):
                messagebox.showerror("Port busy",
                        "Port %d is already IN USE — a stale backend is probably "
                        "still running ( duplicates silently steal traffic and "
                        "freeze the tracker).\n\nPress STOP first, or kill leftovers "
                        "in an Admin cmd:\n"
                        "  taskkill /F /IM sni-backend.exe" % lp)
                self.log("Port %d busy — refusing to start a duplicate backend. "
                         "Kill stale sni-backend.exe first." % lp, "error")
                return
        except Exception:
            pass
        if not is_admin():
            if not messagebox.askyesno("Not admin",
                    "You are NOT Administrator. WinDivert will likely fail.\nStart anyway?"):
                return
        self.save_only(silent=True)
        cfg, err = self._collect()
        if err:
            return
        eps = ", ".join("%s:%s" % (e["ip"], e["port"]) for e in cfg["ENDPOINTS"][:4])
        self.log("Starting: %s:%s -> [%s] "
                 "(SNI=%s, method=%s)" % (cfg["LISTEN_HOST"], cfg["LISTEN_PORT"], eps,
                                          cfg["FAKE_SNIS"][0], cfg["BYPASS_METHOD"]), "info")
        try:
            self.manual_stop = False
            self._run_id += 1
            self.injector_proc = self._spawn(backend_cmd("--config", CONFIG_PATH))
        except Exception as exc:
            self.log("Failed to start injector: %s" % exc, "error")
            return
        if cfg["MODE"] == "Trojan + Xray":
            xray_exe = find_xray_exe()
            if not xray_exe:
                self.log("xray.exe not found (searched APP_DIR, xray/bin subfolders, CWD, PATH, "
                         "XRAY_PATH) — running SNI injector only.", "warning")
            else:
                try:
                    self.log("Using xray: %s" % xray_exe, "info")
                    self.xray_proc = self._spawn([xray_exe, "-c", XRAY_CONFIG_PATH])
                    self.log("Xray started (SOCKS5 :%s, HTTP :%s)"
                             % (cfg["SOCKS5_PORT"], cfg["HTTP_PORT"]), "success")
                except Exception as exc:
                    self.log("Xray start failed: %s" % exc, "warning")
        self.running = True
        self.start_time = time.time()
        self.active_conns = self.total_conns = self.success_conns = self.failed_conns = 0
        self.success_rate = 0.0
        self.best_endpoint = ""
        self.best_method = ""
        self.method_rate = 0.0
        self.method_runs = 0
        self.auto_method = ""
        self.auto_stats = {}
        # Traffic tracker reset for this run.
        self.up_bytes = 0
        self.down_bytes = 0
        self.up_rate = 0.0
        self.down_rate = 0.0
        self._prev_up = 0
        self._prev_down = 0
        self._prev_traffic_t = time.time()
        self._last_stats_t = time.time()
        self._no_stats_warned = False
        self._traffic_warn_done = False
        self._stats_seen = False
        self._refresh_stats()
        self._update_method_hint()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self._set_status(True)
        self._bar_show(True)
        self.injector_reader = threading.Thread(target=self._reader, args=(self.injector_proc, "injector", self._run_id), daemon=True)
        self.injector_reader.start()
        if self.xray_proc:
            self.xray_reader = threading.Thread(target=self._reader, args=(self.xray_proc, "xray", self._run_id), daemon=True)
            self.xray_reader.start()
        else:
            self.xray_reader = None
        self.log("Injector started.", "success")
        self.toast("Engine started", "success")

    def _spawn(self, cmd: list):
        if sys.platform == "win32":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            proc = subprocess.Popen(cmd, cwd=APP_DIR, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1,
                                    encoding="utf-8", errors="replace",
                                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            proc = subprocess.Popen(cmd, cwd=APP_DIR, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1,
                                    encoding="utf-8", errors="replace")
        self._pin_child(proc)
        return proc

    def _pin_child(self, proc):
        """Pin a child proc into a KILL_ON_JOB_CLOSE job (Windows only).

        Once pinned, Windows kills the child automatically whenever THIS
        process dies — X-close, End Task, crash, console close — so backends
        can never be orphaned in the background holding the port. Never raises;
        silently keeps old behavior if pinning is unavailable (e.g. nested job).
        """
        if sys.platform != "win32" or proc is None:
            return
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            job = getattr(self, "_child_job", None)
            if job is None:
                job = k32.CreateJobObjectW(None, None)
                if not job:
                    return
                is64 = ctypes.sizeof(ctypes.c_void_p) == 8
                buf = (ctypes.c_byte * (144 if is64 else 112))()
                # LimitFlags lives at offset 16 on both 32/64-bit;
                # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000.
                ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[4] = 0x2000
                # JobObjectExtendedLimitInformation = 9.
                if k32.SetInformationJobObject(job, 9, buf, len(buf)):
                    self._child_job = job
                else:
                    try:
                        k32.CloseHandle(job)
                    except Exception:
                        pass
                    return
            try:
                k32.AssignProcessToJobObject(job, proc._handle)
            except Exception:
                pass
        except Exception:
            pass

    def _reader(self, proc, tag: str, run_id: int = 0):
        try:
            assert proc.stdout is not None
            noise_tail = 0  # lines remaining in an overlapped-cancel spam burst
            for line in iter(proc.stdout.readline, ""):
                if not line:
                    break
                line = line.rstrip("\r\n")
                if not line:
                    continue
                stripped = line.lstrip()
                if stripped.startswith("{"):
                    try:
                        obj = json.loads(stripped)
                        if isinstance(obj, dict) and obj.get("type") == "stats":
                            self.msg_q.put(("stats", run_id, obj))
                            continue
                    except Exception:
                        pass
                if _is_noise_line(line):
                    noise_tail = 8
                    continue
                if noise_tail > 0 and _is_overlapped_tail(line):
                    noise_tail -= 1
                    continue
                noise_tail = 0
                # Bound queue memory: if the UI thread falls behind (long
                # uptime, log burst), drop routine log lines rather than
                # growing msg_q unbounded. Stats/exit messages still pass.
                try:
                    if self.msg_q.qsize() > 2000:
                        continue
                except Exception:
                    pass
                self.msg_q.put(("log", tag, line))
        except Exception as exc:
            self.msg_q.put(("log", tag, "[%s] reader error: %s" % (tag, exc)))
        finally:
            self.msg_q.put(("exit", tag, run_id))

    def _poll_queue(self):
        cur_run = getattr(self, "_run_id", 0)
        try:
            while True:
                try:
                    msg = self.msg_q.get_nowait()
                    kind = msg[0]
                except queue.Empty:
                    break
                except Exception:
                    continue
                if kind == "stats":
                    if not self.running:
                        continue
                    try:
                        _, rid, obj = msg
                    except (TypeError, ValueError):
                        try:
                            _, obj = msg
                        except (TypeError, ValueError):
                            continue
                        rid = cur_run
                    if rid != cur_run:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    self._last_stats_t = time.time()
                    if not getattr(self, "_stats_seen", False):
                        self._stats_seen = True
                        self._append("[gui] Receiving backend stats — tracker live.", "success")
                    if ("up_bytes" not in obj and "down_bytes" not in obj
                            and not self._traffic_warn_done):
                        self._traffic_warn_done = True
                        self._append("[gui] Backend does not report traffic counters "
                                     "(up/down missing) — update sni-backend.exe / main.py "
                                     "to the matching version.", "warning")
                    try:
                        self.active_conns = int(obj.get("active", 0))
                        self.total_conns = int(obj.get("total", 0))
                        self.success_conns = int(obj.get("success", 0))
                        self.failed_conns = int(obj.get("failed", 0))
                        self.success_rate = float(obj.get("success_rate", 0.0))
                        be = str(obj.get("best_endpoint", "") or "")
                        if be:
                            self.best_endpoint = be
                        else:
                            sb = obj.get("scoreboard") or {}
                            eps = sb.get("endpoints") or []
                            if eps:
                                self.best_endpoint = str(eps[0].get("key", ""))
                        bm = str(obj.get("best_method", "") or "")
                        if bm:
                            self.best_method = bm
                            meths = obj.get("methods") or []
                            if meths:
                                self.method_rate = float(meths[0].get("rate", 0.0))
                                self.method_runs = int(meths[0].get("ok", 0)) + int(meths[0].get("fail", 0))
                        # --- traffic tracker: totals from backend, rates local ---
                        try:
                            new_up = int(obj.get("up_bytes", self.up_bytes) or 0)
                            new_down = int(obj.get("down_bytes", self.down_bytes) or 0)
                        except (TypeError, ValueError):
                            new_up, new_down = self.up_bytes, self.down_bytes
                        now = time.time()
                        if self._prev_traffic_t:
                            dt = now - self._prev_traffic_t
                            if dt >= 0.5:
                                # Guard against backend restart (counters reset).
                                if new_up >= self._prev_up and new_down >= self._prev_down and dt > 0:
                                    self.up_rate = (new_up - self._prev_up) / dt
                                    self.down_rate = (new_down - self._prev_down) / dt
                                self._prev_up, self._prev_down = new_up, new_down
                                self._prev_traffic_t = now
                        else:
                            self._prev_up, self._prev_down = new_up, new_down
                            self._prev_traffic_t = now
                        self.up_bytes, self.down_bytes = new_up, new_down
                    except Exception:
                        pass
                    try:
                        am = obj.get("auto_method") or {}
                        if isinstance(am, dict) and am.get("method"):
                            self.auto_method = str(am.get("method", ""))
                            self.auto_stats = am
                    except Exception:
                        pass
                    try:
                        self._update_active_table(obj.get("active_list") or [])
                    except Exception:
                        pass
                    self._refresh_stats()
                    self._update_method_hint()
                elif kind == "busy":
                    try:
                        self.busy_jobs = max(0, self.busy_jobs + int(msg[1]))
                    except Exception:
                        pass
                elif kind == "use_best_endpoint":
                    try:
                        _, best = msg
                    except (TypeError, ValueError):
                        continue
                    if not isinstance(best, dict):
                        continue
                    ip = str(best.get("ip", "") or "").strip()
                    port = str(best.get("port", "") or "").strip()
                    if ip:
                        self.v_endpoint_ip.set(ip)
                        if port:
                            self.v_endpoint_port.set(port)
                    self._append("Primary endpoint set to %s:%s "
                                 "(%sms)" % (ip, port, best.get("latency_ms")), "success")
                    self.toast("Best endpoint applied: %s:%s" % (ip, port), "success")
                elif kind == "use_best_sni":
                    try:
                        _, best = msg
                    except (TypeError, ValueError):
                        continue
                    if not isinstance(best, dict):
                        continue
                    sni = str(best.get("sni", "") or "").strip()
                    if sni:
                        self.v_fake_sni.set(sni)
                    self._append("Fake SNI set to %s "
                                 "(%sms on primary endpoint)" % (sni, best.get("latency_ms")), "success")
                    self.toast("Best SNI applied: %s" % sni, "success")
                elif kind == "log":
                    try:
                        _, tag, line = msg
                    except (TypeError, ValueError):
                        continue
                    low = line.lower()
                    if "server started on" in low and tag == "injector":
                        self._bar_show(False)
                    # Console always hides routine injector packet chatter
                    # (total silence). Smart-tool, gui and error lines pass.
                    if tag == "injector" and _is_routine_injector_line(line):
                        # Still surface WinDivert failures that hide in routine flow.
                        if tag == "injector" and ("windivert" in low or "access is denied" in low
                                                 or "1058" in low):
                            try:
                                hint = windivert_hint_for_error(line, is_admin())
                            except Exception:
                                hint = "WinDivert failed."
                            self._append("[gui] %s" % hint, "error")
                        continue
                    if "error" in low or "fatal" in low or "traceback" in low:
                        lvl = "error"
                    elif "warn" in low:
                        lvl = "warning"
                    elif "success" in low or "started" in low or "ok (" in low or "tls ok" in low:
                        lvl = "success"
                    else:
                        lvl = "info"
                    self._append("[%s] %s" % (tag, line), lvl)
                    if tag == "injector" and ("windivert" in low or "access is denied" in low
                                              or "1058" in low):
                        try:
                            hint = windivert_hint_for_error(line, is_admin())
                        except Exception:
                            hint = "WinDivert failed."
                        self._append("[gui] %s" % hint, "error")
                elif kind == "exit":
                    try:
                        _, tag, rid = msg
                    except (TypeError, ValueError):
                        try:
                            _, tag = msg
                        except (TypeError, ValueError):
                            continue
                        rid = cur_run
                    self._append("[%s] process exited." % tag, "warning")
                    if (tag == "injector" and not self.manual_stop and self.running
                            and rid == cur_run):
                        self.root.after(0, lambda _rid=rid: self._on_injector_exit(_rid))
        except queue.Empty:
            pass
        except Exception:
            # Never let one bad message kill the loop (frozen tracker/uptime).
            pass
        finally:
            try:
                if self.running and self.start_time:
                    secs = int(time.time() - self.start_time)
                    self.lbl_uptime.config(text="%02d:%02d" % (secs // 60, secs % 60))
                    if (not self._no_stats_warned and self._last_stats_t
                            and (time.time() - self._last_stats_t) > 30.0):
                        self._no_stats_warned = True
                        self._append("[gui] No traffic stats from backend for 30s — "
                                     "check the console above for FATAL/WinDivert errors. "
                                     "If using sni-backend.exe, update it to the matching version.", "warning")
            except Exception:
                pass
            try:
                self.root.after(120, self._poll_queue)
            except Exception:
                pass

    def _refresh_stats(self):
        try:
            self.lbl_active.config(text="● Active %d" % self.active_conns)
            self.lbl_total.config(text="Total %d" % self.total_conns)
            self.lbl_okfail.config(text="OK %d · Fail %d" % (self.success_conns, self.failed_conns))
            best = self.best_endpoint or "—"
            self.lbl_best.config(text="Best %s (%.0f%%)" % (best, self.success_rate * 100.0))
            if self.auto_method:
                st = self.auto_stats or {}
                self.lbl_method.config(text="Method auto→%s (%d att, %d fail, %.0fs)"
                                       % (self.auto_method, int(st.get("attempts", 0)),
                                          int(st.get("failures", 0)), float(st.get("elapsed", 0.0))))
            elif self.best_method:
                runs = self.method_runs
                self.lbl_method.config(text="Method %s · %.0f%% (%d)" % (self.best_method, self.method_rate * 100.0, runs))
            else:
                self.lbl_method.config(text="Method —")
        except Exception:
            pass
        # Traffic tracker: totals + live rates.
        try:
            self.lbl_up.config(text="▲ %s (%s/s)" % (fmt_bytes(self.up_bytes), fmt_bytes(self.up_rate)))
        except Exception:
            pass
        try:
            self.lbl_down.config(text="▼ %s (%s/s)" % (fmt_bytes(self.down_bytes), fmt_bytes(self.down_rate)))
        except Exception:
            pass

    def _update_method_hint(self):
        """Live scoreboard hint under the method cards."""
        try:
            if self.best_method and self.method_runs > 0:
                self.lbl_method_hint.configure(
                    text="Live best: %s · %.0f%% success over %d bypass(es) — Auto already uses it. "
                         "Pick one card to force it." % (self.best_method, self.method_rate * 100.0, self.method_runs))
            else:
                self.lbl_method_hint.configure(text="")
        except Exception:
            pass

    def _on_injector_exit(self, run_id=None):
        # No auto-restart: a crash stops the engine and re-enables START,
        # so STOP always works and logs never spam "1/3" forever.
        if self.manual_stop or not self.running:
            return
        if run_id is not None and run_id != self._run_id:
            return
        self._terminate(self.xray_proc)
        self.xray_proc = None
        self.injector_proc = None
        self.running = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self._set_status(False)
        self._bar_show(False)
        self.log("Injector exited — port in use? not admin? WinDivert driver? "
                 "Fix the error above, then press START again.", "error")

    def stop(self):
        if not self.running and self.injector_proc is None:
            return
        self.manual_stop = True
        self.running = False
        # Invalidate any in-flight messages from this run immediately;
        # late stats/exit from lingering readers are then ignored by epoch.
        self._run_id += 1
        old_injector, old_xray = self.injector_proc, self.xray_proc
        inj_dead = self._terminate(old_injector)
        xray_dead = self._terminate(old_xray)
        self.injector_proc = None
        self.xray_proc = None
        for _proc, _dead, _name in ((old_injector, inj_dead, "injector backend"),
                                    (old_xray, xray_dead, "xray")):
            if _proc is not None and not _dead:
                try:
                    _pid = _proc.pid
                except Exception:
                    _pid = "?"
                self.log("Could not kill %s (PID %s) — kill it in an Admin cmd: "
                         "taskkill /F /PID %s" % (_name, _pid, _pid), "error")
        for _attr in ("injector_reader", "xray_reader"):
            try:
                _t = getattr(self, _attr, None)
                if _t is not None and _t.is_alive():
                    _t.join(timeout=0.5)
            except Exception:
                pass
            try:
                setattr(self, _attr, None)
            except Exception:
                pass
        self._drain_queue()
        self.log("Stopping...", "warning")
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self._set_status(False)
        self._bar_show(False)
        self.lbl_uptime.config(text="--:--")
        # Session summary: traffic totals.
        try:
            self._append("Session traffic: ▲ %s up · ▼ %s down "
                         "(OK %d · Fail %d)." % (fmt_bytes(self.up_bytes), fmt_bytes(self.down_bytes),
                                                 self.success_conns, self.failed_conns), "info")
        except Exception:
            pass
        self.log("Stopped.", "warning")
        self.toast("Engine stopped", "warning")

    @staticmethod
    def _terminate(proc) -> bool:
        """Terminate a child, escalating to kill. Returns True if it is gone.

        Never raises. A False return means the process survived (e.g. access
        denied) — callers must surface that instead of silently orphaning it.
        """
        if proc is None:
            return True
        try:
            if proc.poll() is not None:
                return True
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        try:
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=3)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            return proc.poll() is not None
        except Exception:
            return True

    # -- misc UI ---------------------------------------------------
    def _set_status(self, on: bool):
        if on:
            self.status_dot.config(fg=THEME["success"])
            self.status_lbl.config(text="ACTIVE", fg=THEME["success"], font=FONT_STATUS)
            try:
                self.status_pill.config(highlightbackground=THEME["success"])
            except Exception:
                pass
        else:
            self.status_dot.config(fg=THEME["faint"])
            self.status_lbl.config(text="INACTIVE", fg=THEME["muted"], font=FONT_STATUS)
            try:
                self.status_pill.config(highlightbackground=THEME["card_edge"])
            except Exception:
                pass

    def log(self, text: str, level: str = "info"):
        # Bound queue memory over long uptime: drop gui logs if UI is behind.
        try:
            if self.msg_q.qsize() > 2000:
                return
        except Exception:
            pass
        self.msg_q.put(("log", "gui", text))

    def _drain_queue(self):
        """Drop pending stats/log messages (e.g. on START/STOP) to free memory
        and avoid stale stats from a previous run flashing after restart."""
        try:
            while True:
                self.msg_q.get_nowait()
        except queue.Empty:
            pass
        except Exception:
            pass

    def _append(self, text: str, level: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, text)
        try:
            self.console.insert(tk.END, line, level)
            self.console.see(tk.END)
        except Exception:
            pass
        try:
            if int(self.console.index("end-1c").split(".")[0]) > 3000:
                self.console.delete("1.0", "500.0")
        except Exception:
            pass
        try:
            if self.log_file:
                # Rotate daily log past ~10MB so long uptime can't fill disk.
                try:
                    if os.path.exists(self.log_file) and os.path.getsize(self.log_file) > 10 * 1024 * 1024:
                        base, ext = os.path.splitext(self.log_file)
                        try:
                            os.rename(self.log_file,
                                      "%s_%s%s" % (base, datetime.now().strftime("%H%M%S"), ext))
                        except Exception:
                            pass
                except Exception:
                    pass
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(line)
        except Exception:
            pass

    def _open_log_file(self):
        try:
            os.makedirs(LOGS_DIR, exist_ok=True)
            self.log_file = os.path.join(LOGS_DIR, "gui_%s.log" % datetime.now().strftime("%Y%m%d"))
        except Exception:
            self.log_file = None

    def clear_log(self):
        self.console.delete("1.0", tk.END)

    def export_log(self):
        try:
            name = os.path.join(APP_DIR, "sni_log_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S"))
            with open(name, "w", encoding="utf-8") as f:
                f.write(self.console.get("1.0", tk.END))
            self._append("Log exported: %s" % name, "success")
            self.toast("Log exported", "success")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def copy_proxy(self):
        info = "SOCKS5: 127.0.0.1:%s\nHTTP: 127.0.0.1:%s" % (self.v_socks.get().strip(), self.v_http.get().strip())
        self.root.clipboard_clear()
        self.root.clipboard_append(info)
        self._append("Proxy info copied to clipboard.", "success")
        self.toast("Proxy info copied", "success")

    def on_closing(self):
        # Flush any pending debounced autosave so the last edits survive.
        try:
            if self._autosave_after_id is not None:
                try:
                    self.root.after_cancel(self._autosave_after_id)
                except Exception:
                    pass
                self._autosave_after_id = None
                self._do_autosave()
        except Exception:
            pass
        # NOTE: no try/finally with destroy inside — a `return` (user said No)
        # must leave the window alive. _shutdown_children never raises.
        if self.running:
            try:
                stop_it = messagebox.askyesno("Exit", "Injector is running. Stop and exit?")
            except Exception:
                stop_it = True
            if not stop_it:
                return
            self.manual_stop = True
        self._shutdown_children()
        try:
            self.root.destroy()
        except Exception:
            pass

    def _shutdown_children(self):
        """Best-effort child cleanup for app exit. Never raises.

        stop() early-returns when idle, but a proc handle can still exist
        transiently — make sure no backend/xray is left running behind us.
        (Job-object pinning + backend pipe-break exit cover abnormal deaths.)
        """
        try:
            self.stop()
        except Exception:
            pass
        for attr in ("injector_proc", "xray_proc"):
            try:
                proc = getattr(self, attr, None)
                if proc is None:
                    continue
                try:
                    if proc.poll() is None:
                        self._terminate(proc)
                finally:
                    try:
                        setattr(self, attr, None)
                    except Exception:
                        pass
            except Exception:
                continue


def main():
    os.chdir(APP_DIR)
    set_windows_appusermodelid()  # before the first window exists
    root = tk.Tk()
    set_app_icon(root)
    SpooferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
