# utils/auto_state.py — adaptive sticky "auto" bypass-method rotation.
#
# "auto" used to re-randomize the bypass method for EVERY connection, which
# made it unlearnable and unobservable. Instead the engine now STICKS with one
# method for a window and rotates only when a trigger fires:
#   * failures >= 3
#   * attempts >= 10
#   * window elapsed >= 60s
# Thread-safe with a plain threading.Lock: fake_tcp's fake_send_thread runs
# inside BoundedExecutor worker threads, while resolve_method()/next_method()
# are called from the asyncio loop thread.
from __future__ import annotations

import logging
import random
import threading
import time
from typing import Optional

log = logging.getLogger("auto_state")

# Rotation thresholds (whichever fires first).
AUTO_MAX_FAILURES = 3
AUTO_MAX_ATTEMPTS = 10
AUTO_WINDOW_S = 60.0

REAL_METHODS = (
    "wrong_seq", "wrong_seq_ttl", "split_seq", "fragmented",
    "padding", "delayed_retry", "double_sni",
)


class AutoState:
    """Sticky auto-mode rotation state (thread-safe)."""

    def __init__(self, methods: tuple = REAL_METHODS,
                 max_failures: int = AUTO_MAX_FAILURES,
                 max_attempts: int = AUTO_MAX_ATTEMPTS,
                 window_s: float = AUTO_WINDOW_S, clock=time.monotonic):
        self._methods = tuple(methods)
        if not self._methods:
            raise ValueError("AutoState requires at least one method")
        self._max_failures = max(1, int(max_failures))
        self._max_attempts = max(1, int(max_attempts))
        self._window_s = float(window_s)
        self._clock = clock
        self._lock = threading.Lock()
        self._current: str = self._methods[0]
        self._attempts = 0
        self._failures = 0
        self._successes = 0
        self._started_at = self._clock()
        self._log = logging.getLogger("auto_state")

    # -- internals -----------------------------------------------------
    def _rotate_locked(self) -> tuple:
        """Pick a fresh method != current; reset counters + window.

        Returns (previous, attempts, failures, elapsed) so the caller can log
        the COMPLETED window's counts (post-reset they are all zero).
        """
        previous = self._current
        attempts = self._attempts
        failures = self._failures
        elapsed = self._clock() - self._started_at
        if len(self._methods) > 1:
            choices = [m for m in self._methods if m != previous]
            self._current = random.choice(choices)
        else:
            self._current = self._methods[0]
        self._attempts = 0
        self._failures = 0
        self._successes = 0
        self._started_at = self._clock()
        return previous, attempts, failures, elapsed

    # -- public API ----------------------------------------------------
    def next_method(self) -> str:
        """Return the current sticky method and count one attempt.

        Rotates FIRST when the previous window has expired its triggers, so
        the returned method always belongs to the freshly opened window.
        """
        with self._lock:
            elapsed = self._clock() - self._started_at
            if (self._failures >= self._max_failures
                    or self._attempts >= self._max_attempts
                    or elapsed >= self._window_s):
                prev, att, fails, win_elapsed = self._rotate_locked()
                try:
                    self._log.info(
                        "auto: rotating method %s -> %s (attempts=%d failures=%d elapsed=%.0fs)",
                        prev, self._current, att, fails, win_elapsed)
                except Exception:
                    pass
            self._attempts += 1
            return self._current

    def note_failure(self) -> None:
        """Count one failed connection against the current window."""
        with self._lock:
            self._failures += 1

    def note_success(self) -> None:
        """Count one successful connection (observability only)."""
        with self._lock:
            self._successes += 1

    @property
    def current_method(self) -> str:
        with self._lock:
            return self._current

    def stats(self) -> dict:
        """Snapshot for GUI/stats: current sticky method + window counters."""
        with self._lock:
            return {
                "method": self._current,
                "attempts": self._attempts,
                "failures": self._failures,
                "successes": self._successes,
                "elapsed": round(self._clock() - self._started_at, 1),
                "window_s": self._window_s,
                "max_failures": self._max_failures,
                "max_attempts": self._max_attempts,
            }

    def reset(self, method: Optional[str] = None) -> None:
        """Reset to a fresh window (self-tests, config reload)."""
        with self._lock:
            if method and method in self._methods:
                self._current = method
            self._attempts = 0
            self._failures = 0
            self._successes = 0
            self._started_at = self._clock()


_singleton: Optional[AutoState] = None
_singleton_lock = threading.Lock()


def get_auto_state() -> AutoState:
    """Module-level singleton accessor (thread-safe, lazy init)."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = AutoState()
    return _singleton


def reset_auto_state(method: Optional[str] = None) -> None:
    """Reset the singleton (used by self-tests so runs are deterministic)."""
    get_auto_state().reset(method=method)
