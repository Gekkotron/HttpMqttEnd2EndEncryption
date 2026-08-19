"""Env-var helpers tolerant of trailing inline comments.

systemd's `EnvironmentFile=` does NOT strip trailing `# comment` fragments
from values (unlike python-dotenv). If a user copies `.env.example` and
uncomments a line that had an inline comment, e.g.

    RESTART_BACKOFF_MAX_ATTEMPTS=5    # 0 = retry forever until PASS

then under systemd the value seen by Python is the literal
``"5    # 0 = retry forever until PASS"`` — which crashes ``int()`` /
``float()``. These helpers strip the trailing comment defensively before
parsing so a stray inline comment is a warning, not a startup crash.

Only whitespace + '#' is treated as an inline-comment delimiter, so a
value that legitimately starts with '#' (or contains '#' with no leading
whitespace) is preserved.
"""
from __future__ import annotations

import os
import re


_INLINE_COMMENT = re.compile(r"\s+#.*$")


def _strip_inline_comment(raw: str) -> str:
    return _INLINE_COMMENT.sub("", raw).strip()


def env_str(name: str, default: str = "") -> str:
    """Return the env var, stripped of inline comments and surrounding space."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return _strip_inline_comment(raw)


def env_int(name: str, default: int) -> int:
    """Parse the env var as int, tolerating inline comments and blank values."""
    raw = os.getenv(name)
    if raw is None:
        return default
    cleaned = _strip_inline_comment(raw)
    if not cleaned:
        return default
    return int(cleaned)


def env_float(name: str, default: float) -> float:
    """Parse the env var as float, tolerating inline comments and blank values."""
    raw = os.getenv(name)
    if raw is None:
        return default
    cleaned = _strip_inline_comment(raw)
    if not cleaned:
        return default
    return float(cleaned)
