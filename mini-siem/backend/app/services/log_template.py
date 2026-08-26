"""
Log template extraction (Drain-like): mask IPs, numbers, hex, and long tokens
to build a stable template string for clustering / anomaly features.
"""

from __future__ import annotations

import hashlib
import re

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_HEX = re.compile(r"\b[0-9a-fA-F]{8,}\b")
_RE_NUMBER = re.compile(r"\b\d+\b")
_RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def extract_template(message: str) -> str:
    if not message:
        return "<empty>"
    s = message.strip()
    s = _RE_UUID.sub("<UUID>", s)
    s = _RE_IPV4.sub("<IP>", s)
    s = _RE_HEX.sub("<HEX>", s)
    s = _RE_NUMBER.sub("<N>", s)
    s = re.sub(r"\s+", " ", s)
    return s[:4000]


def template_fingerprint(template: str) -> str:
    return hashlib.sha256(template.encode("utf-8", errors="replace")).hexdigest()[:16]
