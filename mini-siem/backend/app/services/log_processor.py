"""
Log normalization pipeline: ingest heterogeneous raw logs and emit a unified JSON shape.
Supports Syslog (BSD + simplified RFC5424), Windows Event-style lines, and Apache/Nginx combined logs.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from dateutil import parser as date_parser
from pydantic import BaseModel, Field


class LogSourceType(str, Enum):
    SYSLOG = "syslog"
    WINDOWS = "windows_event"
    WEB = "web_server"
    TRAFFIC = "ip_traffic"
    UNKNOWN = "unknown"


class NormalizedLogEvent(BaseModel):
    """Unified log record for storage, rules, and ML downstream."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source_type: LogSourceType
    normalized: bool = True
    severity: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    user: str | None = None
    facility: str | None = None
    event_code: str | None = None
    http_method: str | None = None
    http_status: int | None = None
    url_path: str | None = None
    message: str
    raw: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump_json_safe(self) -> dict[str, Any]:
        d = self.model_dump(mode="python")
        d["timestamp"] = self.timestamp.isoformat()
        d["source_type"] = self.source_type.value
        return d


# --- Regex patterns ---

# BSD Syslog: <pri>MMM dd hh:mm:ss host tag: message
_RE_BSD_SYSLOG = re.compile(
    r"^<(?P<pri>\d+)>(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:]+):\s*(?P<msg>.*)$"
)

# Simplified RFC 5424: PRI VERSION SP TIMESTAMP SP HOST SP APP SP PROCID SP MSGID SP STRUCTURED-DATA MSG
_RE_RFC5424 = re.compile(
    r"^<(?P<pri>\d+)>\d+\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>\[[^\]]*\]|-)\s*"
    r"(?P<msg>.*)$"
)

# Windows Event Log text simulation: "YYYY-MM-DD HH:MM:SS" Level=... Source=... EventID=...
_RE_WIN_EVENT = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?:Level=(?P<level>\w+)\s+)?"
    r"(?:Source=(?P<source>[^\s]+)\s+)?"
    r"(?:EventID=(?P<eid>\d+)\s+)?"
    r"(?:Computer=(?P<computer>[^\s]+)\s+)?"
    r"(?P<rest>.*)$",
    re.IGNORECASE,
)

# Apache/Nginx combined: host ident user [date] "method path proto" status size ...
_RE_COMBINED = re.compile(
    r"^(?P<ip>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<req>(?P<method>\S+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\S+)"
)

# Simulated packet / flow line: SRC=x.x.x.x DST=y.y.y.y PROTO=TCP ...
_RE_TRAFFIC = re.compile(
    r"(?:SRC|src)=(?P<src>[\d.]+).*?(?:DST|dst)=(?P<dst>[\d.]+)",
    re.IGNORECASE | re.DOTALL,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_short(s: str, n: int = 12) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:n]


def _traffic_kv(line: str, key: str) -> str | None:
    m = re.search(rf"(?:^|\s){re.escape(key)}=(?P<v>\S+)", line, re.I)
    return m.group("v") if m else None


def _parse_ts(s: str | None, fallback: datetime) -> datetime:
    if not s or not s.strip():
        return fallback
    try:
        dt = date_parser.parse(s.strip(), fuzzy=False)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return fallback


def _parse_apache_ts(s: str, fallback: datetime) -> datetime:
    """Apache/Nginx combined log: 04/Apr/2026:12:00:01 +0000"""
    try:
        dt = datetime.strptime(s.strip(), "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except ValueError:
        return _parse_ts(s, fallback)


def _syslog_severity_from_pri(pri: str | None) -> str | None:
    if not pri:
        return None
    try:
        p = int(pri)
        sev = p % 8
        names = [
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "informational",
            "debug",
        ]
        return names[sev] if 0 <= sev < len(names) else None
    except ValueError:
        return None


class LogProcessor:
    """
    Normalizes raw log lines into NormalizedLogEvent.
    Auto-detects format; optional hint via source_hint.
    """

    def normalize(
        self,
        raw_line: str,
        *,
        source_hint: LogSourceType | None = None,
        received_at: datetime | None = None,
    ) -> NormalizedLogEvent:
        line = (raw_line or "").strip()
        now = received_at or _utc_now()
        if not line:
            return self._unknown(line, now, reason="empty")

        if source_hint == LogSourceType.TRAFFIC:
            return self._parse_traffic(line, now)
        if source_hint == LogSourceType.WINDOWS:
            return self._parse_windows(line, now)
        if source_hint == LogSourceType.WEB:
            return self._parse_web(line, now)
        if source_hint == LogSourceType.SYSLOG:
            return self._parse_syslog(line, now)

        # Auto-detect order: web (distinctive), traffic keywords, windows, syslog
        if _RE_COMBINED.match(line):
            return self._parse_web(line, now)
        if re.search(r"\b(SRC|DST|src|dst)=", line):
            return self._parse_traffic(line, now)
        if re.search(r"EventID\s*=", line, re.I) or re.search(r"Level\s*=\s*\w+", line, re.I):
            return self._parse_windows(line, now)
        if line.startswith("<") and ">" in line[:6]:
            return self._parse_syslog(line, now)

        return self._unknown(line, now, reason="unrecognized_format")

    def _parse_syslog(self, line: str, now: datetime) -> NormalizedLogEvent:
        m = _RE_RFC5424.match(line)
        if m:
            ts = _parse_ts(m.group("ts"), now)
            return NormalizedLogEvent(
                timestamp=ts,
                source_type=LogSourceType.SYSLOG,
                severity=_syslog_severity_from_pri(m.group("pri")),
                hostname=m.group("host"),
                message=m.group("msg").strip() or line,
                raw=line,
                metadata={
                    "app_name": m.group("app"),
                    "procid": m.group("procid"),
                    "msgid": m.group("msgid"),
                    "structured_data": m.group("sd"),
                },
            )
        m = _RE_BSD_SYSLOG.match(line)
        if m:
            ts = _parse_ts(m.group("ts"), now)
            return NormalizedLogEvent(
                timestamp=ts,
                source_type=LogSourceType.SYSLOG,
                severity=_syslog_severity_from_pri(m.group("pri")),
                hostname=m.group("host"),
                facility=None,
                message=m.group("msg").strip(),
                raw=line,
                metadata={"tag": m.group("tag"), "priority": m.group("pri")},
            )
        return self._unknown(line, now, reason="syslog_parse_failed")

    def _parse_windows(self, line: str, now: datetime) -> NormalizedLogEvent:
        m = _RE_WIN_EVENT.match(line)
        if not m:
            return self._unknown(line, now, reason="windows_parse_failed")
        ts = _parse_ts(m.group("ts"), now)
        level = m.group("level")
        rest = (m.group("rest") or "").strip()
        return NormalizedLogEvent(
            timestamp=ts,
            source_type=LogSourceType.WINDOWS,
            severity=(level or "").lower() or None,
            hostname=m.group("computer"),
            event_code=m.group("eid"),
            message=rest or line,
            raw=line,
            metadata={"windows_source": m.group("source")},
        )

    def _parse_web(self, line: str, now: datetime) -> NormalizedLogEvent:
        m = _RE_COMBINED.match(line)
        if not m:
            return self._unknown(line, now, reason="web_parse_failed")
        ts = _parse_apache_ts(m.group("ts"), now)
        status_s = m.group("status")
        status = int(status_s) if status_s.isdigit() else None
        return NormalizedLogEvent(
            timestamp=ts,
            source_type=LogSourceType.WEB,
            source_ip=m.group("ip"),
            http_method=m.group("method"),
            http_status=status,
            url_path=m.group("path"),
            user=None if m.group("user") == "-" else m.group("user"),
            message=f"{m.group('method')} {m.group('path')} -> {status_s}",
            raw=line,
            metadata={"bytes": m.group("size")},
        )

    def _parse_traffic(self, line: str, now: datetime) -> NormalizedLogEvent:
        m = _RE_TRAFFIC.search(line)
        src = m.group("src") if m else None
        dst = m.group("dst") if m else None
        meta: dict[str, Any] = {
            "fingerprint": _sha256_short(line),
            "proto": _traffic_kv(line, "PROTO"),
            "lport": _traffic_kv(line, "LPORT"),
            "rport": _traffic_kv(line, "RPORT"),
            "conn_status": _traffic_kv(line, "STATUS"),
            "process_name": _traffic_kv(line, "PROC"),
            "risk_hint": _traffic_kv(line, "RISK_HINT"),
            "host_agent": _traffic_kv(line, "HOST_AGENT"),
            "ping_target": _traffic_kv(line, "TARGET"),
            "rtt_ms": _traffic_kv(line, "RTT_MS"),
        }
        meta = {k: v for k, v in meta.items() if v is not None}
        return NormalizedLogEvent(
            timestamp=now,
            source_type=LogSourceType.TRAFFIC,
            source_ip=src,
            destination_ip=dst,
            message=line[:500],
            raw=line,
            metadata=meta,
        )

    def _unknown(self, line: str, now: datetime, reason: str) -> NormalizedLogEvent:
        return NormalizedLogEvent(
            timestamp=now,
            source_type=LogSourceType.UNKNOWN,
            normalized=False,
            message=line[:2000] if line else "(empty)",
            raw=line,
            metadata={"parse_error": reason},
        )
