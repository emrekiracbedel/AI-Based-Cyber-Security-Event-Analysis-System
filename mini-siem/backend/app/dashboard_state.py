"""
Dashboard state: heatmap, alerts, DDoS, log pipeline (normalize → Sigma → ML → Mongo).
"""

from __future__ import annotations

import asyncio
import random
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.db.mongo_store import insert_alert_doc, insert_log_doc
from app.services.anomaly_detector import get_anomaly_detector
from app.services.ddos_detector import DdosDetector
from app.services.log_processor import LogProcessor, LogSourceType
from app.services.log_template import extract_template, template_fingerprint
from app.services.sigma_engine import get_sigma_engine


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dedup_key_alert(alert: SecurityAlert) -> str:
    if alert.category == "ddos_rate":
        return f"ddos_rate:{alert.source_ip}:{alert.destination_ip}"
    return f"{alert.category}:{alert.source_ip}:{alert.detail[:80]}"


def _security_alert_from_mongo(doc: dict[str, Any]) -> SecurityAlert | None:
    try:
        aid = doc.get("id")
        if not aid:
            return None
        ts = doc.get("timestamp")
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()
        else:
            ts = str(ts or "")
        mr = doc.get("matched_rules")
        if mr is None:
            mr = []
        elif not isinstance(mr, list):
            mr = [mr]
        ascore = doc.get("anomaly_score")
        if ascore is not None:
            try:
                ascore = float(ascore)
            except (TypeError, ValueError):
                ascore = None
        return SecurityAlert(
            id=str(aid),
            title=str(doc.get("title", "")),
            triage=str(doc.get("triage", "medium")).lower(),
            source_ip=doc.get("source_ip"),
            destination_ip=doc.get("destination_ip"),
            timestamp=ts,
            detail=str(doc.get("detail", "")),
            category=str(doc.get("category", "")),
            raw_hint=str(doc.get("raw_hint", "")),
            matched_rules=[str(x) for x in mr],
            anomaly_score=ascore,
        )
    except (TypeError, ValueError, KeyError):
        return None


@dataclass
class SecurityAlert:
    id: str
    title: str
    triage: str
    source_ip: str | None
    destination_ip: str | None
    timestamp: str
    detail: str
    category: str
    raw_hint: str = ""
    matched_rules: list[str] = field(default_factory=list)
    anomaly_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "triage": self.triage,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "timestamp": self.timestamp,
            "detail": self.detail,
            "category": self.category,
            "raw_hint": self.raw_hint,
            "matched_rules": list(self.matched_rules),
            "anomaly_score": self.anomaly_score,
        }


class DashboardState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._heatmap: dict[tuple[str, str], int] = defaultdict(int)
        self._alerts: list[SecurityAlert] = []
        self._alert_by_id: dict[str, SecurityAlert] = {}
        self._ddos = DdosDetector(
            window_ms=settings.ddos_window_ms,
            burst_max_same_ms=settings.ddos_burst_max_same_ms,
            rps_high=settings.ddos_rps_high,
            rps_medium=settings.ddos_rps_medium,
            retention_ms=120_000,
        )
        self._seen_alert_keys: set[str] = set()
        self._tick = 0
        self._log_processor = LogProcessor()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            cells = [
                {"src_ip": s, "dst_ip": d, "count": c}
                for (s, d), c in sorted(
                    self._heatmap.items(), key=lambda x: -x[1]
                )[:200]
            ]
            alerts = [a.to_dict() for a in self._alerts[-500:]]
        return {
            "server_time": _utc_now_iso(),
            "heatmap": cells,
            "alerts": alerts,
        }

    def get_alert_dict(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            a = self._alert_by_id.get(alert_id)
            return a.to_dict() if a else None

    def _add_alert(self, alert: SecurityAlert) -> None:
        with self._lock:
            # DDoS: her ingest_flow farklı "observed N" metni üretir; aynı anahtarla tek uyarı
            key = _dedup_key_alert(alert)
            if key in self._seen_alert_keys:
                return
            self._seen_alert_keys.add(key)
            if len(self._seen_alert_keys) > 2000:
                self._seen_alert_keys.clear()
            self._alerts.append(alert)
            self._alert_by_id[alert.id] = alert
            if len(self._alerts) > 2000:
                drop = self._alerts[:-1500]
                for x in drop:
                    self._alert_by_id.pop(x.id, None)
                self._alerts = self._alerts[-1500:]
        doc = alert.to_dict()
        threading.Thread(
            target=insert_alert_doc,
            args=(doc,),
            daemon=True,
        ).start()

    def ingest_flow(
        self,
        src_ip: str,
        dst_ip: str,
        *,
        at_epoch_ms: int | None = None,
        weight: int = 1,
    ) -> None:
        verdict = self._ddos.observe(src_ip, at_epoch_ms=at_epoch_ms, weight=weight)
        with self._lock:
            self._heatmap[(src_ip, dst_ip)] += max(1, weight)

        if verdict.flagged and verdict.triage in ("medium", "high"):
            title = (
                "Possible DoS / flash or sustained high rate"
                if verdict.triage == "high"
                else "Elevated traffic rate (possible scan or load spike)"
            )
            self._add_alert(
                SecurityAlert(
                    id=str(uuid.uuid4()),
                    title=title,
                    triage=verdict.triage,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    timestamp=_utc_now_iso(),
                    detail=verdict.reason,
                    category="ddos_rate",
                    raw_hint=(
                        f"window_ms={verdict.window_ms} burst={verdict.burst_in_same_ms}/"
                        f"{verdict.burst_threshold} "
                        f"win_events={verdict.events_in_window} ~{verdict.approx_rps:.0f}/s "
                        f"(med<{verdict.rps_medium}/s high<{verdict.rps_high}/s)"
                    ),
                )
            )

    def ingest_raw_log(
        self,
        raw_line: str,
        *,
        source_hint: LogSourceType | None = None,
    ) -> dict[str, Any]:
        event = self._log_processor.normalize(raw_line, source_hint=source_hint)
        tpl = extract_template(event.message)
        fp = template_fingerprint(tpl)
        d: dict[str, Any] = event.model_dump_json_safe()
        d["log_template"] = tpl
        d["template_fingerprint"] = fp

        ar = get_anomaly_detector().predict(d)
        d["anomaly_engine"] = {
            "anomaly_score": float(ar["anomaly_score"]),
            "is_anomaly": bool(ar["is_anomaly"]),
            "reason": str(ar["reason"]),
        }
        d["anomaly_score"] = float(ar["anomaly_score"])
        d["ml_anomaly"] = bool(ar["is_anomaly"])

        threading.Thread(target=insert_log_doc, args=(d,), daemon=True).start()

        matches = get_sigma_engine().evaluate(d)
        rule_ids = [m["id"] for m in matches]
        for m in matches:
            self._add_alert(
                SecurityAlert(
                    id=str(uuid.uuid4()),
                    title=str(m["title"]),
                    triage=str(m.get("level", "medium")).lower(),
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    timestamp=_utc_now_iso(),
                    detail=f"Sigma rule `{m['id']}` matched normalized fields.",
                    category=f"sigma:{m['id']}",
                    raw_hint=f"template_fp={fp}",
                    matched_rules=[str(m["id"])],
                    anomaly_score=float(ar["anomaly_score"]),
                )
            )

        if ar["is_anomaly"] and ar.get("reason") == "iforest":
            self._add_alert(
                SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="ML anomaly (Isolation Forest)",
                    triage="medium",
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    timestamp=_utc_now_iso(),
                    detail=(
                        f"Outlier score_sample={ar['anomaly_score']:.4f} on engineered features."
                    ),
                    category="ml_anomaly",
                    raw_hint=f"rules_evaluated={rule_ids} template_fp={fp}",
                    matched_rules=rule_ids,
                    anomaly_score=float(ar["anomaly_score"]),
                )
            )

        if event.source_type == LogSourceType.TRAFFIC and event.source_ip and event.destination_ip:
            self.ingest_flow(event.source_ip, event.destination_ip, weight=1)

        return d

    def simulate_tick(self) -> None:
        self._tick += 1
        bases = [
            ("10.0.0.12", "10.0.0.1"),
            ("10.0.0.15", "10.0.0.2"),
            ("203.0.113.5", "198.51.100.10"),
            ("198.51.100.7", "198.51.100.10"),
        ]
        for src, dst in bases:
            if random.random() < 0.7:
                self.ingest_flow(src, dst, weight=random.randint(1, 3))

        if random.random() < 0.25:
            samples = [
                '<38>Apr  4 12:00:01 host sshd: authentication failure; ruser= root',
                "2026-04-04 12:00:02 Level=Warning Source=Security EventID=4625 Computer=WIN1 Message=logon failure",
                '203.0.113.10 - - [04/Apr/2026:12:00:03 +0000] "GET /cgi-bin/../../etc/passwd HTTP/1.1" 404 120',
                'SRC=10.0.0.99 DST=198.51.100.10 PROTO=TCP SPT=4444 DPT=443',
            ]
            self.ingest_raw_log(random.choice(samples))

        if random.random() < 0.08:
            self._add_alert(
                SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="Windows security: failed logon",
                    triage="medium",
                    source_ip="192.0.2.50",
                    destination_ip=None,
                    timestamp=_utc_now_iso(),
                    detail="EventID 4625 — multiple failures for user svc_backup",
                    category="auth_failure",
                )
            )

        if random.random() < 0.07:
            self._add_alert(
                SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="Web server 4xx spike",
                    triage="low",
                    source_ip="203.0.113.88",
                    destination_ip="198.51.100.10",
                    timestamp=_utc_now_iso(),
                    detail="Elevated 404 responses on /admin",
                    category="web_anomaly",
                )
            )

        # Orta triage: ~1 sn içinde yüzlerce olay ama flash yok (RPS medium ile high arası)
        if self._tick % 70 == 0:
            med_src = "198.51.100.99"
            med_dst = "198.51.100.10"
            base = int(time.time() * 1000)
            for i in range(150):
                self.ingest_flow(med_src, med_dst, at_epoch_ms=base + i * 7, weight=1)

        # Nadir HIGH: aynı ms içinde burst (dedup ile kaynak başına tek satır uyarı)
        if self._tick % 120 == 0:
            burst_src = "203.0.113.200"
            dst = "198.51.100.10"
            t_ms = int(time.time() * 1000)
            for _ in range(settings.ddos_burst_max_same_ms + 25):
                self.ingest_flow(burst_src, dst, at_epoch_ms=t_ms, weight=1)


    def hydrate_from_mongo(self) -> dict[str, int]:
        """Mongo bağlıysa son uyarıları ve (src,dst) heatmap sayılarını RAM'e yükler."""
        from app.db.mongo_store import (
            aggregate_src_dst_counts_from_logs,
            list_recent_alerts_for_dashboard,
        )

        raw = list_recent_alerts_for_dashboard(500)
        flows = aggregate_src_dst_counts_from_logs(limit_docs=8000)

        loaded = 0
        with self._lock:
            for doc in reversed(raw):
                a = _security_alert_from_mongo(doc)
                if a is None:
                    continue
                key = _dedup_key_alert(a)
                if key in self._seen_alert_keys:
                    continue
                self._seen_alert_keys.add(key)
                self._alerts.append(a)
                self._alert_by_id[a.id] = a
                loaded += 1
            if len(self._alerts) > 2000:
                drop = self._alerts[:-1500]
                for x in drop:
                    self._alert_by_id.pop(x.id, None)
                self._alerts = self._alerts[-1500:]

            for (s, d), c in flows.items():
                self._heatmap[(s, d)] = c

        return {"alerts_hydrated": loaded, "heatmap_pairs": len(flows)}


_dashboard: DashboardState | None = None


def get_dashboard() -> DashboardState:
    global _dashboard
    if _dashboard is None:
        _dashboard = DashboardState()
    return _dashboard


async def simulation_loop() -> None:
    dash = get_dashboard()
    while True:
        await asyncio.to_thread(dash.simulate_tick)
        await asyncio.sleep(1.0)
