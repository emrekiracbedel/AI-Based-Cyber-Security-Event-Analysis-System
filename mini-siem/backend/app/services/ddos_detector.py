"""
Hybrid DoS/DDoS detection:

1) Flash flood: aynı milisaniye diliminde çok yüksek istek sayısı (gerçek volumetric burst).
2) Sürekli yük: son N ms (varsayılan 1000 ms) içindeki toplam ağırlık → saniye başına eşdeğer hız (RPS).

Tek tek / seyrek istekler (ör. health ping, WebSocket saniyede 1 mesaj) high triage üretmez.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Callable, Deque


@dataclass
class DdosVerdict:
    source_ip: str
    flagged: bool
    triage: str  # none | medium | high
    reason: str
    burst_in_same_ms: int
    window_ms: int
    events_in_window: int
    approx_rps: float
    burst_threshold: int
    rps_high: int
    rps_medium: int
    label: str


@dataclass
class _IpState:
    """Recent (epoch_ms, weight) for sliding window + per-ms buckets for burst."""

    events: Deque[tuple[int, int]] = field(default_factory=deque)
    buckets: dict[int, int] = field(default_factory=dict)
    bucket_order: Deque[int] = field(default_factory=deque)


class DdosDetector:
    def __init__(
        self,
        *,
        window_ms: int = 1000,
        burst_max_same_ms: int = 80,
        rps_high: int = 300,
        rps_medium: int = 100,
        retention_ms: int = 120_000,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if window_ms < 50:
            raise ValueError("window_ms too small")
        if burst_max_same_ms < 1 or rps_high < 1 or rps_medium < 1:
            raise ValueError("thresholds must be positive")
        if rps_medium >= rps_high:
            raise ValueError("rps_medium must be < rps_high")
        self.window_ms = int(window_ms)
        self.burst_max_same_ms = int(burst_max_same_ms)
        self.rps_high = int(rps_high)
        self.rps_medium = int(rps_medium)
        self.retention_ms = int(retention_ms)
        self._clock = clock or time.time
        self._lock = Lock()
        self._by_ip: dict[str, _IpState] = defaultdict(_IpState)

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    def _prune_events(self, state: _IpState, cutoff_ms: int) -> None:
        while state.events and state.events[0][0] < cutoff_ms:
            state.events.popleft()

    def _prune_buckets(self, state: _IpState, cutoff_ms: int) -> None:
        while state.bucket_order and state.bucket_order[0] < cutoff_ms:
            old = state.bucket_order.popleft()
            state.buckets.pop(old, None)

    def observe(
        self,
        source_ip: str,
        *,
        at_epoch_ms: int | None = None,
        weight: int = 1,
    ) -> DdosVerdict:
        if not source_ip or not str(source_ip).strip():
            return self._empty_verdict("")

        ip = str(source_ip).strip()
        t_ms = at_epoch_ms if at_epoch_ms is not None else self._now_ms()
        w = max(1, int(weight))
        cutoff_win = t_ms - self.window_ms
        cutoff_ret = t_ms - self.retention_ms

        with self._lock:
            state = self._by_ip[ip]
            self._prune_events(state, cutoff_ret)
            self._prune_buckets(state, cutoff_ret)

            state.events.append((t_ms, w))
            self._prune_events(state, cutoff_win)

            in_window = sum(wt for _, wt in state.events)
            approx_rps = in_window * (1000.0 / float(self.window_ms))

            state.buckets[t_ms] = state.buckets.get(t_ms, 0) + w
            if not state.bucket_order or state.bucket_order[-1] != t_ms:
                state.bucket_order.append(t_ms)
            self._prune_buckets(state, cutoff_ret)
            burst = state.buckets.get(t_ms, 0)

            triage = "none"
            reason = "within_limits"
            if burst > self.burst_max_same_ms:
                triage = "high"
                reason = (
                    f"flash flood: {burst} weighted events in same ms "
                    f"(threshold {self.burst_max_same_ms}/ms)"
                )
            elif in_window > self.rps_high * (self.window_ms / 1000.0):
                triage = "high"
                reason = (
                    f"sustained high rate: ~{approx_rps:.0f} weighted events/s over "
                    f"{self.window_ms}ms (threshold {self.rps_high}/s)"
                )
            elif in_window > self.rps_medium * (self.window_ms / 1000.0):
                triage = "medium"
                reason = (
                    f"elevated rate: ~{approx_rps:.0f} weighted events/s over "
                    f"{self.window_ms}ms (threshold {self.rps_medium}/s)"
                )

            flagged = triage in ("medium", "high")
            label = "dos_suspect" if flagged else "legitimate"

        return DdosVerdict(
            source_ip=ip,
            flagged=flagged,
            triage=triage,
            reason=reason,
            burst_in_same_ms=burst,
            window_ms=self.window_ms,
            events_in_window=in_window,
            approx_rps=approx_rps,
            burst_threshold=self.burst_max_same_ms,
            rps_high=self.rps_high,
            rps_medium=self.rps_medium,
            label=label,
        )

    def _empty_verdict(self, ip: str) -> DdosVerdict:
        return DdosVerdict(
            source_ip=ip,
            flagged=False,
            triage="none",
            reason="missing_source_ip",
            burst_in_same_ms=0,
            window_ms=self.window_ms,
            events_in_window=0,
            approx_rps=0.0,
            burst_threshold=self.burst_max_same_ms,
            rps_high=self.rps_high,
            rps_medium=self.rps_medium,
            label="legitimate",
        )

    def reset(self) -> None:
        with self._lock:
            self._by_ip.clear()
