"""
Bu makinenin gerçek ağ bağlantılarını okuyup Mini-SIEM API'sine gönderir (sahte veri üretmez).

- TCP ESTABLISHED: yerel IP, uzak IP, portlar, süreç adı
- İsteğe bağlı: google.com için ICMP ping (Windows ping.exe)

Önkoşul: API çalışıyor (uvicorn veya paketlenmiş masaüstü). Yönetici olarak çalıştırmak
diğer kullanıcıların süreçlerine ait soketleri de görmeyi kolaylaştırır.

Kullanım:
  cd backend && .\\.venv\\Scripts\\activate
  pip install -r requirements.txt
  python scripts/host_network_agent.py
  python scripts/host_network_agent.py --api http://127.0.0.1:8000 --interval 2 --ping-every 30
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
import time
from typing import Any, Iterable

import httpx
import psutil

# Sık görülen riskli uzak portlar (heuristic; yanlış pozitif olabilir)
_ELEVATED_REMOTE_PORTS = frozenset({
    23,
    135,
    139,
    445,
    1433,
    3389,
    4444,
    5555,
    6667,
    8080,
    8443,
    1337,
})


def _local_ipv4() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.3)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "0.0.0.0"


def _conn_signature(c: Any) -> tuple:
    la = c.laddr
    ra = c.raddr
    if not ra:
        return ()
    lip = la.ip if la else ""
    rip = ra.ip if ra else ""
    lp = la.port if la else 0
    rp = ra.port if ra else 0
    return (c.type, c.status, lip, rip, lp, rp, c.pid or 0)


def _proc_name(pid: int | None) -> str:
    if not pid:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except (psutil.Error, OSError):
        return "unknown"


def _risk_hint(rport: int) -> str:
    if rport in _ELEVATED_REMOTE_PORTS:
        return "elevated"
    return "low"


def _iter_relevant_connections() -> Iterable[Any]:
    for c in psutil.net_connections(kind="inet"):
        if c.family != socket.AF_INET:
            continue
        if not c.raddr:
            continue
        rip = c.raddr.ip
        if rip.startswith("127.") or rip == "::1":
            continue
        if c.type == socket.SOCK_STREAM:
            if c.status != psutil.CONN_ESTABLISHED:
                continue
        elif c.type == socket.SOCK_DGRAM:
            # UDP: bazı süreçlerde raddr dolu olmayabilir; dolu olanları al
            pass
        else:
            continue
        yield c


def _build_line(local_ip: str, c: Any) -> str:
    la, ra = c.laddr, c.raddr
    lip = la.ip if la else local_ip
    lport = la.port if la else 0
    rip = ra.ip
    rport = ra.port
    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
    proc = _proc_name(c.pid)
    rh = _risk_hint(int(rport))
    return (
        f"SRC={lip} DST={rip} PROTO={proto} LPORT={lport} RPORT={rport} "
        f"STATUS={c.status} PROC={proc} HOST_AGENT=1 RISK_HINT={rh} "
        f"LOCAL_PUBLIC_HINT={local_ip}"
    )


def _ping_google_windows(local_ip: str) -> str | None:
    try:
        r = subprocess.run(
            ["ping", "-n", "1", "google.com"],
            capture_output=True,
            timeout=6,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        out = (r.stdout or "") + (r.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return None
    # Reply from 142.250.x.x: bytes=32 time=12ms TTL=116
    m = re.search(
        r"Reply from (?P<ip>[\d.]+).*?time[=<](?P<ms>\d+)\s*ms",
        out,
        re.I | re.DOTALL,
    )
    if not m:
        return None
    dst = m.group("ip")
    ms = m.group("ms")
    return (
        f"SRC={local_ip} DST={dst} PROTO=ICMP TARGET=google.com RTT_MS={ms} "
        f"STATUS=ECHO_REPLY PING=1 HOST_AGENT=1 RISK_HINT=low"
    )


def main() -> None:
    p = argparse.ArgumentParser(description="Mini-SIEM host network → /api/ingest/log")
    p.add_argument("--api", default="http://127.0.0.1:8000", help="API kök URL")
    p.add_argument("--interval", type=float, default=2.0, help="Tarama aralığı (sn)")
    p.add_argument(
        "--ping-every",
        type=float,
        default=0,
        help="0=kapalı; örn. 30 = ~30 sn'de bir google.com ping satırı gönder",
    )
    args = p.parse_args()
    base = args.api.rstrip("/")
    url = f"{base}/api/ingest/log"

    local_ip = _local_ipv4()
    seen: set[tuple] = set()
    last_ping_mono = 0.0

    print(f"Host agent → {url} (Ctrl+C çıkış)", file=sys.stderr)
    print(f"Yerel IPv4 (tahmini): {local_ip}", file=sys.stderr)

    with httpx.Client(timeout=10.0) as client:
        while True:
            t0 = time.monotonic()
            current: set[tuple] = set()
            try:
                for c in _iter_relevant_connections():
                    sig = _conn_signature(c)
                    if not sig:
                        continue
                    current.add(sig)
                    if sig in seen:
                        continue
                    line = _build_line(local_ip, c)
                    try:
                        r = client.post(
                            url,
                            json={"raw": line, "source_hint": "ip_traffic"},
                        )
                        if r.status_code >= 400:
                            print(f"ingest HTTP {r.status_code}: {r.text[:200]}", file=sys.stderr)
                    except httpx.RequestError as e:
                        print(f"ingest hata: {e}", file=sys.stderr)
            except psutil.AccessDenied:
                print(
                    "psutil: erişim reddedildi — mümkünse yönetici olarak çalıştırın.",
                    file=sys.stderr,
                )

            seen = current
            now_m = time.monotonic()
            if args.ping_every > 0 and now_m - last_ping_mono >= args.ping_every:
                last_ping_mono = now_m
                pline = _ping_google_windows(local_ip)
                if pline:
                    try:
                        client.post(
                            url,
                            json={"raw": pline, "source_hint": "ip_traffic"},
                        )
                    except httpx.RequestError as e:
                        print(f"ping ingest: {e}", file=sys.stderr)

            elapsed = time.monotonic() - t0
            sleep_for = max(0.1, args.interval - elapsed)
            time.sleep(sleep_for)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
