"""
High-volume heterogeneous log + DDoS-style flow simulation against a running API.

  1) Start backend:  uvicorn app.main:app --host 127.0.0.1 --port 8000
  2) Run:  python scripts/simulate_heterogeneous_logs.py

Uses httpx to POST /api/ingest/log and /api/ingest/flow.
"""

from __future__ import annotations

import argparse
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

SYSLOGS = [
    '<34>Oct 11 22:14:15 srv1 sshd: Failed password for invalid user admin from 203.0.113.10',
    '<38>Apr  4 10:01:02 fw kernel: DROP IN=eth0 SRC=198.51.100.9 DST=10.0.0.1',
]
WINDOWS = [
    "2026-04-04 10:05:00 Level=Error Source=Security EventID=4625 Computer=DC1 Message=logon failure",
    "2026-04-04 10:05:01 Level=Warning Source=App EventID=1000 Computer=WS1 Message=application crash",
]
WEB = [
    '10.0.0.5 - - [04/Apr/2026:10:10:00 +0000] "GET /api/health HTTP/1.1" 200 32',
    '10.0.0.6 - - [04/Apr/2026:10:10:01 +0000] "GET /wp-admin/setup.php HTTP/1.1" 404 120',
    '10.0.0.7 - - [04/Apr/2026:10:10:02 +0000] "GET /search?q=union%20select HTTP/1.1" 500 80',
]
TRAFFIC = [
    "SRC=10.0.0.12 DST=198.51.100.10 PROTO=TCP SPT=44312 DPT=443",
    "SRC=192.0.2.55 DST=198.51.100.10 PROTO=TCP SPT=40111 DPT=443",
]


def post_log(client: httpx.Client, base: str, raw: str) -> None:
    r = client.post(f"{base}/api/ingest/log", json={"raw": raw}, timeout=30.0)
    r.raise_for_status()


def post_burst_flow(client: httpx.Client, base: str) -> None:
    src = f"192.0.2.{random.randint(1, 220)}"
    dst = "198.51.100.10"
    t_ms = int(time.time() * 1000)
    for _ in range(12):
        r = client.post(
            f"{base}/api/ingest/flow",
            json={"src_ip": src, "dst_ip": dst, "weight": 1, "at_epoch_ms": t_ms},
            timeout=30.0,
        )
        r.raise_for_status()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--duration", type=float, default=15.0)
    p.add_argument("--workers", type=int, default=8)
    args = p.parse_args()
    base = args.base_url.rstrip("/")
    pool = SYSLOGS + WINDOWS + WEB + TRAFFIC
    deadline = time.time() + args.duration

    with httpx.Client() as client:
        while time.time() < deadline:
            futs = []
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                for _ in range(args.workers * 4):
                    line = random.choice(pool)
                    futs.append(ex.submit(post_log, client, base, line))
                if random.random() < 0.3:
                    futs.append(ex.submit(post_burst_flow, client, base))
                for fu in as_completed(futs):
                    try:
                        fu.result()
                    except Exception as e:
                        print("request error:", e)
            time.sleep(0.05)
    print("Simulation pass complete.")


if __name__ == "__main__":
    main()
