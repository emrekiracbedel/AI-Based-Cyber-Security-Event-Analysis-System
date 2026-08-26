"""
PyInstaller giriş noktası: paketlenmiş Mini-SIEM API (Uvicorn).
Geliştirmede: backend kökünden `python run_server.py`
"""

from __future__ import annotations

import multiprocessing
import os
import sys


def main() -> None:
    multiprocessing.freeze_support()
    if getattr(sys, "frozen", False):
        for stream in (sys.stdout, sys.stderr):
            if stream is not None and hasattr(stream, "reconfigure"):
                try:
                    stream.reconfigure(encoding="utf-8", errors="replace")
                except Exception:
                    pass

    port = int((os.environ.get("MINI_SIEM_PORT") or "8000").strip() or "8000")
    host = (os.environ.get("MINI_SIEM_HOST") or "127.0.0.1").strip() or "127.0.0.1"

    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        log_level="info",
        access_log=False,
        use_colors=False,
    )


if __name__ == "__main__":
    main()
