# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller — onedir çıktı: dist/MiniSIEM-Backend/ (Electron extraResources ile kopyalanır)."""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all

block_cipher = None
ROOT = Path(SPECPATH)

datas = [
    (str(ROOT / "rules" / "sigma_rules.yml"), "rules"),
    (str(ROOT / "models" / "iforest.joblib"), "models"),
]
binaries = []
hiddenimports: list[str] = [
    "app",
    "app.main",
    "app.config",
    "app.dashboard_state",
    "app.db",
    "app.db.mongo_store",
    "app.services",
    "app.services.sigma_engine",
    "app.services.anomaly_detector",
    "app.services.log_template",
    "app.services.log_processor",
    "app.services.ddos_detector",
    "app.services.llm_explain",
]

for pkg in (
    "sklearn",
    "scipy",
    "joblib",
    "numpy",
    "uvicorn",
    "fastapi",
    "starlette",
    "pydantic",
    "anyio",
    "httpx",
    "httpcore",
    "h11",
    "pymongo",
    "bson",
    "dns",
    "yaml",
    "multipart",
    "websockets",
):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass

a = Analysis(
    [str(ROOT / "run_server.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "IPython"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MiniSIEM-Backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="MiniSIEM-Backend",
)
