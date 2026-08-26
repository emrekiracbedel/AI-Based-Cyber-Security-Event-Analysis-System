"""Environment-driven settings (MongoDB, LLM, paths)."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _backend_root() -> Path:
    """PyInstaller: veri dosyaları sys._MEIPASS altında; geliştirmede backend kökü."""
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


BACKEND_ROOT = _backend_root()


def get_llm_provider() -> str:
    """openai | gemini — explicit LLM_PROVIDER veya sadece GEMINI_API_KEY tanımlıysa gemini."""
    explicit = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if explicit in ("openai", "gemini"):
        return explicit
    g = (os.environ.get("GEMINI_API_KEY") or "").strip()
    o = (os.environ.get("OPENAI_API_KEY") or "").strip()
    if g and not o:
        return "gemini"
    return "openai"


def llm_is_configured() -> bool:
    if get_llm_provider() == "gemini":
        return bool((os.environ.get("GEMINI_API_KEY") or "").strip())
    return bool((os.environ.get("OPENAI_API_KEY") or "").strip())


def resolve_llm_for_request(
    openai_header: str | None,
    gemini_header: str | None,
) -> tuple[str, str | None]:
    """İstemciden gelen başlıklar, sunucu env'ini bu istek için geçersiz kılabilir.

    Dönüş: (provider \"openai\" | \"gemini\", api_key veya None).
    """
    o = (openai_header or "").strip()
    g = (gemini_header or "").strip()
    explicit = os.environ.get("LLM_PROVIDER", "").strip().lower()

    if explicit == "gemini":
        key = g or (settings.gemini_api_key or "").strip()
        return ("gemini", key or None)
    if explicit == "openai":
        key = o or (settings.openai_api_key or "").strip()
        return ("openai", key or None)

    if o and not g:
        return ("openai", o)
    if g and not o:
        return ("gemini", g)
    if o and g:
        return ("openai", o)

    prov = get_llm_provider()
    if prov == "gemini":
        return ("gemini", (settings.gemini_api_key or "").strip() or None)
    return ("openai", (settings.openai_api_key or "").strip() or None)


def llm_is_configured_for_request(
    openai_header: str | None,
    gemini_header: str | None,
) -> bool:
    return bool(resolve_llm_for_request(openai_header, gemini_header)[1])


def effective_llm_provider_for_request(
    openai_header: str | None,
    gemini_header: str | None,
) -> str:
    prov, key = resolve_llm_for_request(openai_header, gemini_header)
    if key:
        return prov
    return get_llm_provider()


class Settings:
    mongodb_uri: str = os.environ.get("MONGODB_URI", "mongodb://127.0.0.1:27017")
    mongodb_db: str = os.environ.get("MONGODB_DB", "mini_siem")
    openai_api_key: str | None = os.environ.get("OPENAI_API_KEY")
    gemini_api_key: str | None = os.environ.get("GEMINI_API_KEY")
    openai_base_url: str = os.environ.get(
        "OPENAI_BASE_URL", "https://api.openai.com/v1"
    ).rstrip("/")
    llm_model: str = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    # Gemini REST: v1 (stabil) veya v1beta — model adı hesabında ListModels ile doğrulanmalı
    gemini_api_version: str = os.environ.get("GEMINI_API_VERSION", "v1").strip().lstrip("/")
    # Yeni API anahtarlarında gemini-2.0-flash kapalı olabiliyor; güncel Flash:
    gemini_model: str = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    sigma_rules_path: Path = Path(
        os.environ.get("SIGMA_RULES_PATH", str(BACKEND_ROOT / "rules" / "sigma_rules.yml"))
    )
    iforest_model_path: Path = Path(
        os.environ.get(
            "IFOREST_MODEL_PATH", str(BACKEND_ROOT / "models" / "iforest.joblib")
        )
    )
    # Varsayılan kapalı: sadece /api/ingest/* ve Mongo’daki geçmiş (hydrate) veriyi gösterir.
    enable_demo_simulation: bool = (
        os.environ.get("ENABLE_DEMO_SIMULATION", "false").lower() in ("1", "true", "yes")
    )

    # DDoS: sliding window (ms) + burst (same ms) + sustained RPS-style thresholds
    ddos_window_ms: int = int(os.environ.get("DDOS_WINDOW_MS", "1000"))
    ddos_burst_max_same_ms: int = int(os.environ.get("DDOS_BURST_MAX_SAME_MS", "80"))
    ddos_rps_high: int = int(os.environ.get("DDOS_RPS_HIGH", "300"))
    ddos_rps_medium: int = int(os.environ.get("DDOS_RPS_MEDIUM", "100"))


settings = Settings()
