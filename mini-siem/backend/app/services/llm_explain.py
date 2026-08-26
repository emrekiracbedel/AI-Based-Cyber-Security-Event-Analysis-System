"""
LLM explainability: OpenAI Chat Completions or Google Gemini generateContent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from app.config import resolve_llm_for_request, settings


@dataclass
class LLMExplainResult:
    """text set on success; error set on failure (with optional HTTP/body detail)."""

    text: str | None = None
    error: str | None = None


def _alert_prompt(alert: dict[str, Any]) -> str:
    parts = [
        f"Title: {alert.get('title')}",
        f"Triage: {alert.get('triage')}",
        f"Category: {alert.get('category')}",
        f"Detail: {alert.get('detail')}",
        f"Source IP: {alert.get('source_ip')}",
        f"Destination IP: {alert.get('destination_ip')}",
        f"Matched rules: {alert.get('matched_rules')}",
        f"Anomaly score (engine): {alert.get('anomaly_score')}",
    ]
    return "\n".join(parts)


_SYSTEM = (
    "You are a senior SOC analyst. Write for a security operator. Tone: clear, factual, "
    "not alarmist.\n\n"
    "You MUST follow this exact markdown structure — use these four headings verbatim "
    "(including the ** bold markers):\n\n"
    "**Triage summary:** One short line (severity + category).\n\n"
    "**What happened:** 2–4 sentences describing the event in plain language.\n\n"
    "**Why flagged:** 2–4 sentences on why the detection fired and what risk it suggests.\n\n"
    "**What to verify next:** 2–5 short lines starting with \"- \" (actionable checks).\n\n"
    "Do not merge sections into one paragraph. Do not omit any heading."
)


def template_explanation(
    alert: dict[str, Any], *, show_key_setup_hint: bool = False
) -> str:
    """Deterministic SOC-style text. Optional footer only when no LLM key is configured."""
    triage = str(alert.get("triage", "low")).upper()
    cat = str(alert.get("category", ""))
    parts = [
        f"This alert is triaged as **{triage}** (category `{cat}`).",
        f"**What happened:** {alert.get('detail', '')}",
    ]
    sip = alert.get("source_ip")
    dip = alert.get("destination_ip")
    if sip:
        parts.append(
            f"The activity involves source **{sip}**"
            + (f" toward **{dip}**." if dip else ".")
        )
    if cat.startswith("sigma:") or (alert.get("matched_rules") or []):
        parts.append(
            "**Why flagged:** A Sigma-style signature matched fields in the normalized "
            "log (pattern / keyword / regex in the rule pack)."
        )
    elif cat == "ddos_rate":
        parts.append(
            "**Why flagged:** Traffic-rate heuristics (burst and/or sliding window) "
            "exceeded configured thresholds (possible volumetric DoS or aggressive automation)."
        )
    elif cat == "ml_anomaly":
        parts.append(
            "**Why flagged:** The Isolation Forest model scored this event as an outlier "
            "relative to engineered features (time, length, template hash bucket, log source)."
        )
    elif cat == "auth_failure":
        parts.append(
            "**Why flagged:** Repeated authentication failures may indicate guessing or "
            "misconfiguration; correlate with other hosts and identity sources."
        )
    else:
        parts.append(
            "**Why flagged:** Behavioral or signature deviation from baseline; validate "
            "against WAF, firewall, and auth telemetry."
        )
    rh = alert.get("raw_hint")
    if rh:
        parts.append(f"**Engine context:** {rh}")
    if show_key_setup_hint:
        parts.append(
            "_LLM için: masaüstünde **API keys → Manage** ile anahtar girin veya sunucuda "
            "`OPENAI_API_KEY` / `GEMINI_API_KEY` ortam değişkenlerini kullanın._"
        )
    return "\n\n".join(parts)


def _short_err(body: str, limit: int = 400) -> str:
    t = (body or "").strip().replace("\n", " ")
    return t[:limit] + ("…" if len(t) > limit else "")


async def _explain_openai(alert: dict[str, Any], *, api_key: str) -> LLMExplainResult:
    key = (api_key or "").strip()
    if not key:
        return LLMExplainResult(error="no_api_key")

    url = f"{settings.openai_base_url}/chat/completions"
    body = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _alert_prompt(alert)},
        ],
        "temperature": 0.3,
        "max_tokens": 1200,
    }
    headers = {"Authorization": f"Bearer {key}"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(url, json=body, headers=headers)
            if r.status_code >= 400:
                return LLMExplainResult(
                    error=f"HTTP {r.status_code}: {_short_err(r.text)}"
                )
            data = r.json()
            choices = data.get("choices") or []
            if not choices:
                return LLMExplainResult(
                    error=f"No choices in API response: {_short_err(str(data))}"
                )
            msg = choices[0].get("message") or {}
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                return LLMExplainResult(text=content.strip())
            return LLMExplainResult(error="Empty message content from API")
    except httpx.RequestError as e:
        return LLMExplainResult(error=f"Network error (proxy/firewall/DNS?): {e}")
    except Exception as e:
        return LLMExplainResult(error=f"Unexpected error: {e!s}"[:500])


async def _explain_gemini(alert: dict[str, Any], *, api_key: str) -> LLMExplainResult:
    key = (api_key or "").strip()
    if not key:
        return LLMExplainResult(error="no_api_key")

    model = (settings.gemini_model or "gemini-2.5-flash").strip()
    ver = (settings.gemini_api_version or "v1").strip().lstrip("/")
    # AI Studio API key: query ?key= (Google dokümantasyonu)
    url = (
        f"https://generativelanguage.googleapis.com/{ver}/"
        f"models/{model}:generateContent?key={quote(key, safe='')}"
    )
    # v1 generateContent JSON'da `systemInstruction` alanı yok (400: Unknown name).
    # Talimat + uyarıyı tek user turunda birleştir — v1 ve v1beta ile uyumlu.
    user_text = f"{_SYSTEM}\n\n--- Alert ---\n\n{_alert_prompt(alert)}"
    body: dict[str, Any] = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_text}],
            }
        ],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 1200,
        },
    }
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(url, json=body, headers={"Content-Type": "application/json"})
            if r.status_code >= 400:
                return LLMExplainResult(
                    error=f"HTTP {r.status_code}: {_short_err(r.text)}"
                )
            data = r.json()
            cands = data.get("candidates") or []
            if not cands:
                return LLMExplainResult(
                    error=f"No candidates: {_short_err(str(data))}"
                )
            c0 = cands[0]
            reason = c0.get("finishReason")
            if reason and reason not in ("STOP", "MAX_TOKENS"):
                return LLMExplainResult(
                    error=f"Gemini finishReason={reason}: {_short_err(str(c0))}"
                )
            content = c0.get("content") or {}
            parts = content.get("parts") or []
            if not parts:
                return LLMExplainResult(error="Empty Gemini content.parts")
            text = parts[0].get("text")
            if isinstance(text, str) and text.strip():
                return LLMExplainResult(text=text.strip())
            return LLMExplainResult(error="Empty text in Gemini response")
    except httpx.RequestError as e:
        return LLMExplainResult(error=f"Network error (proxy/firewall/DNS?): {e}")
    except Exception as e:
        return LLMExplainResult(error=f"Unexpected error: {e!s}"[:500])


async def explain_with_llm(
    alert: dict[str, Any],
    *,
    openai_header: str | None = None,
    gemini_header: str | None = None,
) -> LLMExplainResult:
    prov, key = resolve_llm_for_request(openai_header, gemini_header)
    if not key:
        return LLMExplainResult(error="no_api_key")
    if prov == "gemini":
        return await _explain_gemini(alert, api_key=key)
    return await _explain_openai(alert, api_key=key)
