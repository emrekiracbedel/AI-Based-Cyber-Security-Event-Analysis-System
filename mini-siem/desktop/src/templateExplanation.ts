import type { SecurityAlertRow } from "./api";

/** Instant SOC-style text (matches backend template_explanation). */
export function templateExplanationFromAlert(
  alert: SecurityAlertRow,
  showKeySetupHint = false
): string {
  const triage = String(alert.triage ?? "low").toUpperCase();
  const cat = String(alert.category ?? "");
  const parts = [
    `This alert is triaged as **${triage}** (category \`${cat}\`).`,
    `**What happened:** ${alert.detail ?? ""}`,
  ];
  const sip = alert.source_ip;
  const dip = alert.destination_ip;
  if (sip) {
    parts.push(
      `The activity involves source **${sip}**` +
        (dip ? ` toward **${dip}**.` : ".")
    );
  }
  if (cat.startsWith("sigma:") || (alert.matched_rules?.length ?? 0) > 0) {
    parts.push(
      "**Why flagged:** A Sigma-style signature matched fields in the normalized " +
        "log (pattern / keyword / regex in the rule pack)."
    );
  } else if (cat === "ddos_rate") {
    parts.push(
      "**Why flagged:** Traffic-rate heuristics (burst and/or sliding window) " +
        "exceeded configured thresholds (possible volumetric DoS or aggressive automation)."
    );
  } else if (cat === "ml_anomaly") {
    parts.push(
      "**Why flagged:** The Isolation Forest model scored this event as an outlier " +
        "relative to engineered features (time, length, template hash bucket, log source)."
    );
  } else if (cat === "auth_failure") {
    parts.push(
      "**Why flagged:** Repeated authentication failures may indicate guessing or " +
        "misconfiguration; correlate with other hosts and identity sources."
    );
  } else {
    parts.push(
      "**Why flagged:** Behavioral or signature deviation from baseline; validate " +
        "against WAF, firewall, and auth telemetry."
    );
  }
  if (alert.raw_hint) {
    parts.push(`**Engine context:** ${alert.raw_hint}`);
  }
  if (showKeySetupHint) {
    parts.push(
      "_LLM için: masaüstünde **API keys → Manage** ile anahtar girin veya sunucuda " +
        "`OPENAI_API_KEY` / `GEMINI_API_KEY` ortam değişkenlerini kullanın._"
    );
  }
  return parts.join("\n\n");
}
