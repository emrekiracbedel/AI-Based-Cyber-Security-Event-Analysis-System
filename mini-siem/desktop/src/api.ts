function resolveApiBase(): string {
  if (import.meta.env.VITE_API_BASE) {
    return String(import.meta.env.VITE_API_BASE);
  }
  // Dev: Vite proxy → same origin, avoids CORS from :5173 → :8000
  if (import.meta.env.DEV) return "";
  return "http://127.0.0.1:8000";
}

export const API_BASE = resolveApiBase();

function resolveWsDashboardUrl(): string {
  if (import.meta.env.VITE_WS_DASHBOARD_URL) {
    return String(import.meta.env.VITE_WS_DASHBOARD_URL);
  }
  if (import.meta.env.DEV && typeof window !== "undefined") {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}/ws/dashboard`;
  }
  const wsHost = (API_BASE || "http://127.0.0.1:8000").replace(/^http/, "ws");
  return `${wsHost}/ws/dashboard`;
}

/** localStorage — LLM isteklerinde `X-MiniSiem-Llm-*` başlıklarına gider */
export const LLM_STORAGE_OPENAI = "minisiem_llm_openai";
export const LLM_STORAGE_GEMINI = "minisiem_llm_gemini";

export function readLlmKeys(): { openai: string; gemini: string } {
  if (typeof localStorage === "undefined") {
    return { openai: "", gemini: "" };
  }
  return {
    openai: localStorage.getItem(LLM_STORAGE_OPENAI) ?? "",
    gemini: localStorage.getItem(LLM_STORAGE_GEMINI) ?? "",
  };
}

export function llmHeaders(): Record<string, string> {
  const { openai, gemini } = readLlmKeys();
  const h: Record<string, string> = {};
  const o = openai.trim();
  const g = gemini.trim();
  if (o) h["X-MiniSiem-Llm-OpenAI"] = o;
  if (g) h["X-MiniSiem-Llm-Gemini"] = g;
  return h;
}

export const WS_DASHBOARD_URL = resolveWsDashboardUrl();

export type HeatmapCell = {
  src_ip: string;
  dst_ip: string;
  count: number;
};

export type SecurityAlertRow = {
  id: string;
  title: string;
  triage: "low" | "medium" | "high" | string;
  source_ip: string | null;
  destination_ip: string | null;
  timestamp: string;
  detail: string;
  category: string;
  raw_hint?: string;
  matched_rules?: string[];
  anomaly_score?: number | null;
};

export type HealthStatus = {
  status: string;
  mongo: { connected: boolean; db?: string; error?: string };
  sigma_rules_loaded: number;
  ml_model_loaded: boolean;
  llm_configured: boolean;
  llm_provider?: string;
  demo_simulation: boolean;
};

export type ExplainResult = {
  explanation: string;
  source: "llm" | "template" | "llm_error" | "none" | string;
};

export type DashboardSnapshot = {
  server_time: string;
  heatmap: HeatmapCell[];
  alerts: SecurityAlertRow[];
};

export async function fetchSnapshot(): Promise<DashboardSnapshot> {
  const r = await fetch(`${API_BASE}/api/snapshot`);
  if (!r.ok) throw new Error(`snapshot ${r.status}`);
  return r.json() as Promise<DashboardSnapshot>;
}

const EXPLAIN_TIMEOUT_MS = 25_000;

export async function fetchExplanation(
  alertId: string,
  signal?: AbortSignal
): Promise<ExplainResult> {
  const timeout = AbortSignal.timeout(EXPLAIN_TIMEOUT_MS);
  const combined =
    signal != null
      ? AbortSignal.any([signal, timeout])
      : timeout;
  const r = await fetch(
    `${API_BASE}/api/alerts/${encodeURIComponent(alertId)}/explain`,
    { headers: llmHeaders(), signal: combined }
  );
  if (!r.ok) throw new Error(`explain ${r.status}`);
  return r.json() as Promise<ExplainResult>;
}

export async function fetchHealth(): Promise<HealthStatus> {
  const r = await fetch(`${API_BASE}/api/health`, { headers: llmHeaders() });
  if (!r.ok) throw new Error(`health ${r.status}`);
  return r.json() as Promise<HealthStatus>;
}
