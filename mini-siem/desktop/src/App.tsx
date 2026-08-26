import { useEffect, useState } from "react";
import {
  type DashboardSnapshot,
  type HealthStatus,
  type SecurityAlertRow,
  WS_DASHBOARD_URL,
  fetchHealth,
  fetchSnapshot,
} from "./api";
import { AIInsightPanel } from "./components/AIInsightPanel";
import { ApiKeysPanel } from "./components/ApiKeysPanel";
import { SecurityAlerts } from "./components/SecurityAlerts";
import { TrafficHeatmap } from "./components/TrafficHeatmap";

export default function App() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [wsState, setWsState] = useState<"connecting" | "open" | "closed">(
    "connecting"
  );
  const [selected, setSelected] = useState<SecurityAlertRow | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [llmKeysRevision, setLlmKeysRevision] = useState(0);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
    const h = setInterval(() => {
      fetchHealth()
        .then(setHealth)
        .catch(() => setHealth(null));
    }, 15000);
    return () => clearInterval(h);
  }, []);

  useEffect(() => {
    fetchSnapshot()
      .then(setSnapshot)
      .catch(() => setSnapshot({ server_time: "", heatmap: [], alerts: [] }));
  }, []);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      if (cancelled) return;
      setWsState("connecting");
      ws = new WebSocket(WS_DASHBOARD_URL);
      ws.onopen = () => setWsState("open");
      ws.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data as string) as DashboardSnapshot;
          setSnapshot(data);
        } catch {
          /* ignore */
        }
      };
      ws.onerror = () => setWsState("closed");
      ws.onclose = () => {
        setWsState("closed");
        if (!cancelled) retryTimer = setTimeout(connect, 2000);
      };
    };

    connect();
    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
      ws?.close();
    };
  }, []);

  const heatmap = snapshot?.heatmap ?? [];
  const alerts = snapshot?.alerts ?? [];
  const serverTime = snapshot?.server_time;

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 py-4 backdrop-blur">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-white">
            Mini-SIEM Desktop
          </h1>
          <p className="text-xs text-slate-500">
            Electron · React · Tailwind · Recharts
          </p>
        </div>
        <div className="text-right text-xs text-slate-400">
          <div className="flex items-center justify-end gap-2">
            <span
              className={
                "inline-block h-2 w-2 rounded-full " +
                (wsState === "open"
                  ? "bg-emerald-400"
                  : wsState === "connecting"
                    ? "bg-amber-400"
                    : "bg-rose-500")
              }
            />
            <span>
              API stream:{" "}
              <span className="font-mono text-slate-300">{wsState}</span>
            </span>
          </div>
          {serverTime && (
            <p className="mt-1 font-mono text-[11px] text-slate-500">
              server {new Date(serverTime).toLocaleString()}
            </p>
          )}
          {health && (
            <p className="mt-2 max-w-md text-[11px] leading-relaxed text-slate-500">
              MongoDB:{" "}
              <span className={health.mongo.connected ? "text-emerald-400" : ""}>
                {health.mongo.connected ? "connected" : "offline"}
              </span>
              {" · "}
              Sigma rules:{" "}
              <span className="text-slate-400">{health.sigma_rules_loaded}</span>
              {" · "}
              ML model:{" "}
              <span
                className={
                  health.ml_model_loaded ? "text-emerald-400" : "text-amber-400"
                }
              >
                {health.ml_model_loaded ? "loaded" : "missing"}
              </span>
              {" · "}
              LLM:{" "}
              <span
                className={
                  health.llm_configured ? "text-emerald-400" : "text-slate-500"
                }
              >
                {health.llm_configured ? "API key set" : "template only"}
              </span>
              {health.llm_provider && (
                <>
                  {" · "}
                  <span className="font-mono text-slate-400">
                    {health.llm_provider}
                  </span>
                </>
              )}
            </p>
          )}
        </div>
      </header>

      <main className="flex flex-1 flex-col gap-4 p-4">
        <ApiKeysPanel
          onKeysChanged={() => {
            setLlmKeysRevision((n) => n + 1);
            fetchHealth()
              .then(setHealth)
              .catch(() => setHealth(null));
          }}
        />
        <section>
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
            Traffic heatmap
          </h2>
          <TrafficHeatmap cells={heatmap} />
        </section>

        <section className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-2">
          <SecurityAlerts
            alerts={alerts}
            selectedId={selected?.id ?? null}
            onSelect={(a) => setSelected(a)}
          />
          <AIInsightPanel alert={selected} llmKeysRevision={llmKeysRevision} />
        </section>
      </main>
    </div>
  );
}
