import type { SecurityAlertRow } from "../api";

const triageStyles: Record<string, string> = {
  high: "bg-rose-500/20 text-rose-200 ring-1 ring-rose-500/40",
  medium: "bg-amber-500/20 text-amber-100 ring-1 ring-amber-500/35",
  low: "bg-emerald-500/15 text-emerald-100 ring-1 ring-emerald-500/30",
};

export function SecurityAlerts({
  alerts,
  selectedId,
  onSelect,
}: {
  alerts: SecurityAlertRow[];
  selectedId: string | null;
  onSelect: (a: SecurityAlertRow) => void;
}) {
  const rows = [...alerts].reverse();

  return (
    <div className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-800 bg-slate-900/40">
      <div className="border-b border-slate-800 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-100">
          Security alerts
        </h2>
        <p className="text-xs text-slate-500">
          Newest first · triage for SOC-style handling
        </p>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-950/95 backdrop-blur">
            <tr className="text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2 font-medium">Triage</th>
              <th className="px-4 py-2 font-medium">Title</th>
              <th className="px-4 py-2 font-medium">ML</th>
              <th className="px-4 py-2 font-medium">Source</th>
              <th className="px-4 py-2 font-medium">Dest</th>
              <th className="px-4 py-2 font-medium">Time</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-8 text-center text-slate-500"
                >
                  No alerts yet.
                </td>
              </tr>
            ) : (
              rows.map((a) => {
                const active = a.id === selectedId;
                const triage = (a.triage || "low").toLowerCase();
                const badge =
                  triageStyles[triage] ??
                  "bg-slate-700/40 text-slate-200 ring-1 ring-slate-600";
                return (
                  <tr
                    key={a.id}
                    onClick={() => onSelect(a)}
                    className={
                      "cursor-pointer border-t border-slate-800/80 transition-colors hover:bg-slate-800/50 " +
                      (active ? "bg-cyan-950/40" : "")
                    }
                  >
                    <td className="px-4 py-2">
                      <span
                        className={
                          "inline-block rounded-full px-2 py-0.5 text-[11px] font-medium capitalize " +
                          badge
                        }
                      >
                        {triage}
                      </span>
                    </td>
                    <td className="max-w-[200px] truncate px-4 py-2 text-slate-200">
                      {a.title}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-[11px] text-slate-500">
                      {typeof a.anomaly_score === "number"
                        ? a.anomaly_score.toFixed(3)
                        : "—"}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {a.source_ip ?? "—"}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {a.destination_ip ?? "—"}
                    </td>
                    <td className="whitespace-nowrap text-xs text-slate-500">
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
