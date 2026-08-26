import { useEffect, useRef, useState } from "react";
import { fetchExplanation } from "../api";
import type { SecurityAlertRow } from "../api";
import { templateExplanationFromAlert } from "../templateExplanation";

function formatExplanation(text: string) {
  const segments = text.split(/(\*\*[^*]+\*\*)/g);
  return segments.map((part, i) => {
    const m = part.match(/^\*\*(.+)\*\*$/);
    if (m) {
      return (
        <strong key={i} className="font-semibold text-cyan-200">
          {m[1]}
        </strong>
      );
    }
    return <span key={i}>{part}</span>;
  });
}

export function AIInsightPanel({
  alert,
  llmKeysRevision = 0,
}: {
  alert: SecurityAlertRow | null;
  llmKeysRevision?: number;
}) {
  const [text, setText] = useState<string | null>(null);
  const [source, setSource] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const requestIdRef = useRef(0);

  useEffect(() => {
    if (!alert) {
      setText(null);
      setSource(null);
      setErr(null);
      setLoading(false);
      return;
    }

    const reqId = ++requestIdRef.current;
    setText(templateExplanationFromAlert(alert));
    setSource("local");
    setLoading(true);
    setErr(null);

    const abort = new AbortController();

    fetchExplanation(alert.id, abort.signal)
      .then((res) => {
        if (requestIdRef.current !== reqId) return;
        if (res.explanation?.trim()) {
          setText(res.explanation);
          setSource(res.source ?? null);
        }
      })
      .catch((e: unknown) => {
        if (requestIdRef.current !== reqId) return;
        if (e instanceof DOMException && e.name === "AbortError") return;
        const msg =
          e instanceof Error ? e.message : "Failed to load explanation";
        setErr(
          msg.includes("timeout") || msg.includes("aborted")
            ? "API did not respond in time — showing local summary below. Check that the backend is running on port 8000."
            : `${msg} — showing local summary below.`
        );
      })
      .finally(() => {
        if (requestIdRef.current === reqId) setLoading(false);
      });

    return () => {
      abort.abort();
    };
  }, [alert?.id, llmKeysRevision]);

  return (
    <div className="flex min-h-0 w-full flex-col rounded-xl border border-slate-800 bg-slate-900/40">
      <div className="border-b border-slate-800 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-100">AI insight</h2>
        <p className="text-xs text-slate-500">
          Local summary first · LLM or template from API when available
        </p>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-4 text-sm leading-relaxed text-slate-300">
        {!alert && (
          <p className="text-slate-500">
            Select an alert to fetch an explanation from the backend.
          </p>
        )}
        {alert && loading && (
          <p className="mb-3 text-[11px] text-slate-500">
            Fetching API explanation…
          </p>
        )}
        {alert && err && (
          <p className="mb-3 rounded-lg border border-amber-900/60 bg-amber-950/40 px-3 py-2 text-xs text-amber-200">
            {err}
          </p>
        )}
        {alert && text && (
          <div className="space-y-3">
            {source && (
              <p className="text-[11px] text-slate-500">
                Source:{" "}
                <span
                  className={
                    "rounded px-1.5 py-0.5 font-mono " +
                    (source === "llm"
                      ? "bg-emerald-950 text-emerald-300"
                      : source === "llm_error"
                        ? "bg-amber-950 text-amber-200"
                        : source === "local"
                          ? "bg-slate-800 text-slate-400"
                          : "bg-slate-800 text-slate-300")
                  }
                >
                  {source}
                </span>
              </p>
            )}
            <div className="space-y-3 whitespace-pre-wrap">
              {text.split("\n\n").map((para, idx) => (
                <p key={idx}>{formatExplanation(para)}</p>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
