import { useEffect, useState } from "react";
import {
  LLM_STORAGE_GEMINI,
  LLM_STORAGE_OPENAI,
  readLlmKeys,
} from "../api";

function KeyIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  );
}

export function ApiKeysPanel({ onKeysChanged }: { onKeysChanged: () => void }) {
  const [manageOpen, setManageOpen] = useState(false);
  const [openai, setOpenai] = useState("");
  const [gemini, setGemini] = useState("");

  useEffect(() => {
    if (!manageOpen) return;
    const k = readLlmKeys();
    setOpenai(k.openai);
    setGemini(k.gemini);
  }, [manageOpen]);

  useEffect(() => {
    if (!manageOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setManageOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [manageOpen]);

  const save = () => {
    const o = openai.trim();
    const g = gemini.trim();
    if (o) localStorage.setItem(LLM_STORAGE_OPENAI, o);
    else localStorage.removeItem(LLM_STORAGE_OPENAI);
    if (g) localStorage.setItem(LLM_STORAGE_GEMINI, g);
    else localStorage.removeItem(LLM_STORAGE_GEMINI);
    setManageOpen(false);
    onKeysChanged();
  };

  const clearAll = () => {
    localStorage.removeItem(LLM_STORAGE_OPENAI);
    localStorage.removeItem(LLM_STORAGE_GEMINI);
    setOpenai("");
    setGemini("");
    onKeysChanged();
  };

  return (
    <>
      <div className="flex items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3">
        <div className="flex min-w-0 items-start gap-3">
          <div className="mt-0.5 shrink-0 rounded-lg bg-slate-900 p-2 ring-1 ring-slate-800">
            <KeyIcon className="h-5 w-5 text-cyan-400" />
          </div>
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-white">API keys</h2>
            <p className="text-xs text-slate-500">
              OpenAI / Gemini keys for AI alert explanations (saved on this
              device)
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setManageOpen(true)}
          className="shrink-0 rounded-lg border border-slate-600 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-100 transition hover:border-slate-500 hover:bg-slate-800"
        >
          Manage
        </button>
      </div>

      {manageOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
          role="presentation"
          onClick={() => setManageOpen(false)}
        >
          <div
            role="dialog"
            aria-labelledby="api-keys-title"
            className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-950 p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3
              id="api-keys-title"
              className="text-base font-semibold text-white"
            >
              Manage API keys
            </h3>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">
              Keys are kept in local storage and sent only to your Mini-SIEM API
              (e.g. <code className="text-slate-400">/api/health</code>, explain)
              as <code className="text-slate-400">X-MiniSiem-Llm-*</code> headers.
              If both are set, OpenAI is used unless the server sets{" "}
              <code className="text-slate-400">LLM_PROVIDER=gemini</code>.
            </p>

            <label className="mt-4 block text-xs font-medium text-slate-400">
              OpenAI API key
              <input
                type="password"
                autoComplete="off"
                value={openai}
                onChange={(e) => setOpenai(e.target.value)}
                placeholder="sk-…"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-700 focus:outline-none focus:ring-1 focus:ring-cyan-700"
              />
            </label>

            <label className="mt-3 block text-xs font-medium text-slate-400">
              Gemini API key
              <input
                type="password"
                autoComplete="off"
                value={gemini}
                onChange={(e) => setGemini(e.target.value)}
                placeholder="AIza…"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-700 focus:outline-none focus:ring-1 focus:ring-cyan-700"
              />
            </label>

            <div className="mt-5 flex flex-wrap items-center justify-end gap-2">
              <button
                type="button"
                onClick={clearAll}
                className="rounded-lg px-3 py-2 text-xs font-medium text-slate-400 hover:bg-slate-900 hover:text-slate-200"
              >
                Clear saved
              </button>
              <button
                type="button"
                onClick={() => setManageOpen(false)}
                className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-900"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={save}
                className="rounded-lg bg-cyan-700 px-3 py-2 text-xs font-semibold text-white hover:bg-cyan-600"
              >
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
