import { useMemo, useRef, useState } from "react";
import type { HeatmapCell } from "../api";

const TOP_FLOWS = 8;
const MATRIX_SIZE = 7;

function shortenIp(ip: string, max = 16): string {
  if (ip.length <= max) return ip;
  return `${ip.slice(0, max - 1)}…`;
}

function heatColor(t: number): string {
  if (t <= 0) return "rgba(15, 23, 42, 0.9)";
  const hue = 192 - t * 42;
  const sat = 55 + t * 35;
  const light = 18 + t * 38;
  return `hsla(${hue}, ${sat}%, ${light}%, ${0.35 + t * 0.65})`;
}

function stableTopIps(
  prev: string[],
  totals: Map<string, number>,
  limit: number
): string[] {
  const ranked = [...totals.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([ip]) => ip);
  const next: string[] = [];
  for (const ip of prev) {
    if (totals.has(ip) && next.length < limit) next.push(ip);
  }
  for (const ip of ranked) {
    if (!next.includes(ip) && next.length < limit) next.push(ip);
  }
  return next.slice(0, limit);
}

function rankStyle(i: number): string {
  if (i === 0) return "from-amber-400/90 to-orange-500 text-amber-950";
  if (i === 1) return "from-slate-300/90 to-slate-400 text-slate-900";
  if (i === 2) return "from-amber-700/80 to-amber-900 text-amber-100";
  return "from-slate-700 to-slate-800 text-slate-300";
}

export function TrafficHeatmap({ cells }: { cells: HeatmapCell[] }) {
  const stableSrcRef = useRef<string[]>([]);
  const stableDstRef = useRef<string[]>([]);
  const [hovered, setHovered] = useState<{
    src: string;
    dst: string;
  } | null>(null);

  const {
    topFlows,
    matrix,
    srcLabels,
    dstLabels,
    maxCount,
    stats,
    matrixMax,
  } = useMemo(() => {
    const srcTotals = new Map<string, number>();
    const dstTotals = new Map<string, number>();
    let totalEvents = 0;
    const uniqueIps = new Set<string>();

    for (const c of cells) {
      totalEvents += c.count;
      uniqueIps.add(c.src_ip);
      uniqueIps.add(c.dst_ip);
      srcTotals.set(c.src_ip, (srcTotals.get(c.src_ip) ?? 0) + c.count);
      dstTotals.set(c.dst_ip, (dstTotals.get(c.dst_ip) ?? 0) + c.count);
    }

    stableSrcRef.current = stableTopIps(
      stableSrcRef.current,
      srcTotals,
      MATRIX_SIZE
    );
    stableDstRef.current = stableTopIps(
      stableDstRef.current,
      dstTotals,
      MATRIX_SIZE
    );
    const srcLabels = stableSrcRef.current;
    const dstLabels = stableDstRef.current;

    const pairMap = new Map<string, number>();
    for (const c of cells) {
      pairMap.set(`${c.src_ip}\0${c.dst_ip}`, c.count);
    }

    const topFlows = [...cells]
      .sort((a, b) => b.count - a.count)
      .slice(0, TOP_FLOWS);

    const maxCount = topFlows[0]?.count ?? 0;
    const peak = topFlows[0];

    const matrix: (number | null)[][] = srcLabels.map((src) =>
      dstLabels.map((dst) => {
        const v = pairMap.get(`${src}\0${dst}`);
        return v != null && v > 0 ? v : null;
      })
    );

    const matrixMax = matrix.reduce(
      (m, row) => Math.max(m, ...row.map((v) => v ?? 0)),
      0
    );

    return {
      topFlows,
      matrix,
      srcLabels,
      dstLabels,
      maxCount,
      matrixMax,
      stats: {
        totalEvents,
        pairCount: cells.length,
        uniqueIps: uniqueIps.size,
        peakLabel: peak
          ? `${shortenIp(peak.src_ip, 12)} → ${shortenIp(peak.dst_ip, 12)}`
          : "—",
        peakCount: peak?.count ?? 0,
      },
    };
  }, [cells]);

  if (cells.length === 0) {
    return (
      <div className="relative flex min-h-[280px] flex-col items-center justify-center overflow-hidden rounded-2xl border border-slate-800/80 bg-gradient-to-b from-slate-900/80 to-slate-950 px-6 py-12 text-center">
        <div
          className="pointer-events-none absolute inset-0 opacity-30"
          style={{
            backgroundImage:
              "radial-gradient(circle at 50% 0%, rgb(34, 211, 238) 0%, transparent 45%)",
          }}
        />
        <div className="relative mb-3 flex h-12 w-12 items-center justify-center rounded-full border border-slate-700 bg-slate-900">
          <svg
            className="h-6 w-6 text-slate-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5"
            />
          </svg>
        </div>
        <p className="relative text-sm font-medium text-slate-300">
          No flow samples yet
        </p>
        <p className="relative mt-2 max-w-md text-xs leading-relaxed text-slate-500">
          Enable demo mode, run the host agent, or POST to{" "}
          <code className="text-cyan-600/80">/api/ingest/flow</code>
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800/80 bg-gradient-to-br from-slate-900/90 via-slate-950 to-slate-950 shadow-lg shadow-black/20">
      {/* Stats strip */}
      <div className="grid grid-cols-2 gap-px border-b border-slate-800/80 bg-slate-800/50 sm:grid-cols-4">
        {[
          { label: "Total events", value: stats.totalEvents.toLocaleString() },
          { label: "Active pairs", value: String(stats.pairCount) },
          { label: "Unique IPs", value: String(stats.uniqueIps) },
          {
            label: "Busiest link",
            value: stats.peakLabel,
            sub: stats.peakCount ? `${stats.peakCount} evt` : undefined,
          },
        ].map((s) => (
          <div
            key={s.label}
            className="bg-slate-950/80 px-4 py-3 backdrop-blur-sm"
          >
            <p className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
              {s.label}
            </p>
            <p
              className="mt-0.5 truncate font-mono text-sm font-semibold text-slate-100"
              title={s.value}
            >
              {s.value}
            </p>
            {s.sub && (
              <p className="text-[10px] text-cyan-500/80">{s.sub}</p>
            )}
          </div>
        ))}
      </div>

      <div className="grid gap-0 lg:grid-cols-5">
        {/* Flow lanes */}
        <div className="border-b border-slate-800/60 p-4 lg:col-span-2 lg:border-b-0 lg:border-r">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Top flows
            </h3>
            <span className="rounded-full bg-slate-800/80 px-2 py-0.5 text-[10px] text-slate-500">
              live
            </span>
          </div>
          <ul className="space-y-2">
            {topFlows.map((row, i) => {
              const pct = maxCount > 0 ? (row.count / maxCount) * 100 : 0;
              const isHot =
                hovered?.src === row.src_ip && hovered?.dst === row.dst_ip;
              return (
                <li
                  key={`${row.src_ip}-${row.dst_ip}`}
                  className={
                    "group relative rounded-xl border px-3 py-2.5 transition-all duration-300 " +
                    (isHot
                      ? "border-cyan-500/50 bg-cyan-950/30 shadow-md shadow-cyan-900/20"
                      : "border-slate-800/60 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/70")
                  }
                  onMouseEnter={() =>
                    setHovered({ src: row.src_ip, dst: row.dst_ip })
                  }
                  onMouseLeave={() => setHovered(null)}
                >
                  <div className="mb-2 flex items-center gap-2">
                    <span
                      className={
                        "flex h-5 w-5 shrink-0 items-center justify-center rounded-md bg-gradient-to-br text-[10px] font-bold " +
                        rankStyle(i)
                      }
                    >
                      {i + 1}
                    </span>
                    <span
                      className="truncate rounded-md bg-cyan-950/50 px-2 py-0.5 font-mono text-[11px] text-cyan-200/90 ring-1 ring-cyan-800/40"
                      title={row.src_ip}
                    >
                      {shortenIp(row.src_ip)}
                    </span>
                    <svg
                      className="h-3 w-6 shrink-0 text-slate-600 group-hover:text-cyan-600/80"
                      viewBox="0 0 24 8"
                      fill="none"
                    >
                      <path
                        d="M0 4h18M14 1l5 3-5 3"
                        stroke="currentColor"
                        strokeWidth="1.2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                    <span
                      className="truncate rounded-md bg-slate-800/80 px-2 py-0.5 font-mono text-[11px] text-slate-300 ring-1 ring-slate-700/50"
                      title={row.dst_ip}
                    >
                      {shortenIp(row.dst_ip)}
                    </span>
                    <span className="ml-auto shrink-0 font-mono text-xs font-semibold tabular-nums text-white">
                      {row.count}
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-slate-800/80">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-cyan-600 via-cyan-400 to-teal-300 transition-[width] duration-700 ease-out"
                      style={{
                        width: `${pct}%`,
                        boxShadow:
                          pct > 15
                            ? "0 0 12px rgba(34, 211, 238, 0.35)"
                            : undefined,
                      }}
                    />
                  </div>
                </li>
              );
            })}
          </ul>
        </div>

        {/* Heat matrix */}
        <div className="p-4 lg:col-span-3">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Source × destination matrix
            </h3>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-600">low</span>
              <div
                className="h-2 w-24 rounded-full"
                style={{
                  background:
                    "linear-gradient(90deg, rgba(15,23,42,0.9), hsla(192,90%,48%,0.9))",
                }}
              />
              <span className="text-[10px] text-slate-600">high</span>
            </div>
          </div>

          {srcLabels.length === 0 || dstLabels.length === 0 ? (
            <p className="text-xs text-slate-500">Not enough distinct IPs yet.</p>
          ) : (
            <div className="overflow-x-auto pb-1">
              <div
                className="inline-grid gap-1"
                style={{
                  gridTemplateColumns: `minmax(72px, auto) repeat(${dstLabels.length}, 2rem)`,
                }}
              >
                <div className="h-8" />
                {dstLabels.map((dst) => (
                  <div
                    key={`h-${dst}`}
                    className={
                      "flex h-8 items-end justify-center truncate px-0.5 pb-1 text-center font-mono text-[9px] leading-tight " +
                      (hovered?.dst === dst
                        ? "text-cyan-300"
                        : "text-slate-500")
                    }
                    title={dst}
                  >
                    {shortenIp(dst, 9)}
                  </div>
                ))}

                {srcLabels.map((src, ri) => (
                  <div key={`row-${src}`} className="contents">
                    <div
                      className={
                        "flex items-center truncate pr-2 font-mono text-[10px] " +
                        (hovered?.src === src
                          ? "text-cyan-300"
                          : "text-slate-400")
                      }
                      title={src}
                    >
                      {shortenIp(src, 11)}
                    </div>
                    {matrix[ri].map((count, ci) => {
                      const dst = dstLabels[ci];
                      const t =
                        count != null && matrixMax > 0
                          ? count / matrixMax
                          : 0;
                      const active =
                        hovered?.src === src && hovered?.dst === dst;
                      const related =
                        hovered &&
                        (hovered.src === src || hovered.dst === dst);
                      return (
                        <div
                          key={`${src}-${dst}`}
                          className={
                            "flex h-8 w-8 items-center justify-center rounded-md text-[10px] font-mono tabular-nums transition-all duration-200 " +
                            (active
                              ? "z-10 scale-110 ring-2 ring-cyan-400 ring-offset-1 ring-offset-slate-950"
                              : related
                                ? "ring-1 ring-cyan-700/50"
                                : "")
                          }
                          style={{
                            backgroundColor: heatColor(t),
                            color:
                              t > 0.55
                                ? "#f0fdfa"
                                : t > 0.2
                                  ? "#a5f3fc"
                                  : "#475569",
                            opacity:
                              hovered && !related && !active ? 0.45 : 1,
                          }}
                          title={
                            count != null
                              ? `${src} → ${dst}: ${count} events`
                              : `${src} → ${dst}: no traffic`
                          }
                          onMouseEnter={() =>
                            setHovered({ src, dst })
                          }
                          onMouseLeave={() => setHovered(null)}
                        >
                          {count != null
                            ? count > 99
                              ? "99+"
                              : count
                            : ""}
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
          )}
          <p className="mt-3 text-[10px] leading-relaxed text-slate-600">
            Hover a flow or cell to highlight related IPs. Matrix axes stay fixed
            during live updates.
          </p>
        </div>
      </div>
    </div>
  );
}
