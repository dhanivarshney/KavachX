import type { AnalysisResponse } from "../api/phishlens";
import { Clock, ExternalLink, ShieldCheck, ShieldAlert, AlertTriangle } from "lucide-react";

export interface HistoryEntry {
  url: string;
  result: AnalysisResponse;
  timestamp: string;
}

const LABEL_BADGES = {
  safe: {
    bg: "bg-emerald-100 text-emerald-800 border-emerald-200",
    icon: ShieldCheck,
  },
  suspicious: {
    bg: "bg-amber-100 text-amber-800 border-amber-200",
    icon: AlertTriangle,
  },
  dangerous: {
    bg: "bg-rose-100 text-rose-800 border-rose-200",
    icon: ShieldAlert,
  },
};

interface Props {
  entries: HistoryEntry[];
  onSelect: (url: string) => void;
  onClear: () => void;
}

export function HistoryTable({ entries, onSelect, onClear }: Props) {
  if (entries.length === 0) {
    return (
      <div className="bg-white rounded-2xl border border-slate-200 p-8 text-center">
        <p className="text-sm text-slate-400">No URL scans recorded yet. Enter any domain or URL above to begin real-time analysis.</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-100 bg-slate-50/50">
        <div className="flex items-center gap-2">
          <Clock size={15} className="text-slate-500" />
          <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
            Recent Scans ({entries.length})
          </span>
        </div>
        <button
          onClick={onClear}
          className="text-xs text-slate-400 hover:text-rose-600 transition-colors"
        >
          Clear History
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs text-left">
          <thead className="bg-slate-50/70 text-slate-500 uppercase text-[10px] tracking-wider border-b border-slate-100">
            <tr>
              <th className="px-5 py-3">Host / Domain</th>
              <th className="px-4 py-3 text-center">Risk Score</th>
              <th className="px-4 py-3 text-center">Verdict</th>
              <th className="px-4 py-3">Active Signals</th>
              <th className="px-4 py-3 text-right">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-slate-700">
            {entries.map((entry, idx) => {
              let domain = entry.url;
              try {
                domain = new URL(entry.url).hostname;
              } catch {
                domain = entry.url;
              }

              const badge = LABEL_BADGES[entry.result.label] || LABEL_BADGES.safe;
              const Icon = badge.icon;

              const activeSources = Object.entries(entry.result.sources)
                .filter(([, active]) => active)
                .map(([name]) => name)
                .join(", ");

              return (
                <tr
                  key={idx}
                  onClick={() => onSelect(entry.url)}
                  className="hover:bg-slate-50/80 cursor-pointer transition-colors group"
                >
                  <td className="px-5 py-3 font-medium text-slate-800 flex items-center gap-1.5 max-w-[260px] truncate">
                    <span className="truncate">{domain}</span>
                    <ExternalLink size={12} className="text-slate-300 group-hover:text-blue-500 shrink-0" />
                  </td>

                  <td className="px-4 py-3 text-center font-bold font-mono">
                    <span className={
                      entry.result.risk_score >= 70
                        ? "text-rose-600 font-extrabold"
                        : entry.result.risk_score >= 35
                        ? "text-amber-600 font-bold"
                        : "text-emerald-600"
                    }>
                      {entry.result.risk_score}
                    </span>
                  </td>

                  <td className="px-4 py-3 text-center">
                    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${badge.bg}`}>
                      <Icon size={11} />
                      {entry.result.label}
                    </span>
                  </td>

                  <td className="px-4 py-3 text-slate-500 font-mono text-[11px] max-w-[180px] truncate">
                    {activeSources || "heuristics"}
                  </td>

                  <td className="px-4 py-3 text-right text-slate-400 text-[11px]">
                    {new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
