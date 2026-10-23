import { useState, useMemo } from "react";
import type { ScanRecord } from "../api/phishlens";
import {
  Clock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  Copy,
  Trash2,
  Check,
} from "lucide-react";
import { useToast } from "./useToast";

interface Props {
  scans: ScanRecord[];
  activeUrl?: string;
  onSelect: (scan: ScanRecord) => void;
  onClear?: () => void;
}

export function HistoryTable({ scans, activeUrl, onSelect, onClear }: Props) {
  const [searchQuery, setSearchQuery] = useState("");
  const [filterVerdict, setFilterVerdict] = useState<"all" | "safe" | "suspicious" | "dangerous">("all");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const toast = useToast();

  const filteredScans = useMemo(() => {
    return scans.filter((s) => {
      const matchesSearch =
        s.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (s.domain && s.domain.toLowerCase().includes(searchQuery.toLowerCase()));
      const matchesFilter = filterVerdict === "all" || s.label === filterVerdict;
      return matchesSearch && matchesFilter;
    });
  }, [scans, searchQuery, filterVerdict]);

  const handleCopyUrl = (e: React.MouseEvent, url: string, id: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(url).then(() => {
      setCopiedId(id);
      toast.success("Domain copied", url);
      setTimeout(() => setCopiedId(null), 2000);
    });
  };

  return (
    <div className="rounded-2xl border border-slate-200/90 bg-white shadow-card overflow-hidden">
      {/* Header with Search and Filter */}
      <div className="p-4 sm:p-5 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Clock size={16} className="text-slate-500" />
          <h3 className="text-sm font-semibold text-slate-900 tracking-tight">
            Scan History
          </h3>
          <span className="text-xs font-medium text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full">
            {scans.length}
          </span>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap">
          <div className="relative flex-1 sm:w-56">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" size={13} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter domains..."
              className="w-full bg-slate-50 border border-slate-200 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-600 focus:border-blue-600"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-xs">
            {(["all", "safe", "suspicious", "dangerous"] as const).map((v) => (
              <button
                key={v}
                onClick={() => setFilterVerdict(v)}
                className={`px-2 py-1 rounded-md capitalize font-medium transition-colors ${
                  filterVerdict === v
                    ? "bg-white text-slate-900 shadow-sm"
                    : "text-slate-500 hover:text-slate-800"
                }`}
              >
                {v}
              </button>
            ))}
          </div>

          {onClear && scans.length > 0 && (
            <button
              onClick={onClear}
              title="Clear current scan list"
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-slate-100 transition-colors"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Table Content */}
      {filteredScans.length === 0 ? (
        <div className="p-8 text-center text-xs text-slate-500">
          {scans.length === 0
            ? "No analysis sessions recorded yet. Enter a website address above to initiate an evaluation."
            : "No records match your filter criteria."}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50/75 border-b border-slate-100 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
              <tr>
                <th className="px-5 py-3">Analyzed Website</th>
                <th className="px-4 py-3 text-center">Score</th>
                <th className="px-4 py-3 text-center">Classification</th>
                <th className="px-4 py-3">Origin</th>
                <th className="px-5 py-3 text-right">Timestamp</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {filteredScans.map((scan) => {
                const isSelected = activeUrl === scan.url;
                const isDangerous = scan.label === "dangerous";
                const isSuspicious = scan.label === "suspicious";

                return (
                  <tr
                    key={scan.id}
                    onClick={() => onSelect(scan)}
                    className={`group cursor-pointer transition-colors ${
                      isSelected
                        ? "bg-blue-50/60 font-medium"
                        : "hover:bg-slate-50/80"
                    }`}
                  >
                    <td className="px-5 py-3 max-w-[280px]">
                      <div className="flex items-center gap-2">
                        <span
                          className={`w-2 h-2 rounded-full shrink-0 ${
                            isDangerous
                              ? "bg-rose-500"
                              : isSuspicious
                              ? "bg-amber-500"
                              : "bg-emerald-500"
                          }`}
                        />
                        <span className="truncate text-slate-900 group-hover:text-blue-600 transition-colors">
                          {scan.domain || scan.url}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-400 truncate block mt-0.5">
                        {scan.url}
                      </span>
                    </td>

                    <td className="px-4 py-3 text-center font-mono font-semibold">
                      <span
                        className={
                          isDangerous
                            ? "text-rose-600 font-bold"
                            : isSuspicious
                            ? "text-amber-600 font-bold"
                            : "text-emerald-600"
                        }
                      >
                        {scan.risk_score}
                      </span>
                    </td>

                    <td className="px-4 py-3 text-center">
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${
                          isDangerous
                            ? "bg-rose-50 text-rose-700 border-rose-200"
                            : isSuspicious
                            ? "bg-amber-50 text-amber-700 border-amber-200"
                            : "bg-emerald-50 text-emerald-700 border-emerald-200"
                        }`}
                      >
                        {isDangerous && <ShieldAlert size={10} />}
                        {isSuspicious && <AlertTriangle size={10} />}
                        {!isDangerous && !isSuspicious && <ShieldCheck size={10} />}
                        <span className="capitalize">{scan.label}</span>
                      </span>
                    </td>

                    <td className="px-4 py-3 text-[11px] text-slate-500">
                      <span className="capitalize px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono text-[10px]">
                        {scan.source_origin}
                      </span>
                    </td>

                    <td className="px-5 py-3 text-right text-[11px] text-slate-500 font-mono">
                      {scan.timestamp ? new Date(scan.timestamp).toLocaleTimeString() : "Live"}
                    </td>

                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={(e) => handleCopyUrl(e, scan.url, scan.id)}
                        title="Copy domain URL"
                        className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition-colors inline-flex items-center"
                      >
                        {copiedId === scan.id ? (
                          <Check size={13} className="text-emerald-600" />
                        ) : (
                          <Copy size={13} />
                        )}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
