import { useState, useEffect } from "react";
import { RefreshCw, Activity, ShieldCheck } from "lucide-react";
import { getDiagnostics } from "../api/phishlens";
import type { DiagnosticsResponse } from "../api/phishlens";
import { PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, ResponsiveContainer } from "recharts";

const PIE_COLORS: Record<string, string> = {
  safe: "#10b981",
  suspicious: "#f59e0b",
  dangerous: "#f43f5e",
};

const SHIELD_NAMES: Record<string, string> = {
  threat_intel_enabled: "Known Scam Database",
  tls_analysis_enabled: "Security Lock (SSL)",
  ct_log_lookup_enabled: "Certificate Legitimacy",
  domain_age_lookup_enabled: "Website Age Check",
  ml_model_available: "AI Pattern Matcher",
  rate_limiting_enabled: "High-Traffic Protection",
  diagnostics_enabled: "Live Safety Monitoring",
  demo_threat_source_enabled: "Demo Simulation",
};

export default function Stats() {
  const [diag, setDiag] = useState<DiagnosticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  async function refreshData() {
    setLoading(true);
    try {
      const d = await getDiagnostics().catch(() => null);
      setDiag(d);
      setLastRefreshed(new Date());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 10000);
    return () => clearInterval(interval);
  }, []);

  const labelData = diag
    ? Object.entries(diag.labels).map(([name, value]) => ({ name, value }))
    : [];

  const sourceData = diag
    ? Object.entries(diag.sources).map(([name, value]) => ({ name, value }))
    : [];

  const totalScans = diag?.counters?.analysis_requests ?? 0;

  return (
    <div className="space-y-8">
      {/* Title Bar */}
      <div className="relative rounded-3xl border border-slate-800/80 bg-slate-900/60 p-6 sm:p-8 backdrop-blur-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700/60 text-[10px] font-mono font-bold tracking-widest uppercase text-cyan-400 mb-2">
            <Activity size={11} />
            <span>Telemetry & Threat Metrics</span>
          </div>
          <h1 className="text-2xl font-black text-white">System Threat Intelligence Metrics</h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Real-time multi-vector forensics • Last sync: {lastRefreshed ? lastRefreshed.toLocaleTimeString() : "Live"}
          </p>
        </div>
        <button
          onClick={refreshData}
          disabled={loading}
          className="self-start sm:self-auto inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700/60 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold transition-all cursor-pointer"
        >
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          <span>Refresh Metrics</span>
        </button>
      </div>

      {/* Top Stat Counters */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Audited Payloads", value: totalScans, color: "text-cyan-400" },
          { label: "Scams Intercepted", value: diag?.labels?.dangerous ?? 0, color: "text-rose-400" },
          { label: "Suspicious Flagged", value: diag?.labels?.suspicious ?? 0, color: "text-amber-400" },
          { label: "Verified Authentic", value: diag?.labels?.safe ?? 0, color: "text-emerald-400" },
        ].map((item, idx) => (
          <div
            key={idx}
            className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-5 backdrop-blur-xl"
          >
            <span className="text-[11px] font-mono font-semibold text-slate-400 block">{item.label}</span>
            <div className={`text-3xl font-black ${item.color} mt-2 font-mono`}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      {/* Visual Charts */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Label Distribution Pie Chart */}
        <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl">
          <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-4">
            Threat Classification Spectrum
          </h3>
          {labelData.length > 0 && labelData.some((d) => d.value > 0) ? (
            <div className="h-60">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={labelData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={4}
                  >
                    {labelData.map((entry) => (
                      <Cell key={entry.name} fill={PIE_COLORS[entry.name] || "#64748b"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: "1rem",
                      color: "#fff",
                      fontSize: "12px",
                      fontFamily: "monospace",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex justify-center gap-4 text-xs font-mono mt-2">
                {labelData.map((d) => (
                  <span key={d.name} className="flex items-center gap-1.5 capitalize text-slate-300">
                    <span
                      className="w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: PIE_COLORS[d.name] }}
                    ></span>
                    {d.name}: <strong>{d.value}</strong>
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-60 flex items-center justify-center text-xs font-mono text-slate-500">
              No targets analyzed in the current session.
            </div>
          )}
        </div>

        {/* Source Contribution Bar Chart */}
        <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl">
          <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-4">
            Shield Detection Triggers
          </h3>
          {sourceData.length > 0 && sourceData.some((d) => d.value > 0) ? (
            <div className="h-60">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sourceData}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} fontVariant="monospace" />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: "1rem",
                      color: "#fff",
                      fontSize: "12px",
                      fontFamily: "monospace",
                    }}
                  />
                  <Bar dataKey="value" fill="#06b6d4" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-60 flex items-center justify-center text-xs font-mono text-slate-500">
              No shield telemetry captured yet.
            </div>
          )}
        </div>
      </div>

      {/* Security Shields Health Status */}
      <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl space-y-4">
        <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <ShieldCheck size={14} className="text-cyan-400" />
          <span>Active Forensic Detection Subsystems</span>
        </h3>
        <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-3">
          {diag?.capabilities &&
            Object.entries(diag.capabilities).map(([key, enabled]) => (
              <div
                key={key}
                className="flex items-center gap-2.5 p-3 rounded-2xl bg-slate-950/60 border border-slate-800/60"
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    enabled ? "bg-emerald-400 animate-pulse" : "bg-rose-500"
                  }`}
                />
                <span className="text-xs font-mono text-slate-300">
                  {SHIELD_NAMES[key] || key}
                </span>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}
