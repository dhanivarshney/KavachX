import { useState, useEffect } from "react";
import { RefreshCw, Activity, CheckCircle2, XCircle, Info } from "lucide-react";
import { getDiagnostics, getStats } from "../api/phishlens";
import type { DiagnosticsResponse, StatsResponse } from "../api/phishlens";
import { PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, ResponsiveContainer } from "recharts";
import { useToast } from "../components/useToast";

const PIE_COLORS: Record<string, string> = {
  safe: "#059669",
  suspicious: "#d97706",
  dangerous: "#e11d48",
};

const CAPABILITY_LABELS: Record<string, string> = {
  threat_intel_enabled: "Known Threat Intel Database",
  tls_analysis_enabled: "SSL / TLS Handshake Validator",
  ct_log_lookup_enabled: "Certificate Transparency Logs",
  domain_age_lookup_enabled: "Domain Registration Age (RDAP)",
  ml_model_available: "AI LightGBM Heuristic Model",
  rate_limiting_enabled: "Rate-Limiting Flood Defense",
  diagnostics_enabled: "Live Telemetry Feed",
  demo_threat_source_enabled: "Demo Simulation Feed",
};

export default function Stats() {
  const [diag, setDiag] = useState<DiagnosticsResponse | null>(null);
  const [statsData, setStatsData] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const toast = useToast();

  async function refreshData() {
    setLoading(true);
    try {
      const [d, s] = await Promise.all([
        getDiagnostics().catch(() => null),
        getStats().catch(() => null),
      ]);
      setDiag(d);
      setStatsData(s);
      setLastRefreshed(new Date());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let mounted = true;

    async function loadMetrics() {
      try {
        const [d, s] = await Promise.all([
          getDiagnostics().catch(() => null),
          getStats().catch(() => null),
        ]);
        if (mounted) {
          setDiag(d);
          setStatsData(s);
          setLastRefreshed(new Date());
          setLoading(false);
        }
      } catch {
        if (mounted) setLoading(false);
      }
    }

    loadMetrics();
    const interval = setInterval(loadMetrics, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const totalScans = diag?.counters?.analysis_requests ?? 0;

  // Prepare chart data from real backend metrics
  const labelData = diag?.labels
    ? Object.entries(diag.labels).map(([name, value]) => ({
        name: name === "dangerous" ? "High Risk" : name === "suspicious" ? "Suspicious" : "Low Risk",
        key: name,
        value,
      }))
    : [];

  const sourceData = diag?.sources
    ? Object.entries(diag.sources).map(([name, value]) => ({
        name: name.toUpperCase(),
        detections: value,
      }))
    : [];

  return (
    <div className="space-y-8">
      {/* Title & Refresh Bar */}
      <div className="rounded-2xl border border-slate-200/90 bg-white p-6 sm:p-8 shadow-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 border border-blue-200/60 text-[11px] font-semibold uppercase tracking-wider mb-2">
            <Activity size={13} className="stroke-[2.2]" />
            <span>Operational Forensics</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900">
            Security Intelligence Analytics
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Real telemetry derived from live scans • Synced: {lastRefreshed ? lastRefreshed.toLocaleTimeString() : "Pending"}
          </p>
        </div>

        <button
          onClick={() => {
            refreshData();
            toast.info("Refreshed", "Telemetry metrics synced from backend.");
          }}
          disabled={loading}
          className="self-start sm:self-auto inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-semibold transition-all cursor-pointer"
        >
          <RefreshCw size={13} className={loading ? "animate-spin text-blue-600" : ""} />
          <span>Refresh Metrics</span>
        </button>
      </div>

      {/* Primary KPI Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          {
            label: "Total Audited Payloads",
            value: totalScans,
            sub: "Scans executed",
            color: "text-slate-900",
            bg: "bg-white",
          },
          {
            label: "High Risk Flags",
            value: diag?.labels?.dangerous ?? 0,
            sub: "Malicious signatures",
            color: "text-rose-600",
            bg: "bg-rose-50/30",
          },
          {
            label: "Caution Advised",
            value: diag?.labels?.suspicious ?? 0,
            sub: "Anomalous patterns",
            color: "text-amber-600",
            bg: "bg-amber-50/30",
          },
          {
            label: "Verified Authentic",
            value: diag?.labels?.safe ?? 0,
            sub: "Clean indicators",
            color: "text-emerald-600",
            bg: "bg-emerald-50/30",
          },
        ].map((item, idx) => (
          <div
            key={idx}
            className={`rounded-2xl border border-slate-200/90 ${item.bg} p-5 shadow-card`}
          >
            <span className="text-xs font-medium text-slate-500 block">{item.label}</span>
            <div className={`text-3xl font-bold ${item.color} mt-2 font-mono`}>
              {item.value}
            </div>
            <span className="text-[11px] text-slate-400 mt-1 block">{item.sub}</span>
          </div>
        ))}
      </div>

      {/* Visual Analytics */}
      {totalScans === 0 ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center space-y-3 shadow-card">
          <Info size={24} className="text-slate-400 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-800">No Scan Data Accumulated</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Execute scans using the Web Scanner or Chrome extension to populate telemetry distributions and vector analysis.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Pie Chart: Verdict Distribution */}
          <div className="rounded-2xl border border-slate-200/90 bg-white p-6 shadow-card space-y-4">
            <h3 className="text-sm font-semibold text-slate-900">
              Risk Verdict Distribution
            </h3>
            <div className="h-64 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={labelData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {labelData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={PIE_COLORS[entry.key] || "#94a3b8"}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#ffffff",
                      borderRadius: "8px",
                      border: "1px solid #e2e8f0",
                      fontSize: "12px",
                      boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.05)",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex items-center justify-center gap-6 text-xs text-slate-600">
              {labelData.map((item) => (
                <div key={item.key} className="flex items-center gap-1.5">
                  <span
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: PIE_COLORS[item.key] }}
                  />
                  <span>{item.name}:</span>
                  <span className="font-semibold text-slate-900">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Bar Chart: Triggered Vectors */}
          <div className="rounded-2xl border border-slate-200/90 bg-white p-6 shadow-card space-y-4">
            <h3 className="text-sm font-semibold text-slate-900">
              Triggered Detections by Source Vector
            </h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sourceData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <XAxis
                    dataKey="name"
                    tick={{ fontSize: 10, fill: "#64748b" }}
                    angle={-20}
                    textAnchor="end"
                  />
                  <YAxis tick={{ fontSize: 10, fill: "#64748b" }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#ffffff",
                      borderRadius: "8px",
                      border: "1px solid #e2e8f0",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="detections" fill="#2563eb" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="text-[11px] text-slate-400 text-center">
              Aggregate detections flagged by heuristic, ML, threat intelligence, and TLS validators.
            </p>
          </div>
        </div>
      )}

      {/* Feedback Store Telemetry if present */}
      {statsData && statsData.total_reports > 0 && (
        <div className="rounded-2xl border border-slate-200/90 bg-white p-6 shadow-card space-y-3">
          <h3 className="text-sm font-semibold text-slate-900">
            Model Validation & Feedback Metrics
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
              <span className="text-slate-500">Audited Feedback Records:</span>
              <strong className="block text-slate-900 text-sm mt-1">{statsData.total_reports}</strong>
            </div>
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
              <span className="text-slate-500">False Positives Reported:</span>
              <strong className="block text-slate-900 text-sm mt-1">{statsData.false_positives}</strong>
            </div>
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
              <span className="text-slate-500">False Negatives Reported:</span>
              <strong className="block text-slate-900 text-sm mt-1">{statsData.false_negatives}</strong>
            </div>
          </div>
        </div>
      )}

      {/* Engine Capabilities Status Grid */}
      <div className="rounded-2xl border border-slate-200/90 bg-white p-6 shadow-card space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">
              Active Security Engine Capabilities
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Live operational status of detection engines and external lookups
            </p>
          </div>
          <span className="text-[11px] font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 rounded-full">
            {diag?.status === "ok" ? "All Systems Operational" : "Workspace Mode"}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {diag?.capabilities &&
            Object.entries(diag.capabilities).map(([key, active]) => {
              const label = CAPABILITY_LABELS[key] || key.replace(/_/g, " ");
              return (
                <div
                  key={key}
                  className={`p-3 rounded-xl border flex items-center justify-between text-xs transition-colors ${
                    active
                      ? "bg-emerald-50/30 border-emerald-200/70 text-slate-800"
                      : "bg-slate-50 border-slate-200 text-slate-500"
                  }`}
                >
                  <span className="font-medium truncate pr-2">{label}</span>
                  {active ? (
                    <CheckCircle2 size={16} className="text-emerald-600 shrink-0" />
                  ) : (
                    <XCircle size={16} className="text-slate-400 shrink-0" />
                  )}
                </div>
              );
            })}
        </div>
      </div>
    </div>
  );
}
