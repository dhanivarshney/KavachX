import { useState, useEffect, useRef } from "react";
import {
  Search,
  AlertOctagon,
  Radio,
  ChevronDown,
  ChevronUp,
  Globe,
  Sparkles,
} from "lucide-react";
import { analyzeUrl, getExplanation, getRecentScans, getLatestScan } from "../api/phishlens";
import type { AnalysisResponse, ScanRecord } from "../api/phishlens";
import { RiskGauge } from "../components/RiskGauge";
import { SignalBreakdown } from "../components/SignalBreakdown";
import { AIExplain } from "../components/AIExplain";
import TrustpilotCard from "../components/TrustpilotCard";

const BADGE_MAP = {
  safe: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-bold",
  suspicious: "bg-amber-500/10 text-amber-400 border-amber-500/30 font-bold",
  dangerous: "bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold",
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [activeUrl, setActiveUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingAI, setLoadingAI] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [explanation, setExplanation] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [liveScans, setLiveScans] = useState<ScanRecord[]>([]);
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);

  const lastSeenIdRef = useRef<string | null>(null);
  const isInitialMount = useRef<boolean>(true);

  // Poll recent scans every 1.5s to listen for extension visits
  useEffect(() => {
    let isSubscribed = true;

    async function poll() {
      try {
        const latest = await getLatestScan();
        if (!isSubscribed) return;

        if (latest && latest.id !== lastSeenIdRef.current) {
          lastSeenIdRef.current = latest.id;
          setLiveScans((prev) => {
            const exists = prev.some((s) => s.id === latest.id);
            if (exists) return prev;
            return [latest, ...prev].slice(0, 30);
          });

          // Auto-display if scanned via extension
          if (latest.source_origin === "extension" || isInitialMount.current) {
            isInitialMount.current = false;
            setActiveUrl(latest.url);
            setUrl(latest.url);
            const analysisRes: AnalysisResponse = {
              risk_score: latest.risk_score,
              label: latest.label,
              confidence: latest.confidence,
              reasons: latest.reasons,
              sources: {
                heuristics: Boolean(latest.sources.heuristics),
                ml: Boolean(latest.sources.ml),
                phishtank: Boolean(latest.sources.phishtank),
                tls: Boolean(latest.sources.tls),
                domain_age: Boolean(latest.sources.domain_age),
                demo: Boolean(latest.sources.demo),
              },
              risk_breakdown: latest.risk_breakdown,
            };
            setResult(analysisRes);

            setLoadingAI(true);
            getExplanation(latest.label, latest.risk_score, latest.reasons, latest.risk_breakdown)
              .then((exp) => setExplanation(exp))
              .finally(() => setLoadingAI(false));
          }
        }

        const recent = await getRecentScans(15);
        if (isSubscribed && recent.length > 0) {
          setLiveScans(recent);
          if (isInitialMount.current && recent[0]) {
            isInitialMount.current = false;
            handleSelectFromStream(recent[0]);
          }
        }
      } catch {
        // backend warming up or idle
      }
    }

    poll();
    const interval = setInterval(poll, 1500);

    return () => {
      isSubscribed = false;
      clearInterval(interval);
    };
  }, []);

  async function handleManualScan(targetUrl?: string) {
    const raw = targetUrl ?? url;
    if (!raw.trim()) return;

    let normalized = raw.trim();
    if (!/^https?:\/\//i.test(normalized)) {
      normalized = "https://" + normalized;
    }

    setLoading(true);
    setError("");
    setExplanation("");
    setActiveUrl(normalized);

    try {
      const res = await analyzeUrl(normalized);
      setResult(res);

      setLoadingAI(true);
      getExplanation(res.label, res.risk_score, res.reasons, res.risk_breakdown)
        .then((exp) => setExplanation(exp))
        .finally(() => setLoadingAI(false));
    } catch (err: any) {
      setError(err.message || "Failed to inspect this website. Ensure the backend server is running.");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  function handleSelectFromStream(scan: ScanRecord) {
    setActiveUrl(scan.url);
    setUrl(scan.url);
    const analysisRes: AnalysisResponse = {
      risk_score: scan.risk_score,
      label: scan.label,
      confidence: scan.confidence,
      reasons: scan.reasons,
      sources: {
        heuristics: Boolean(scan.sources.heuristics),
        ml: Boolean(scan.sources.ml),
        phishtank: Boolean(scan.sources.phishtank),
        tls: Boolean(scan.sources.tls),
        domain_age: Boolean(scan.sources.domain_age),
        demo: Boolean(scan.sources.demo),
      },
      risk_breakdown: scan.risk_breakdown,
    };
    setResult(analysisRes);

    setLoadingAI(true);
    getExplanation(scan.label, scan.risk_score, scan.reasons, scan.risk_breakdown)
      .then((exp) => setExplanation(exp))
      .finally(() => setLoadingAI(false));
  }

  const sampleUrls = [
    { label: "Fake PayPal Clone (Zero-Day)", url: "https://paypa1-security-verification.com" },
    { label: "Google (Legitimate Domain)", url: "https://www.google.com" },
    { label: "Chase Bank Phishing Lure", url: "http://secure-login-chase-update.info/auth/login" },
    { label: "Scrambled Random Link", url: "https://x7k9q2m1p0z-banking-auth.top" },
  ];

  return (
    <div className="space-y-6">
      {/* Search & Command Input */}
      <div className="rounded-3xl border border-slate-800/80 bg-slate-900/40 p-5 sm:p-6 backdrop-blur-xl">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleManualScan();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Paste website address or domain (e.g. paypa1-verification.com)..."
              className="w-full bg-slate-950/80 border border-slate-800 rounded-2xl pl-11 pr-4 py-3 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-2xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono font-bold text-xs shadow-lg shadow-cyan-500/10 cursor-pointer disabled:opacity-50 transition-all shrink-0"
          >
            <Sparkles size={14} />
            <span>{loading ? "Inspecting 6 Shields..." : "Inspect Website"}</span>
          </button>
        </form>

        {/* Quick Sample Presets */}
        <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold">
            Quick Tests:
          </span>
          {sampleUrls.map((s, i) => (
            <button
              key={i}
              type="button"
              onClick={() => {
                setUrl(s.url);
                handleManualScan(s.url);
              }}
              className="text-xs px-2.5 py-1 rounded-xl bg-slate-800/50 hover:bg-slate-800 text-slate-300 font-mono transition-colors border border-slate-700/40 cursor-pointer"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="rounded-2xl bg-rose-500/10 border border-rose-500/30 p-4 text-xs text-rose-300 flex items-center gap-3">
          <AlertOctagon size={16} className="text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Analysis Results */}
      {result ? (
        <div className="space-y-6">
          {/* Active Target Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900/60 border border-slate-800/80 px-5 py-4 rounded-3xl backdrop-blur-xl">
            <div className="flex items-center gap-3 max-w-xl truncate">
              <div className="p-2 rounded-xl bg-slate-800/80 text-cyan-400 shrink-0">
                <Globe size={18} />
              </div>
              <div className="truncate">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Active Web Target
                </span>
                <span className="font-mono text-xs font-semibold text-white truncate block">
                  {activeUrl}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span
                className={`text-xs font-mono font-bold px-3 py-1 rounded-full border ${BADGE_MAP[result.label]}`}
              >
                {result.label === "dangerous"
                  ? "🔴 SCAM INFRASTRUCTURE"
                  : result.label === "suspicious"
                  ? "🟡 ANOMALOUS / CAUTION"
                  : "🟢 VERIFIED AUTHENTIC"}{" "}
                ({result.risk_score}/100)
              </span>
            </div>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            {/* Left 1/3: Risk Gauge & Quick Metrics */}
            <div className="md:col-span-1 space-y-4">
              <RiskGauge score={result.risk_score} label={result.label} loading={loading} />

              <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-5 space-y-3 text-xs font-mono backdrop-blur-xl">
                <div className="flex justify-between items-center text-slate-400">
                  <span>Confidence Level:</span>
                  <span className="font-bold text-slate-200">
                    {Math.round(result.confidence * 100)}%
                  </span>
                </div>
                <div className="flex justify-between items-center text-slate-400">
                  <span>Classification:</span>
                  <span className="font-bold text-slate-200 uppercase text-[10px] tracking-wider px-2 py-0.5 rounded bg-slate-800">
                    {result.label}
                  </span>
                </div>
                <div className="flex justify-between items-center text-slate-400">
                  <span>Detection Latency:</span>
                  <span className="font-bold text-emerald-400">&lt; 1.2s</span>
                </div>
              </div>
            </div>

            {/* Right 2/3: Breakdown, AI Explain, Trustpilot */}
            <div className="md:col-span-2 space-y-6">
              <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 shadow-sm backdrop-blur-xl">
                <SignalBreakdown breakdown={result.risk_breakdown} />
              </div>

              {/* AI Explanation Box */}
              <AIExplain
                explanation={explanation}
                loading={loadingAI}
                score={result.risk_score}
              />

              {/* Trustpilot Community Reputation */}
              <TrustpilotCard domain={activeUrl} />
            </div>
          </div>
        </div>
      ) : (
        <div className="rounded-3xl border border-slate-800/80 bg-slate-900/40 p-12 text-center space-y-3 backdrop-blur-xl">
          <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto">
            <Radio size={22} className="animate-pulse" />
          </div>
          <h3 className="font-bold text-white text-sm">Monitoring Chrome Browser Activity...</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            Open any website in Google Chrome with the PhishLens extension loaded, or select an example link above to view full telemetry.
          </p>
        </div>
      )}

      {/* Live Stream Table */}
      <div className="rounded-3xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800/80 bg-slate-950/40">
          <div className="flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
              Live Browser Feed ({liveScans.length} Scanned)
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            Real-Time Extension Sync Active
          </span>
        </div>

        {liveScans.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No websites captured yet. Visit any page in Chrome to stream it live here.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60 max-h-96 overflow-y-auto">
            {liveScans.map((scan) => {
              const isSelected = activeUrl === scan.url;
              const isExpanded = expandedScanId === scan.id;

              return (
                <div
                  key={scan.id}
                  className={`p-4 transition-colors ${
                    isSelected ? "bg-slate-800/50" : "hover:bg-slate-800/20"
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                    <div className="flex items-start sm:items-center gap-3 truncate max-w-md">
                      <span
                        className={`shrink-0 w-2 h-2 rounded-full mt-1 sm:mt-0 ${
                          scan.label === "dangerous"
                            ? "bg-rose-500"
                            : scan.label === "suspicious"
                            ? "bg-amber-400"
                            : "bg-emerald-400"
                        }`}
                      />
                      <div className="truncate">
                        <span className="font-mono text-xs font-semibold text-slate-100 block truncate">
                          {scan.url}
                        </span>
                        <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500 mt-0.5">
                          <span>{scan.timestamp ? new Date(scan.timestamp).toLocaleTimeString() : "Live"}</span>
                          <span>•</span>
                          <span className="uppercase text-cyan-400">{scan.source_origin}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${BADGE_MAP[scan.label]}`}
                      >
                        {scan.label} ({scan.risk_score})
                      </span>

                      <button
                        type="button"
                        onClick={() => handleSelectFromStream(scan)}
                        className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors cursor-pointer"
                      >
                        Inspect
                      </button>

                      <button
                        type="button"
                        onClick={() => setExpandedScanId(isExpanded ? null : scan.id)}
                        className="p-1 rounded-lg hover:bg-slate-800 text-slate-500 hover:text-slate-300 transition-colors"
                      >
                        {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Inspector Accordion */}
                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t border-slate-800/60 text-xs font-mono text-slate-400 space-y-1">
                      <div>
                        Target Hostname: <span className="text-slate-200 font-semibold">{scan.domain}</span>
                      </div>
                      <div>
                        Red Flags Identified:{" "}
                        <span className="text-rose-400 font-semibold">
                          {scan.reasons.length > 0 ? scan.reasons.join(", ") : "None (Passed)"}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
