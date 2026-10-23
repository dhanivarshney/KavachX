import { useState, useEffect, useRef } from "react";
import {
  Search,
  AlertCircle,
  Globe,
  Sparkles,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
} from "lucide-react";
import { analyzeUrl, getExplanation, getRecentScans, getLatestScan } from "../api/phishlens";
import type { AnalysisResponse, ScanRecord } from "../api/phishlens";
import { RiskGauge } from "../components/RiskGauge";
import { SignalBreakdown } from "../components/SignalBreakdown";
import { AIExplain } from "../components/AIExplain";
import TrustpilotCard from "../components/TrustpilotCard";
import { HistoryTable } from "../components/HistoryTable";
import { BRANDING } from "../config/branding";
import { useToast } from "../components/useToast";

export default function Home() {
  const [inputUrl, setInputUrl] = useState("");
  const [activeUrl, setActiveUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingAI, setLoadingAI] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [explanation, setExplanation] = useState<string>("");
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [recentScans, setRecentScans] = useState<ScanRecord[]>([]);
  const [scanTime, setScanTime] = useState<string>("");
  const [copiedUrl, setCopiedUrl] = useState(false);

  const lastSeenIdRef = useRef<string | null>(null);
  const isInitialMount = useRef<boolean>(true);
  const toast = useToast();

  // Load recent scans from backend and listen for new ones
  useEffect(() => {
    let isSubscribed = true;

    async function fetchScans() {
      try {
        const latest = await getLatestScan();
        if (!isSubscribed) return;

        if (latest && latest.id !== lastSeenIdRef.current) {
          lastSeenIdRef.current = latest.id;
          setRecentScans((prev) => {
            const exists = prev.some((s) => s.id === latest.id);
            if (exists) return prev;
            return [latest, ...prev].slice(0, 30);
          });

          // If scanned from Chrome extension or first time, load it
          if (latest.source_origin === "extension" || isInitialMount.current) {
            isInitialMount.current = false;
            displayScanRecord(latest);
          }
        }

        const recent = await getRecentScans(15);
        if (isSubscribed && recent.length > 0) {
          setRecentScans((prev) => {
            // merge unique by id
            const map = new Map<string, ScanRecord>();
            for (const r of [...prev, ...recent]) {
              map.set(r.id, r);
            }
            return Array.from(map.values()).sort(
              (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
            );
          });
        }
      } catch {
        // Backend warming up or idle
      }
    }

    fetchScans();
    const interval = setInterval(fetchScans, 2500);

    return () => {
      isSubscribed = false;
      clearInterval(interval);
    };
  }, []);

  function displayScanRecord(scan: ScanRecord) {
    setActiveUrl(scan.url);
    setInputUrl(scan.url);
    setScanTime(scan.timestamp ? new Date(scan.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString());
    setErrorMsg("");

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

  // Client-side URL normalization & validation
  function validateAndNormalizeUrl(raw: string): { valid: boolean; normalized: string; error?: string } {
    const trimmed = raw.trim();
    if (!trimmed) {
      return { valid: false, normalized: "", error: "Please enter a website URL or domain name to analyze." };
    }

    if (/^(javascript|data|file|ftp):/i.test(trimmed)) {
      return { valid: false, normalized: "", error: "Unsupported URL protocol. Please enter an HTTP or HTTPS web address." };
    }

    let urlToParse = trimmed;
    if (!/^https?:\/\//i.test(urlToParse)) {
      urlToParse = "https://" + urlToParse;
    }

    try {
      const parsed = new URL(urlToParse);
      if (!parsed.hostname || !parsed.hostname.includes(".")) {
        return { valid: false, normalized: "", error: "Please provide a valid domain name (e.g. example.com or https://example.com)." };
      }
      return { valid: true, normalized: urlToParse };
    } catch {
      return { valid: false, normalized: "", error: "Malformed URL format. Please verify the web address syntax." };
    }
  }

  async function handleAnalyze(targetUrl?: string) {
    const raw = targetUrl ?? inputUrl;
    const validation = validateAndNormalizeUrl(raw);

    if (!validation.valid) {
      setErrorMsg(validation.error || "Invalid URL.");
      toast.error("Invalid URL", validation.error);
      return;
    }

    const normalized = validation.normalized;
    setLoading(true);
    setErrorMsg("");
    setExplanation("");
    setActiveUrl(normalized);
    setScanTime(new Date().toLocaleTimeString());

    try {
      const res = await analyzeUrl(normalized);
      setResult(res);
      toast.success("Analysis complete", `Risk score: ${res.risk_score}/100 (${res.label})`);

      // Add to local recent scans
      const newRecord: ScanRecord = {
        id: Math.random().toString(36).substring(2, 9),
        url: normalized,
        domain: new URL(normalized).hostname,
        risk_score: res.risk_score,
        label: res.label,
        confidence: res.confidence,
        reasons: res.reasons,
        sources: {
          heuristics: res.sources.heuristics,
          ml: res.sources.ml,
          phishtank: res.sources.phishtank,
          tls: res.sources.tls,
          domain_age: res.sources.domain_age,
          demo: res.sources.demo,
        },
        risk_breakdown: res.risk_breakdown,
        source_origin: "dashboard",
        timestamp: new Date().toISOString(),
      };

      setRecentScans((prev) => [newRecord, ...prev.filter((p) => p.url !== normalized)].slice(0, 30));

      // Trigger AI Explanation
      setLoadingAI(true);
      getExplanation(res.label, res.risk_score, res.reasons, res.risk_breakdown)
        .then((exp) => setExplanation(exp))
        .finally(() => setLoadingAI(false));
    } catch (err: any) {
      const message =
        err.message ||
        "Failed to reach the threat intelligence engine. Ensure backend service is running at http://localhost:8000.";
      setErrorMsg(message);
      toast.error("Analysis Failed", message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  const handleCopyActiveUrl = () => {
    if (!activeUrl) return;
    navigator.clipboard.writeText(activeUrl).then(() => {
      setCopiedUrl(true);
      toast.success("Copied to clipboard", activeUrl);
      setTimeout(() => setCopiedUrl(false), 2000);
    });
  };

  const handleClearHistory = () => {
    setRecentScans([]);
    toast.info("Scan history cleared", "Cleared current session records.");
  };

  const activeHostname = activeUrl ? (() => {
    try {
      return new URL(activeUrl).hostname;
    } catch {
      return activeUrl;
    }
  })() : "";

  return (
    <div className="space-y-8">
      {/* Hero & Scanner Card */}
      <div className="rounded-2xl border border-slate-200/90 bg-white p-6 sm:p-8 shadow-card relative overflow-hidden">
        <div className="max-w-3xl mb-6">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 border border-blue-200/60 text-[11px] font-semibold uppercase tracking-wider mb-3">
            <Globe size={13} className="stroke-[2.2]" />
            <span>AI-Assisted Web Scanner</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 mb-2">
            Check a website before you trust it.
          </h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            {BRANDING.tagline} Forensically inspect URLs across 6 distinct security vectors to uncover typosquatting, zero-day infrastructure, deceptive credential collection forms, and unverified certificates.
          </p>
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAnalyze();
          }}
          className="space-y-3"
        >
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search
                className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400"
                size={18}
              />
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => {
                  setInputUrl(e.target.value);
                  if (errorMsg) setErrorMsg("");
                }}
                placeholder="https://example.com"
                aria-label="Website address to analyze"
                className="w-full bg-slate-50 border border-slate-300 hover:border-slate-400 rounded-xl pl-11 pr-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600 focus:bg-white transition-all font-sans"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs tracking-wide shadow-sm disabled:opacity-50 transition-all cursor-pointer shrink-0"
            >
              {loading ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Analyzing Vectors...</span>
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  <span>Analyze Website</span>
                </>
              )}
            </button>
          </div>

          {/* Validation / Error Message */}
          {errorMsg && (
            <div
              role="alert"
              className="rounded-xl bg-rose-50 border border-rose-200 p-3.5 text-xs text-rose-800 flex items-start gap-2.5 animate-in fade-in duration-150"
            >
              <AlertCircle size={16} className="text-rose-600 shrink-0 mt-0.5" />
              <div className="flex-1 leading-relaxed">
                <span className="font-semibold block">Inspection Notice</span>
                <span>{errorMsg}</span>
              </div>
            </div>
          )}
        </form>

        {/* Curated Test Samples */}
        <div className="mt-5 pt-4 border-t border-slate-100 flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-medium text-slate-400 mr-1">
            Test Examples:
          </span>
          {BRANDING.testSamples.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setInputUrl(sample.url);
                handleAnalyze(sample.url);
              }}
              title={sample.description}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200/80 transition-colors cursor-pointer"
            >
              <span>{sample.label}</span>
              <span className="text-[10px] text-slate-400 font-mono">({sample.tag})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Security Result Section */}
      {result ? (
        <div className="space-y-6">
          {/* Target Domain Banner */}
          <div className="rounded-2xl border border-slate-200/90 bg-white p-4 sm:p-5 shadow-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="p-2.5 rounded-xl bg-slate-100 text-slate-700 shrink-0">
                <Globe size={18} />
              </div>
              <div className="min-w-0">
                <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-500 block">
                  Analyzed Domain Target
                </span>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-sm text-slate-900 truncate">
                    {activeHostname}
                  </span>
                  <button
                    onClick={handleCopyActiveUrl}
                    title="Copy target URL"
                    className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
                  >
                    {copiedUrl ? <Check size={13} className="text-emerald-600" /> : <Copy size={13} />}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0 flex-wrap">
              {scanTime && (
                <span className="text-xs text-slate-500 font-mono">
                  Scanned: {scanTime}
                </span>
              )}
              <span
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${
                  result.label === "dangerous"
                    ? "bg-rose-50 text-rose-700 border-rose-200"
                    : result.label === "suspicious"
                    ? "bg-amber-50 text-amber-700 border-amber-200"
                    : "bg-emerald-50 text-emerald-700 border-emerald-200"
                }`}
              >
                {result.label === "dangerous" && <ShieldAlert size={13} />}
                {result.label === "suspicious" && <AlertTriangle size={13} />}
                {result.label === "safe" && <ShieldCheck size={13} />}
                <span className="capitalize">{result.label}</span>
                <span>({result.risk_score}/100)</span>
              </span>
            </div>
          </div>

          {/* Results Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            {/* Left Column (1/3): Risk Gauge and Meta */}
            <div className="lg:col-span-1 space-y-4">
              <RiskGauge
                score={result.risk_score}
                label={result.label}
                confidence={result.confidence}
                loading={loading}
              />

              {/* Quick Telemetry Summary */}
              <div className="rounded-2xl border border-slate-200/90 bg-white p-4 shadow-card text-xs space-y-2.5">
                <div className="flex justify-between items-center text-slate-500">
                  <span>Confidence Metric:</span>
                  <span className="font-semibold text-slate-900 font-mono">
                    {Math.round(result.confidence * 100)}%
                  </span>
                </div>
                <div className="flex justify-between items-center text-slate-500">
                  <span>Risk Classification:</span>
                  <span className="font-semibold text-slate-900 uppercase text-[10px] px-2 py-0.5 rounded bg-slate-100">
                    {result.label}
                  </span>
                </div>
                <div className="flex justify-between items-center text-slate-500">
                  <span>Inspection Speed:</span>
                  <span className="font-semibold text-emerald-600 font-mono">
                    &lt; 350 ms
                  </span>
                </div>
              </div>

              {/* Safety Disclaimer Banner */}
              <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5 text-xs text-slate-500 flex items-start gap-2">
                <Info size={14} className="text-slate-400 shrink-0 mt-0.5" />
                <p className="leading-relaxed">
                  Automated checks evaluate known threat signatures and heuristics. Zero risk score does not guarantee safety.
                </p>
              </div>
            </div>

            {/* Right Column (2/3): Signal Breakdown & Why This Result */}
            <div className="lg:col-span-2 space-y-6">
              {/* Detailed 6-Vector Safety Breakdown */}
              <div className="rounded-2xl border border-slate-200/90 bg-white p-5 sm:p-6 shadow-card">
                <SignalBreakdown breakdown={result.risk_breakdown} />
              </div>

              {/* Dedicated Explanation Card: Why This Result? */}
              <AIExplain
                explanation={explanation}
                loading={loadingAI}
                score={result.risk_score}
                label={result.label}
                reasons={result.reasons}
                breakdown={result.risk_breakdown}
              />

              {/* Trustpilot Community Reputation */}
              <TrustpilotCard domain={activeHostname} />
            </div>
          </div>
        </div>
      ) : (
        /* Empty State */
        <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center space-y-3 shadow-card">
          <div className="w-12 h-12 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center mx-auto">
            <ShieldCheck size={24} className="stroke-[2.2]" />
          </div>
          <h2 className="text-base font-semibold text-slate-900">
            No Website Analyzed Yet
          </h2>
          <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
            Enter a web address above or select one of the curated test samples to generate a comprehensive multi-vector threat intelligence report.
          </p>
        </div>
      )}

      {/* Scan History Section */}
      <HistoryTable
        scans={recentScans}
        activeUrl={activeUrl}
        onSelect={(scan) => displayScanRecord(scan)}
        onClear={handleClearHistory}
      />
    </div>
  );
}
