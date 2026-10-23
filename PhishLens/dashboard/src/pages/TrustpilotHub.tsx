import { useState, useEffect } from "react";
import {
  Star,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Sparkles,
  Info,
  CheckCircle2,
  AlertOctagon,
} from "lucide-react";
import { getTrustpilotReputation } from "../api/phishlens";
import type { TrustpilotResponse } from "../api/phishlens";

const SAMPLE_BENCHMARKS = [
  { label: "Fake PayPal Clone (Zero-Day)", domain: "paypa1-security-verification.com" },
  { label: "PayPal (Real Brand)", domain: "paypal.com" },
  { label: "Amazon (E-Commerce)", domain: "amazon.com" },
  { label: "State Bank of India", domain: "sbi.co.in" },
  { label: "Flipkart", domain: "flipkart.com" },
  { label: "Apple", domain: "apple.com" },
];

export default function TrustpilotHub() {
  const [domain, setDomain] = useState("paypal.com");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<TrustpilotResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSearch(targetDomain?: string) {
    const query = (targetDomain ?? domain).trim();
    if (!query) return;

    setLoading(true);
    setError(null);

    try {
      const res = await getTrustpilotReputation(query);
      setData(res);
    } catch (err: any) {
      setError(err.message || "Could not retrieve Trustpilot reputation data.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    handleSearch("paypal.com");
  }, []);

  const isScam = data?.is_unverified_scam_indicator;

  return (
    <div className="space-y-6">
      {/* Hero Header */}
      <div className="relative rounded-3xl border border-slate-800/80 bg-slate-900/60 p-6 sm:p-8 backdrop-blur-xl overflow-hidden">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 max-w-2xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700/60 text-[10px] font-mono font-bold tracking-widest uppercase text-cyan-400 mb-3">
            <Star size={11} className="fill-cyan-400" />
            <span>Community Trust Intelligence</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white mb-2">
            Trustpilot Review Analyzer
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
            Query real-world consumer ratings, review distributions, and past fraud complaints.
            Identifies newly registered scam sites with zero community history.
          </p>
        </div>
      </div>

      {/* Search Bar */}
      <div className="rounded-3xl border border-slate-800/80 bg-slate-900/40 p-5 backdrop-blur-xl">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSearch();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="Enter website domain (e.g. paypal.com or paypa1-verification.com)..."
              className="w-full bg-slate-950/80 border border-slate-800 rounded-2xl pl-11 pr-4 py-3 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-2xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold text-xs tracking-wide shadow-lg shadow-blue-500/10 cursor-pointer disabled:opacity-50 transition-all shrink-0"
          >
            <Sparkles size={14} />
            <span>{loading ? "Querying Trust Database..." : "Analyze Reputation"}</span>
          </button>
        </form>

        {/* Quick Benchmark Presets */}
        <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold">
            Quick Tests:
          </span>
          {SAMPLE_BENCHMARKS.map((b, i) => (
            <button
              key={i}
              type="button"
              onClick={() => {
                setDomain(b.domain);
                handleSearch(b.domain);
              }}
              className="text-xs px-2.5 py-1 rounded-xl bg-slate-800/50 hover:bg-slate-800 text-slate-300 font-mono transition-colors border border-slate-700/40 cursor-pointer"
            >
              {b.label}
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

      {/* Results View */}
      {data && (
        <div className="space-y-6">
          {/* Executive Overview Banner */}
          <div
            className={`p-6 rounded-3xl border backdrop-blur-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6 ${
              isScam
                ? "bg-rose-500/10 border-rose-500/30 text-rose-100"
                : "bg-slate-900/60 border-slate-800/80 text-slate-100"
            }`}
          >
            <div className="flex items-center gap-4">
              <div
                className={`p-3.5 rounded-2xl ${
                  isScam
                    ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                    : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                }`}
              >
                {isScam ? <ShieldAlert size={28} /> : <ShieldCheck size={28} />}
              </div>
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400">
                    Domain Audited
                  </span>
                  <span
                    className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full border ${
                      isScam
                        ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                        : "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                    }`}
                  >
                    {isScam ? "Zero-Day Unverified Scam" : "Verified Enterprise Entity"}
                  </span>
                </div>
                <h2 className="text-xl sm:text-2xl font-black font-mono tracking-tight text-white">
                  {data.domain}
                </h2>
              </div>
            </div>

            {/* External Live Trustpilot Deep Link */}
            <a
              href={data.trustpilot_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold bg-slate-800/80 hover:bg-slate-700 text-slate-200 border border-slate-700/60 transition-colors shrink-0"
            >
              <span>View Live on Trustpilot</span>
              <ExternalLink size={13} />
            </a>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            {/* Left 1/3: Star Telemetry & Breakdown */}
            <div className="space-y-6">
              {/* Score Tile */}
              <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl space-y-4">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  TrustScore & Star Matrix
                </span>
                <div className="flex items-baseline gap-3">
                  <span className="text-4xl font-black text-white font-mono">
                    {data.star_rating > 0 ? data.trust_score.toFixed(1) : "0.0"}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">/ 5.0 Rating</span>
                </div>

                <div className="flex text-amber-400 gap-1">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <Star
                      key={star}
                      size={20}
                      className={star <= data.star_rating ? "fill-amber-400" : "text-slate-700"}
                    />
                  ))}
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Total Reviews:</span>
                  <span className="text-slate-100 font-bold">{data.total_reviews}</span>
                </div>

                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Trust Label:</span>
                  <span
                    className={`font-bold ${
                      isScam ? "text-rose-400" : "text-amber-400"
                    }`}
                  >
                    {data.rating_label}
                  </span>
                </div>
              </div>

              {/* Star Distribution Visual Bars */}
              <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl space-y-3">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Rating Distribution
                </span>
                <div className="space-y-2">
                  {data.star_distribution.map((dist) => (
                    <div key={dist.star} className="flex items-center gap-3 text-xs font-mono">
                      <span className="w-12 text-slate-400 shrink-0">{dist.star} Star</span>
                      <div className="flex-1 h-2 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            dist.star >= 4
                              ? "bg-emerald-500"
                              : dist.star === 3
                              ? "bg-amber-500"
                              : "bg-rose-500"
                          }`}
                          style={{ width: `${dist.percentage}%` }}
                        />
                      </div>
                      <span className="w-9 text-right text-slate-300 font-bold">
                        {dist.percentage}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Right 2/3: Consumer Complaints & Forensic Assessment */}
            <div className="md:col-span-2 space-y-6">
              {/* Executive Summary */}
              <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl space-y-3">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Info size={13} className="text-cyan-400" />
                  <span>Reputation & Risk Analysis</span>
                </span>
                <p className="text-sm text-slate-200 leading-relaxed font-medium">
                  {data.community_verdict}
                </p>
              </div>

              {/* Top Complaints / Red Flags */}
              <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl space-y-4">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <AlertTriangle
                    size={13}
                    className={isScam ? "text-rose-400" : "text-amber-400"}
                  />
                  <span>
                    {isScam ? "Critical Community Red Flags" : "Top Consumer Feedback Trends"}
                  </span>
                </span>

                <div className="space-y-2.5">
                  {data.top_complaints.map((item, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-3 p-3.5 rounded-2xl bg-slate-950/60 border border-slate-800/60 text-xs text-slate-200"
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${
                          isScam ? "bg-rose-500" : "bg-amber-400"
                        }`}
                      />
                      <span className="leading-relaxed">{item}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Phishing Insight Note */}
              <div className="rounded-3xl border border-cyan-500/20 bg-cyan-950/10 p-5 text-xs text-cyan-200/90 leading-relaxed space-y-1">
                <div className="font-bold flex items-center gap-1.5 text-cyan-300">
                  <CheckCircle2 size={14} />
                  <span>How PhishLens Uses Trustpilot Data:</span>
                </div>
                <p className="text-slate-400 text-xs">
                  Phishing kits rely on fresh, unreviewed domains to escape blocklists. When our
                  engine detects a banking or payment domain with <strong>0 Trustpilot reviews</strong>,
                  it flags it as a high-risk zero-day replica.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
