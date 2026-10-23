import { useState, useEffect } from "react";
import {
  FileText,
  Star,
  ExternalLink,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Search,
  Sparkles,
  Info,
  Copy,
  Check,
  Printer,
  AlertCircle,
} from "lucide-react";
import { getTrustpilotReputation } from "../api/phishlens";
import type { TrustpilotResponse } from "../api/phishlens";
import { BRANDING } from "../config/branding";
import { useToast } from "../components/useToast";

const BENCHMARK_DOMAINS = [
  { label: "PayPal Clone (Zero-Day)", domain: "paypa1-security-verification.com", tag: "Phishing Target" },
  { label: "PayPal (Official)", domain: "paypal.com", tag: "Verified Brand" },
  { label: "Amazon Official", domain: "amazon.com", tag: "High Trust" },
  { label: "State Bank of India", domain: "sbi.co.in", tag: "Banking" },
  { label: "Apple Official", domain: "apple.com", tag: "Technology" },
];

export default function TrustReport() {
  const [domain, setDomain] = useState("paypal.com");
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<TrustpilotResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState(false);
  const [reportTimestamp, setReportTimestamp] = useState<string>("");
  const toast = useToast();

  async function handleSearch(targetDomain?: string) {
    const query = (targetDomain ?? domain).trim();
    if (!query) {
      toast.error("Input required", "Please enter a domain to inspect.");
      return;
    }

    // Strip protocols if entered
    let cleanHost = query;
    try {
      if (query.startsWith("http://") || query.startsWith("https://")) {
        cleanHost = new URL(query).hostname;
      }
    } catch {
      cleanHost = query;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await getTrustpilotReputation(cleanHost);
      setData(res);
      setReportTimestamp(new Date().toLocaleString());
      toast.success("Trust Report Loaded", `Domain: ${cleanHost}`);
    } catch (err: any) {
      const msg = err.message || "Could not retrieve reputation intelligence.";
      setError(msg);
      toast.error("Lookup Failed", msg);
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    getTrustpilotReputation("paypal.com")
      .then((res) => {
        if (!cancelled) {
          setData(res);
          setReportTimestamp(new Date().toLocaleString());
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const handleCopyReport = () => {
    if (!data) return;

    const reportText = `=== ${BRANDING.productName} — Domain Trust Report ===
Target Domain: ${data.domain}
Audit Timestamp: ${reportTimestamp}
Trust Level: ${data.rating_label}
Trust Score: ${data.trust_score.toFixed(1)} / 5.0 (${data.total_reviews})
Zero-Day Flag: ${data.is_unverified_scam_indicator ? "YES (Unreviewed / High Fraud Risk)" : "NO (Verified Footprint)"}

Community Assessment:
${data.community_verdict}

Top Indicators / Concerns:
${data.top_complaints ? data.top_complaints.map((c) => `- ${c}`).join("\n") : "None reported."}

Important Limitation:
${BRANDING.disclaimer}
Report generated via ${BRANDING.companyName}.`;

    navigator.clipboard.writeText(reportText).then(() => {
      setCopiedReport(true);
      toast.success("Report Copied", "Formatted trust report copied to clipboard.");
      setTimeout(() => setCopiedReport(false), 2000);
    });
  };

  const isScam = data?.is_unverified_scam_indicator;

  return (
    <div className="space-y-8">
      {/* Hero Header */}
      <div className="rounded-2xl border border-slate-200/90 bg-white p-6 sm:p-8 shadow-card">
        <div className="max-w-3xl mb-6">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 border border-blue-200/60 text-[11px] font-semibold uppercase tracking-wider mb-3">
            <FileText size={13} className="stroke-[2.2]" />
            <span>Community Trust Intelligence</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 mb-2">
            Domain Trust & Reputation Report
          </h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Generate verifiable domain trust assessments. Cross-references global consumer reviews, rating distributions, and historical fraud complaints to distinguish established institutions from unreviewed zero-day look-alikes.
          </p>
        </div>

        {/* Search Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSearch();
          }}
          className="space-y-3"
        >
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
              <input
                type="text"
                value={domain}
                onChange={(e) => {
                  setDomain(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="Enter domain or web address (e.g. paypal.com or paypa1-verification.com)..."
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
                  <span>Querying Trust...</span>
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  <span>Generate Report</span>
                </>
              )}
            </button>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-xl bg-rose-50 border border-rose-200 p-3.5 text-xs text-rose-800 flex items-start gap-2.5 animate-in fade-in duration-150"
            >
              <AlertCircle size={16} className="text-rose-600 shrink-0 mt-0.5" />
              <div className="flex-1 leading-relaxed">
                <span className="font-semibold block">Lookup Notice</span>
                <span>{error}</span>
              </div>
            </div>
          )}
        </form>

        {/* Quick Benchmarks */}
        <div className="mt-5 pt-4 border-t border-slate-100 flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-medium text-slate-400 mr-1">
            Sample Benchmarks:
          </span>
          {BENCHMARK_DOMAINS.map((b, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setDomain(b.domain);
                handleSearch(b.domain);
              }}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200/80 transition-colors cursor-pointer"
            >
              <span>{b.label}</span>
              <span className="text-[10px] text-slate-400 font-mono">({b.tag})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Generated Report View */}
      {data && (
        <div className="space-y-6">
          {/* Action Toolbar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white p-4 rounded-xl border border-slate-200/90 shadow-card">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-500">
                Audit Target: <strong className="text-slate-900">{data.domain}</strong>
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-xs text-slate-500">
                Generated: {reportTimestamp}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyReport}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-medium transition-colors cursor-pointer"
              >
                {copiedReport ? (
                  <>
                    <Check size={13} className="text-emerald-600" />
                    <span>Report Copied</span>
                  </>
                ) : (
                  <>
                    <Copy size={13} />
                    <span>Copy Text Report</span>
                  </>
                )}
              </button>

              <button
                onClick={() => window.print()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-medium transition-colors cursor-pointer"
              >
                <Printer size={13} />
                <span>Print</span>
              </button>
            </div>
          </div>

          {/* Main Card */}
          <div
            className={`rounded-2xl border p-6 sm:p-8 shadow-card transition-all ${
              isScam
                ? "bg-rose-50/20 border-rose-200"
                : "bg-white border-slate-200/90"
            }`}
          >
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
              <div className="flex items-center gap-3">
                <div
                  className={`p-3 rounded-xl shrink-0 ${
                    isScam
                      ? "bg-rose-100 text-rose-700 border border-rose-200"
                      : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                  }`}
                >
                  {isScam ? <ShieldAlert size={22} /> : <CheckCircle2 size={22} />}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-bold text-slate-900">
                      {data.domain}
                    </h2>
                    <span
                      className={`text-[11px] font-semibold px-2.5 py-0.5 rounded-full border ${
                        isScam
                          ? "bg-rose-50 text-rose-700 border-rose-200"
                          : "bg-emerald-50 text-emerald-700 border-emerald-200"
                      }`}
                    >
                      {isScam ? "Unreviewed Zero-Day Domain" : "Established Verified Brand"}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Verified through Trustpilot API & Threat Intelligence Directory
                  </p>
                </div>
              </div>

              {data.trustpilot_url && (
                <a
                  href={data.trustpilot_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200/80 px-3 py-1.5 rounded-lg border border-slate-200 transition-colors self-start sm:self-auto"
                >
                  <span>Verify at Trustpilot</span>
                  <ExternalLink size={12} />
                </a>
              )}
            </div>

            {/* Key Scores */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 my-6">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/60">
                <span className="text-xs font-medium text-slate-500 block">Trust Rating</span>
                <div className="flex items-center gap-2 mt-1">
                  <div className="flex text-amber-400">
                    {[1, 2, 3, 4, 5].map((star) => (
                      <Star
                        key={star}
                        size={16}
                        className={star <= data.star_rating ? "fill-amber-400" : "text-slate-300"}
                      />
                    ))}
                  </div>
                  <span className="text-sm font-bold text-slate-900 font-sans">
                    {data.star_rating > 0 ? `${data.trust_score.toFixed(1)} / 5.0` : "0.0"}
                  </span>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/60">
                <span className="text-xs font-medium text-slate-500 block">Reviews Analyzed</span>
                <span className="text-sm font-bold text-slate-900 block mt-1">
                  {data.total_reviews}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/60">
                <span className="text-xs font-medium text-slate-500 block">Reputation Category</span>
                <span
                  className={`text-sm font-bold block mt-1 ${
                    isScam ? "text-rose-600" : "text-emerald-700"
                  }`}
                >
                  {data.rating_label}
                </span>
              </div>
            </div>

            {/* Community Verdict */}
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-50/80 border border-slate-200/60">
                <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider mb-1.5">
                  Executive Verdict
                </h3>
                <p className="text-xs text-slate-700 leading-relaxed">
                  {data.community_verdict}
                </p>
              </div>

              {/* Complaints / Indicators */}
              {data.top_complaints && data.top_complaints.length > 0 && (
                <div className="p-4 rounded-xl bg-white border border-slate-200/60 space-y-2">
                  <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle size={13} className={isScam ? "text-rose-600" : "text-amber-600"} />
                    <span>{isScam ? "Fraud Indicators" : "Reported User Complaints"}</span>
                  </h3>
                  <div className="space-y-1.5">
                    {data.top_complaints.map((item, idx) => (
                      <div key={idx} className="text-xs text-slate-600 flex items-start gap-2">
                        <span className="text-slate-400 mt-0.5">•</span>
                        <span className="leading-snug">{item}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Limitations Notice */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/60 text-xs text-slate-500 flex items-start gap-2.5">
                <Info size={16} className="text-slate-400 shrink-0 mt-0.5" />
                <div className="leading-relaxed">
                  <strong className="text-slate-700 block">Report Limitation Notice:</strong>
                  Community reputation metrics summarize public consumer reports up to the timestamp above. Newly deployed phishing sites often have zero reviews because they were registered within days. Never rely on absence of reviews as proof of safety.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
