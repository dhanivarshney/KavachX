import { useState } from "react";
import {
  MessageSquare,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
} from "lucide-react";
import { analyzeSmishing } from "../api/phishlens";
import type { SmishingResponse } from "../api/phishlens";
import { useToast } from "../components/useToast";

const SAMPLE_MESSAGES = [
  {
    title: "Electricity Disconnection Panic",
    sender: "VK-POWR",
    tag: "High Urgency",
    text: "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM from the main sub-station due to unpaid previous month bill. Update your bill immediately: http://paypa1-security-verification.com",
  },
  {
    title: "Bank KYC Suspension Threat",
    sender: "VK-SBIINB",
    tag: "Impersonation",
    text: "Dear User, your NetBanking account has been blocked due to pending KYC verification. Update your PAN & Aadhaar immediately to resume banking services: http://secure-login-chase-update.info/auth/login",
  },
  {
    title: "Courier Delivery Failure Bait",
    sender: "AD-INDPOST",
    tag: "Fake Delivery",
    text: "India Post Notice: Your package could not be delivered due to incomplete address details. Update your shipping address within 24 hours or package will be returned: http://x7k9q2m1p0z-banking-auth.top/address",
  },
  {
    title: "Malicious APK Job Offer",
    sender: "+91-9845120394",
    tag: "Malware Trap",
    text: "Congratulations! You have been shortlisted for product rating job. Earn Rs. 5000 daily. Just 30 mins work from phone. Download our task application to claim bonus: http://instant-task-payout.live/task.apk",
  },
  {
    title: "Authentic Banking Security OTP",
    sender: "HDFC-OTP",
    tag: "Legitimate",
    text: "582914 is your secret One Time Password (OTP) for NetBanking login. Valid for 5 minutes. Do not share this OTP with anyone, including bank staff.",
  },
];

export default function Smishing() {
  const [message, setMessage] = useState("");
  const [senderId, setSenderId] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SmishingResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedLink, setCopiedLink] = useState<string | null>(null);
  const toast = useToast();

  async function handleAnalyze(customText?: string, customSender?: string) {
    const textToScan = customText ?? message;
    const senderToScan = customSender ?? senderId;

    if (!textToScan.trim()) {
      setError("Please paste or type a text message or chat snippet to inspect.");
      toast.error("Input required", "Please enter a message to inspect.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await analyzeSmishing(textToScan, senderToScan);
      setResult(res);
      toast.success(
        "Analysis Complete",
        `Threat Score: ${res.threat_score}/100 (${res.risk_label})`
      );
    } catch (err: any) {
      const msg = err.message || "Failed to analyze message. Ensure the backend server is running.";
      setError(msg);
      toast.error("Analysis Failed", msg);
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  function handleSelectSample(s: typeof SAMPLE_MESSAGES[0]) {
    setMessage(s.text);
    setSenderId(s.sender);
    handleAnalyze(s.text, s.sender);
  }

  const handleCopyLink = (url: string) => {
    navigator.clipboard.writeText(url).then(() => {
      setCopiedLink(url);
      toast.success("Link copied", url);
      setTimeout(() => setCopiedLink(null), 2000);
    });
  };

  return (
    <div className="space-y-8">
      {/* Hero & Scanner Card */}
      <div className="rounded-2xl border border-slate-200/90 bg-white p-6 sm:p-8 shadow-card">
        <div className="max-w-3xl mb-6">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-blue-50 text-blue-700 border border-blue-200/60 text-[11px] font-semibold uppercase tracking-wider mb-3">
            <MessageSquare size={13} className="stroke-[2.2]" />
            <span>SMS & Chat Fraud Intelligence</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 mb-2">
            SMS & Mobile Scam Guard
          </h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Inspect suspicious SMS text messages, WhatsApp alerts, and chat lures. Detects psychological urgency tricks, false bank freezes, fake courier notices, and extracts embedded links for instant security scoring.
          </p>
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAnalyze();
          }}
          className="space-y-4"
        >
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label htmlFor="smishing-text" className="block text-xs font-semibold text-slate-700 mb-1.5">
                Message Content:
              </label>
              <textarea
                id="smishing-text"
                rows={4}
                value={message}
                onChange={(e) => {
                  setMessage(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="Paste the SMS or chat message content here (e.g. 'Your power will be disconnected tonight...')"
                className="w-full bg-slate-50 border border-slate-300 hover:border-slate-400 rounded-xl p-3 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600 focus:bg-white transition-all font-sans resize-y"
              />
            </div>

            <div className="sm:col-span-1 flex flex-col justify-between">
              <div>
                <label htmlFor="sender-id" className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Sender Header (Optional):
                </label>
                <input
                  id="sender-id"
                  type="text"
                  value={senderId}
                  onChange={(e) => setSenderId(e.target.value)}
                  placeholder="e.g. VK-SBIINB or +91..."
                  className="w-full bg-slate-50 border border-slate-300 hover:border-slate-400 rounded-xl px-3 py-2.5 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600 focus:bg-white transition-all font-sans"
                />
                <span className="text-[11px] text-slate-400 mt-1 block">
                  Checks for brand header mismatch against message content.
                </span>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="mt-3 w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs tracking-wide shadow-sm disabled:opacity-50 transition-all cursor-pointer"
              >
                {loading ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Analyzing Tactics...</span>
                  </>
                ) : (
                  <>
                    <Sparkles size={14} />
                    <span>Inspect Message</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-xl bg-rose-50 border border-rose-200 p-3.5 text-xs text-rose-800 flex items-start gap-2.5"
            >
              <AlertCircle size={16} className="text-rose-600 shrink-0 mt-0.5" />
              <div className="flex-1 leading-relaxed">
                <span className="font-semibold block">Scan Notice</span>
                <span>{error}</span>
              </div>
            </div>
          )}
        </form>

        {/* Test Samples */}
        <div className="mt-5 pt-4 border-t border-slate-100 flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-medium text-slate-400 mr-1">
            Test Scenarios:
          </span>
          {SAMPLE_MESSAGES.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleSelectSample(sample)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200/80 transition-colors cursor-pointer"
            >
              <span>{sample.title}</span>
              <span className="text-[10px] text-slate-400 font-mono">({sample.tag})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Analysis Result */}
      {result && (
        <div className="space-y-6">
          {/* Summary Bar */}
          <div className="rounded-2xl border border-slate-200/90 bg-white p-5 shadow-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div
                className={`p-2.5 rounded-xl shrink-0 ${
                  result.risk_label === "dangerous"
                    ? "bg-rose-100 text-rose-700 border border-rose-200"
                    : result.risk_label === "suspicious"
                    ? "bg-amber-100 text-amber-700 border border-amber-200"
                    : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                }`}
              >
                {result.risk_label === "dangerous" ? (
                  <ShieldAlert size={20} />
                ) : result.risk_label === "suspicious" ? (
                  <AlertTriangle size={20} />
                ) : (
                  <ShieldCheck size={20} />
                )}
              </div>
              <div>
                <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-500 block">
                  Smishing Risk Verdict
                </span>
                <span className="font-bold text-sm text-slate-900 capitalize">
                  {result.risk_label === "dangerous"
                    ? "High Risk Malicious Message"
                    : result.risk_label === "suspicious"
                    ? "Suspicious Manipulation Tactics Detected"
                    : "Standard Operational Notification"}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-500 font-mono">
                Threat Score: <strong className="text-slate-900">{result.threat_score}/100</strong>
              </span>
              <span
                className={`px-3 py-1 rounded-full text-xs font-semibold border ${
                  result.risk_label === "dangerous"
                    ? "bg-rose-50 text-rose-700 border-rose-200"
                    : result.risk_label === "suspicious"
                    ? "bg-amber-50 text-amber-700 border-amber-200"
                    : "bg-emerald-50 text-emerald-700 border-emerald-200"
                }`}
              >
                {result.risk_label.toUpperCase()}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            {/* Left 1/3: Tactics & Brand */}
            <div className="lg:col-span-1 space-y-4">
              {/* Impersonated Brand Card */}
              <div className="rounded-2xl border border-slate-200/90 bg-white p-5 shadow-card space-y-3">
                <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
                  Target Identity
                </h3>
                <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/60">
                  <span className="text-[11px] text-slate-500 block">Identified Entity:</span>
                  <span className="font-semibold text-xs text-slate-900 block mt-0.5">
                    {result.impersonated_brand || "No Specific Brand Detected"}
                  </span>
                </div>
              </div>

              {/* Detected Psychological Traps */}
              <div className="rounded-2xl border border-slate-200/90 bg-white p-5 shadow-card space-y-3">
                <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider flex items-center justify-between">
                  <span>Detected Traps</span>
                  <span className="text-xs font-mono font-medium text-slate-500">
                    {result.detected_traps.length}
                  </span>
                </h3>

                {result.detected_traps.length > 0 ? (
                  <div className="space-y-2">
                    {result.detected_traps.map((trap, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-xl bg-rose-50/60 border border-rose-200/80 text-xs text-rose-900 flex items-start gap-2"
                      >
                        <ShieldAlert size={14} className="text-rose-600 shrink-0 mt-0.5" />
                        <span className="font-medium leading-snug">{trap}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/60 text-xs text-slate-500 flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-emerald-600" />
                    <span>No artificial urgency or psychological traps identified.</span>
                  </div>
                )}
              </div>
            </div>

            {/* Right 2/3: Extracted Links & Safety Advice */}
            <div className="lg:col-span-2 space-y-6">
              {/* AI Advice Card */}
              <div className="rounded-2xl border border-slate-200/90 bg-white p-6 shadow-card space-y-3">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 pb-2 border-b border-slate-100">
                  <Sparkles size={16} className="text-blue-600" />
                  <span>AI Protective Action Guidance</span>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed font-normal">
                  {result.ai_advice}
                </p>
                <div className="pt-2 text-[11px] text-slate-500 bg-slate-50 p-2.5 rounded-lg border border-slate-200/60">
                  <strong className="text-slate-700">Safety Rule:</strong> Legitimate institutions never threaten service termination within hours via bare SMS links.
                </div>
              </div>

              {/* Extracted Links Scoring */}
              <div className="rounded-2xl border border-slate-200/90 bg-white p-6 shadow-card space-y-4">
                <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                  <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
                    Extracted Embedded Links ({result.extracted_links.length})
                  </h3>
                  <span className="text-[11px] text-slate-500">
                    Inspected by URL engine
                  </span>
                </div>

                {result.extracted_links.length > 0 ? (
                  <div className="space-y-3">
                    {result.extracted_links.map((link, idx) => (
                      <div
                        key={idx}
                        className={`p-3.5 rounded-xl border transition-all ${
                          link.label === "dangerous"
                            ? "bg-rose-50/20 border-rose-200"
                            : link.label === "suspicious"
                            ? "bg-amber-50/20 border-amber-200"
                            : "bg-slate-50 border-slate-200"
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2 truncate">
                            <span className="font-mono text-xs font-semibold text-slate-900 truncate">
                              {link.url}
                            </span>
                            <button
                              onClick={() => handleCopyLink(link.url)}
                              className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition-colors"
                              title="Copy URL"
                            >
                              {copiedLink === link.url ? (
                                <Check size={12} className="text-emerald-600" />
                              ) : (
                                <Copy size={12} />
                              )}
                            </button>
                          </div>
                          <span
                            className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border self-start sm:self-auto ${
                              link.label === "dangerous"
                                ? "bg-rose-50 text-rose-700 border-rose-200"
                                : link.label === "suspicious"
                                ? "bg-amber-50 text-amber-700 border-amber-200"
                                : "bg-emerald-50 text-emerald-700 border-emerald-200"
                            }`}
                          >
                            Risk: {link.risk_score}/100 ({link.label})
                          </span>
                        </div>

                        {link.reasons.length > 0 && (
                          <div className="space-y-1 pt-1 border-t border-slate-100 text-[11px] text-slate-600">
                            {link.reasons.map((r, ri) => (
                              <div key={ri} className="flex items-start gap-1.5">
                                <span className="text-rose-500 font-bold">•</span>
                                <span>{r}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic p-3 bg-slate-50 rounded-xl">
                    No embedded links or URLs were extracted from this message snippet.
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
