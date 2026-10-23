import { useState } from "react";
import {
  MessageSquare,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Sparkles,
  Info,
  CheckCircle2,
  AlertOctagon,
  Flame,
} from "lucide-react";
import { analyzeSmishing } from "../api/phishlens";
import type { SmishingResponse } from "../api/phishlens";

const SAMPLE_MESSAGES = [
  {
    title: "⚡ Electricity Disconnection Alert",
    sender: "VK-POWR",
    text: "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM from the main sub-station due to unpaid previous month bill. Update your bill immediately: http://paypa1-security-verification.com",
  },
  {
    title: "🏦 SBI NetBanking KYC Freeze",
    sender: "VK-SBIINB",
    text: "Dear SBI User, your NetBanking account has been blocked due to pending KYC verification. Update your PAN & Aadhaar immediately to resume banking services: http://secure-login-chase-update.info/kyc",
  },
  {
    title: "📦 India Post Courier Undelivered",
    sender: "AD-INDPOST",
    text: "India Post Notice: Your package could not be delivered due to incomplete address details. Update your shipping address within 24 hours or package will be returned: http://x7k9q2m1p0z-banking-auth.top/address",
  },
  {
    title: "💼 WhatsApp Work-From-Home Scam",
    sender: "+91-9845120394",
    text: "Congratulations! You have been shortlisted for Amazon product rating part-time job. Earn Rs. 3000 to Rs. 8000 daily. Just 30 mins work from phone. Download our task application: http://instant-task-payout.live/task.apk",
  },
  {
    title: "🟢 Legitimate Bank OTP Alert",
    sender: "SBI-OTP",
    text: "582914 is your secret One Time Password (OTP) for SBI NetBanking login. Valid for 5 minutes. Do not share this OTP with anyone, including bank staff.",
  },
];

export default function Smishing() {
  const [message, setMessage] = useState("");
  const [senderId, setSenderId] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SmishingResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze(customText?: string, customSender?: string) {
    const textToScan = customText ?? message;
    const senderToScan = customSender ?? senderId;

    if (!textToScan.trim()) {
      setError("Please paste or type a text message to inspect.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await analyzeSmishing(textToScan, senderToScan);
      setResult(res);
    } catch (err: any) {
      setError(err.message || "Failed to analyze message. Ensure the backend server is running.");
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

  return (
    <div className="space-y-6">
      {/* Hero Header */}
      <div className="relative rounded-3xl border border-slate-800/80 bg-slate-900/60 p-6 sm:p-8 backdrop-blur-xl overflow-hidden">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 max-w-2xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700/60 text-[10px] font-mono font-bold tracking-widest uppercase text-indigo-400 mb-3">
            <MessageSquare size={11} />
            <span>SMS & Chat Scam Shield</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white mb-2">
            Smishing & Message Scam Detector
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
            Forensically analyzes SMS and WhatsApp communications for psychological manipulation,
            authority impersonation, and extracts embedded links to evaluate their security posture.
          </p>
        </div>
      </div>

      {/* Input Card */}
      <div className="rounded-3xl border border-slate-800/80 bg-slate-900/40 p-5 sm:p-6 backdrop-blur-xl">
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="sm:w-1/3">
              <label className="text-xs font-mono font-bold text-slate-400 block mb-1.5">
                Sender ID / Origin Header
              </label>
              <input
                type="text"
                value={senderId}
                onChange={(e) => setSenderId(e.target.value)}
                placeholder="e.g. VK-POWR or +91-98765..."
                className="w-full text-xs font-mono bg-slate-950/80 border border-slate-800 rounded-2xl px-4 py-3 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>
            <div className="sm:w-2/3">
              <label className="text-xs font-mono font-bold text-slate-400 block mb-1.5">
                Message Body
              </label>
              <textarea
                rows={3}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Paste the suspicious SMS, WhatsApp message, or email payload here..."
                className="w-full text-xs font-mono bg-slate-950/80 border border-slate-800 rounded-2xl px-4 py-3 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
            <span className="text-[11px] font-mono text-slate-500">
              Auto-detects embedded URLs and queries the 6-shield web scanner
            </span>
            <button
              onClick={() => handleAnalyze()}
              disabled={loading || !message.trim()}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-2xl bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-mono font-bold text-xs tracking-wide shadow-lg shadow-indigo-500/10 cursor-pointer disabled:opacity-50 transition-all shrink-0"
            >
              <Sparkles size={14} />
              <span>{loading ? "Scanning Attack Vectors..." : "Inspect Message"}</span>
            </button>
          </div>

          {/* Quick Benchmark Presets */}
          <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold">
              Scam Scenarios:
            </span>
            {SAMPLE_MESSAGES.map((s, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectSample(s)}
                className="text-xs px-2.5 py-1 rounded-xl bg-slate-800/50 hover:bg-slate-800 text-slate-300 font-mono transition-colors border border-slate-700/40 cursor-pointer"
              >
                {s.title}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-2xl bg-rose-500/10 border border-rose-500/30 p-4 text-xs text-rose-300 flex items-center gap-3">
          <AlertOctagon size={16} className="text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Analysis Results */}
      {result && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Main Verdict Banner */}
          <div
            className={`p-6 rounded-3xl border backdrop-blur-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${
              result.risk_label === "dangerous"
                ? "bg-rose-500/10 border-rose-500/30 text-rose-100"
                : result.risk_label === "suspicious"
                ? "bg-amber-500/10 border-amber-500/30 text-amber-100"
                : "bg-emerald-500/10 border-emerald-500/30 text-emerald-100"
            }`}
          >
            <div className="flex items-center gap-4">
              <div
                className={`p-3.5 rounded-2xl ${
                  result.risk_label === "dangerous"
                    ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                    : result.risk_label === "suspicious"
                    ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                }`}
              >
                {result.risk_label === "dangerous" ? (
                  <ShieldAlert size={28} />
                ) : result.risk_label === "suspicious" ? (
                  <AlertTriangle size={28} />
                ) : (
                  <ShieldCheck size={28} />
                )}
              </div>
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider block opacity-75">
                  Message Threat Verdict
                </span>
                <h3 className="text-base sm:text-lg font-black tracking-tight">
                  {result.safety_summary}
                </h3>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <div className="px-4 py-2 rounded-2xl bg-slate-950/60 border border-current font-mono font-black text-sm">
                Threat Index: {result.threat_score} / 100
              </div>
            </div>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            {/* Left 2/3: Identified Traps & Embedded Links */}
            <div className="md:col-span-2 space-y-6">
              {/* Deception Patterns */}
              <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl">
                <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <AlertTriangle size={14} className="text-rose-400" />
                  <span>Identified Threat Vectors ({result.detected_traps.length})</span>
                </h3>

                {result.detected_traps.length > 0 ? (
                  <div className="space-y-2.5">
                    {result.detected_traps.map((trap, idx) => (
                      <div
                        key={idx}
                        className="flex items-start gap-3 p-3.5 rounded-2xl bg-slate-950/60 border border-slate-800/60 text-xs font-mono text-slate-200"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-500 mt-1.5 shrink-0"></span>
                        <span className="leading-snug">{trap}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs font-mono flex items-center gap-2">
                    <CheckCircle2 size={16} className="text-emerald-400" />
                    <span>No known urgency patterns, false countdowns, or deceptive lures found.</span>
                  </div>
                )}
              </div>

              {/* Embedded Links Inspector */}
              {result.extracted_links && result.extracted_links.length > 0 && (
                <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-6 backdrop-blur-xl">
                  <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <ExternalLink size={14} className="text-cyan-400" />
                    <span>Embedded Link Forensic Audit ({result.extracted_links.length})</span>
                  </h3>
                  <div className="space-y-3">
                    {result.extracted_links.map((link, idx) => (
                      <div
                        key={idx}
                        className="p-4 rounded-2xl border border-slate-800/80 bg-slate-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono"
                      >
                        <div className="truncate max-w-md">
                          <span className="font-bold text-white block truncate">{link.url}</span>
                          <span className="text-[11px] text-slate-400 mt-0.5 block">
                            {link.reasons.join(" • ") || "Audited via 6-Shield Multi-Vector Scanner"}
                          </span>
                        </div>
                        <span
                          className={`shrink-0 px-2.5 py-1 rounded-full font-bold uppercase text-[10px] border ${
                            link.label === "dangerous"
                              ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                              : link.label === "suspicious"
                              ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
                              : "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                          }`}
                        >
                          {link.label} ({link.risk_score}/100)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right 1/3: Brand Impersonation & Incident Guidance */}
            <div className="space-y-6">
              {result.impersonated_brand && (
                <div className="rounded-3xl border border-slate-800/80 bg-slate-900/50 p-5 backdrop-blur-xl">
                  <span className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wider block mb-1">
                    Target Entity Impersonated
                  </span>
                  <div className="flex items-center gap-2 font-black text-white text-base">
                    <Flame size={18} className="text-amber-400" />
                    <span>{result.impersonated_brand}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                    Attackers weaponize trusted institutional identities to induce panic and bypass critical judgment.
                  </p>
                </div>
              )}

              {/* Actionable Defense Plan */}
              <div className="rounded-3xl border border-indigo-500/30 bg-slate-900/60 p-6 backdrop-blur-xl space-y-3 shadow-lg shadow-indigo-950/20">
                <div className="flex items-center gap-2 text-indigo-400 text-xs font-mono font-bold uppercase tracking-wider">
                  <Info size={14} />
                  <span>Defensive Incident Action</span>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-medium">
                  {result.ai_advice}
                </p>
                <div className="pt-3 border-t border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1.5">
                  <div>• Never tap shortened links from unknown numbers.</div>
                  <div>• Refuse to download any attachment ending in <code>.apk</code>.</div>
                  <div>• Legitimate banks never solicit OTPs via SMS urgency.</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
