import { Sparkles, ShieldAlert, ShieldCheck, ArrowRight, HelpCircle } from "lucide-react";
import type { RiskBreakdownItem } from "../api/phishlens";
import { BRANDING } from "../config/branding";

interface Props {
  explanation: string;
  loading: boolean;
  score: number;
  label: "safe" | "suspicious" | "dangerous";
  reasons: string[];
  breakdown: RiskBreakdownItem[];
}

export function AIExplain({ explanation, loading, score, label, reasons, breakdown }: Props) {
  const cleanChecks = breakdown.filter((b) => b.score <= 0);

  // Recommendations based on score
  const actionAdvice =
    label === "dangerous"
      ? [
          "Do NOT enter passwords, OTP codes, credit cards, or banking information.",
          "Close this website immediately and do not download any attached files or applications.",
          "If you already submitted credentials, change your password immediately on the official website.",
        ]
      : label === "suspicious"
      ? [
          "Double-check the website address manually using an official search engine or your saved bookmarks.",
          "Avoid submitting login credentials or sensitive data until authenticity is verified.",
          "Check for authentic SSL certificates and verify that the brand domain matches exactly.",
        ]
      : [
          "The website shows clean indicators and no malicious signatures were detected.",
          "As standard practice, always check the address bar before entering account credentials.",
          "Remember that newly created zero-day sites may occasionally bypass heuristic databases.",
        ];

  return (
    <div className="rounded-2xl border border-slate-200/90 bg-white p-5 sm:p-6 shadow-card space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 pb-4 border-b border-slate-100">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-blue-50 text-blue-600 border border-blue-100">
            <Sparkles size={18} className="stroke-[2.2]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-slate-900 tracking-tight">
                Why this result?
              </h3>
              <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200/60">
                AI Threat Intelligence
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Forensic reasoning and actionable user recommendations
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs font-mono font-medium text-slate-500">
            Index: {score}/100
          </span>
          <span
            className={`text-xs font-semibold px-2.5 py-1 rounded-lg border ${
              label === "dangerous"
                ? "bg-rose-50 text-rose-700 border-rose-200"
                : label === "suspicious"
                ? "bg-amber-50 text-amber-700 border-amber-200"
                : "bg-emerald-50 text-emerald-700 border-emerald-200"
            }`}
          >
            {label === "dangerous"
              ? "High Risk"
              : label === "suspicious"
              ? "Suspicious"
              : "Verified Low Risk"}
          </span>
        </div>
      </div>

      {/* AI Synthesis Summary */}
      <div className="bg-slate-50/80 rounded-xl p-4 border border-slate-200/60">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 mb-2">
          <HelpCircle size={14} className="text-blue-600" />
          <span>Executive Security Assessment</span>
        </div>
        {loading ? (
          <div className="space-y-2 py-2">
            <div className="flex items-center gap-2 text-xs text-blue-600 animate-pulse font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-ping" />
              Synthesizing multi-vector forensic indicators...
            </div>
            <div className="h-3 bg-slate-200/70 rounded animate-pulse w-4/5" />
            <div className="h-3 bg-slate-200/70 rounded animate-pulse w-2/3" />
          </div>
        ) : explanation ? (
          <p className="text-xs text-slate-700 leading-relaxed font-normal">
            {explanation}
          </p>
        ) : (
          <p className="text-xs text-slate-700 leading-relaxed font-normal">
            {BRANDING.labels[label].advice}
          </p>
        )}
      </div>

      {/* Two Column Grid: Risk Drivers vs Clean Reassurance */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Risk Factors */}
        <div className="rounded-xl border border-slate-200/80 p-3.5 bg-white">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 mb-2">
            <ShieldAlert size={14} className={reasons.length > 0 ? "text-rose-600" : "text-slate-400"} />
            <span>Signals Increasing Risk ({reasons.length})</span>
          </div>
          {reasons.length > 0 ? (
            <ul className="space-y-1.5 text-xs text-slate-600">
              {reasons.slice(0, 4).map((r, i) => (
                <li key={i} className="flex items-start gap-1.5 leading-snug">
                  <span className="text-rose-500 font-bold shrink-0">•</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500 italic">
              No concerning security red flags or scam patterns were detected during inspection.
            </p>
          )}
        </div>

        {/* Clean Indicators */}
        <div className="rounded-xl border border-slate-200/80 p-3.5 bg-white">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 mb-2">
            <ShieldCheck size={14} className="text-emerald-600" />
            <span>Reassuring Findings ({cleanChecks.length})</span>
          </div>
          {cleanChecks.length > 0 ? (
            <ul className="space-y-1.5 text-xs text-slate-600">
              {cleanChecks.map((c, i) => (
                <li key={i} className="flex items-start gap-1.5 leading-snug">
                  <span className="text-emerald-500 font-bold shrink-0">✓</span>
                  <span className="capitalize">{c.category.replace("_", " ")} check passed without incident</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500 italic">
              All inspected vectors exhibited varying threat indicators.
            </p>
          )}
        </div>
      </div>

      {/* Actionable Next Steps */}
      <div className="pt-2">
        <h4 className="text-xs font-semibold text-slate-900 mb-2 flex items-center gap-2">
          <ArrowRight size={14} className="text-blue-600" />
          <span>Recommended Next Actions:</span>
        </h4>
        <div className="grid gap-2">
          {actionAdvice.map((advice, idx) => (
            <div
              key={idx}
              className="flex items-start gap-2.5 text-xs text-slate-700 bg-slate-50 p-2.5 rounded-lg border border-slate-200/60"
            >
              <span className="font-semibold text-blue-600 shrink-0">{idx + 1}.</span>
              <span className="leading-relaxed">{advice}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
