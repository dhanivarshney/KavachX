import { ShieldCheck, AlertTriangle, ShieldAlert } from "lucide-react";
import { BRANDING } from "../config/branding";

interface RiskGaugeProps {
  score: number;
  label: "safe" | "suspicious" | "dangerous";
  confidence?: number;
  loading?: boolean;
}

export function RiskGauge({ score, label, confidence, loading }: RiskGaugeProps) {
  // Classification info
  const meta =
    label === "dangerous"
      ? {
          title: BRANDING.labels.dangerous.title,
          badgeText: BRANDING.labels.dangerous.badgeText,
          bgLight: "bg-rose-50/60",
          border: "border-rose-200/80",
          textColor: "text-rose-700",
          pillBg: "bg-rose-100/90 text-rose-800 border-rose-200",
          ringColor: "stroke-rose-600",
          icon: ShieldAlert,
          description: BRANDING.labels.dangerous.description,
        }
      : label === "suspicious"
      ? {
          title: BRANDING.labels.suspicious.title,
          badgeText: BRANDING.labels.suspicious.badgeText,
          bgLight: "bg-amber-50/60",
          border: "border-amber-200/80",
          textColor: "text-amber-700",
          pillBg: "bg-amber-100/90 text-amber-800 border-amber-200",
          ringColor: "stroke-amber-500",
          icon: AlertTriangle,
          description: BRANDING.labels.suspicious.description,
        }
      : {
          title: BRANDING.labels.safe.title,
          badgeText: BRANDING.labels.safe.badgeText,
          bgLight: "bg-emerald-50/60",
          border: "border-emerald-200/80",
          textColor: "text-emerald-700",
          pillBg: "bg-emerald-100/90 text-emerald-800 border-emerald-200",
          ringColor: "stroke-emerald-600",
          icon: ShieldCheck,
          description: BRANDING.labels.safe.description,
        };

  const Icon = meta.icon;
  const clampedScore = Math.min(100, Math.max(0, score));

  // Circular gauge calculations
  const radius = 50;
  const strokeWidth = 8;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  return (
    <div
      className={`rounded-2xl border ${meta.border} bg-white p-6 shadow-card flex flex-col items-center text-center relative overflow-hidden transition-all duration-300`}
    >
      {/* Subtle top indicator bar */}
      <div
        className={`absolute top-0 left-0 right-0 h-1.5 ${
          label === "dangerous"
            ? "bg-rose-600"
            : label === "suspicious"
            ? "bg-amber-500"
            : "bg-emerald-600"
        }`}
      />

      {/* SVG Ring Gauge */}
      <div className="relative flex items-center justify-center w-36 h-36 my-2">
        <svg
          className="w-full h-full -rotate-90 transform"
          viewBox="0 0 120 120"
          aria-label={`Risk score: ${score} out of 100`}
          role="img"
        >
          {/* Background Track */}
          <circle
            cx="60"
            cy="60"
            r={radius}
            className="stroke-slate-100"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Progress Indicator */}
          <circle
            cx="60"
            cy="60"
            r={radius}
            className={`${meta.ringColor} transition-all duration-700 ease-out`}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={loading ? circumference : strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>

        {/* Center Score Readout */}
        <div className="absolute flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold text-slate-900 tracking-tight font-sans">
            {loading ? "--" : score}
          </span>
          <span className="text-[10px] font-medium uppercase tracking-wider text-slate-400">
            Risk Index / 100
          </span>
        </div>
      </div>

      {/* Classification Pill & Status */}
      <div className="mt-3 flex items-center gap-2">
        <span
          className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${meta.pillBg}`}
        >
          <Icon size={12} className="stroke-[2.5]" />
          <span>{meta.title}</span>
        </span>
        {confidence !== undefined && (
          <span className="text-[11px] font-medium text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full border border-slate-200">
            {Math.round(confidence * 100)}% Confidence
          </span>
        )}
      </div>

      <p className="text-xs text-slate-600 mt-2.5 leading-relaxed max-w-xs">
        {meta.description}
      </p>

      {/* Scale guide */}
      <div className="w-full mt-4 pt-3 border-t border-slate-100 grid grid-cols-3 text-center text-[10px] font-medium text-slate-400">
        <div>
          <span className="block text-emerald-700 font-semibold">0 - 34</span>
          <span>Low Risk</span>
        </div>
        <div>
          <span className="block text-amber-700 font-semibold">35 - 69</span>
          <span>Suspicious</span>
        </div>
        <div>
          <span className="block text-rose-700 font-semibold">70 - 100</span>
          <span>High Risk</span>
        </div>
      </div>
    </div>
  );
}
