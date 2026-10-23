interface Props {
  score: number;
  label: "safe" | "suspicious" | "dangerous";
  loading?: boolean;
}

const COLORS = {
  safe: {
    bg: "bg-emerald-50",
    text: "text-emerald-700",
    border: "border-emerald-200",
    badge: "bg-emerald-600 text-white",
    ring: "stroke-emerald-500",
    title: "Safe to Visit",
    message: "Verified authentic website. No deceptive or credential harvesting traits identified.",
  },
  suspicious: {
    bg: "bg-amber-50",
    text: "text-amber-700",
    border: "border-amber-200",
    badge: "bg-amber-500 text-white",
    ring: "stroke-amber-500",
    title: "Caution Advised",
    message: "Anomalous indicators detected. Look-alike syntax or unverified security parameters.",
  },
  dangerous: {
    bg: "bg-rose-50",
    text: "text-rose-700",
    border: "border-rose-200",
    badge: "bg-rose-600 text-white",
    ring: "stroke-rose-500",
    title: "Dangerous Scam",
    message: "Immediate threat! Zero-day replica designed to intercept passwords or banking credentials.",
  },
};

export function RiskGauge({ score, label, loading }: Props) {
  const c = COLORS[label] || COLORS.safe;
  const pct = Math.min(100, Math.max(0, score));
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (pct / 100) * circumference;

  return (
    <div className={`rounded-3xl border-2 ${c.border} ${c.bg} p-6 shadow-sm flex flex-col items-center justify-center transition-all duration-300`}>
      <div className="relative flex items-center justify-center w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
          <circle cx="64" cy="64" r={radius} className="stroke-slate-200" strokeWidth="8" fill="transparent" />
          <circle
            cx="64" cy="64" r={radius}
            className={`${c.ring} transition-all duration-700 ease-out`}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={loading ? circumference : strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-black text-slate-900 tracking-tight">{loading ? "--" : score}</span>
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Risk Score</span>
        </div>
      </div>
      <div className="mt-4 text-center space-y-1">
        <div className="flex items-center justify-center gap-2">
          <span className={`text-[10px] uppercase font-black px-2.5 py-0.5 rounded-full ${c.badge}`}>{label}</span>
          <span className={`text-sm font-bold ${c.text}`}>{c.title}</span>
        </div>
        <p className="text-xs text-slate-500 max-w-xs mt-1 leading-relaxed">{c.message}</p>
      </div>
    </div>
  );
}
