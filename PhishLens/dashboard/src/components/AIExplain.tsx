import { Sparkles } from "lucide-react";

interface Props {
  explanation: string;
  loading: boolean;
  score: number;
}

export function AIExplain({ explanation, loading, score }: Props) {
  if (!explanation && !loading) return null;

  return (
    <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-indigo-50 via-purple-50/50 to-blue-50 border border-indigo-200 p-5 sm:p-6 shadow-sm">
      <div className="flex items-center gap-2.5 text-sm font-bold text-slate-900 mb-3">
        <div className="p-2 rounded-xl bg-indigo-600 text-white shadow-sm shadow-indigo-500/20">
          <Sparkles size={16} />
        </div>
        <div className="flex flex-col">
          <span className="leading-tight">AI Safety Analyst</span>
          <span className="text-[10px] text-indigo-500 font-normal">Plain-English Forensic Assessment</span>
        </div>
        <span className="ml-auto text-[10px] font-bold tracking-wider uppercase px-2.5 py-0.5 rounded-full bg-indigo-100 text-indigo-700 border border-indigo-200">
          Gemini 2.0
        </span>
      </div>

      {loading ? (
        <div className="space-y-2 py-3">
          <div className="flex items-center gap-2 text-xs text-indigo-600 animate-pulse font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-ping" />
            Generating plain-English threat summary...
          </div>
          <div className="h-3 bg-indigo-100 rounded animate-pulse w-3/4" />
          <div className="h-3 bg-indigo-50 rounded animate-pulse w-1/2" />
        </div>
      ) : (
        <p className="text-xs text-slate-700 leading-relaxed mt-1">{explanation}</p>
      )}

      <div className="mt-4 pt-3 border-t border-indigo-100 flex items-center justify-between text-[11px] text-slate-500">
        <span>
          Status:{" "}
          <strong className={score >= 70 ? "text-rose-600" : score >= 35 ? "text-amber-600" : "text-emerald-600"}>
            {score >= 70 ? "Verified Scam Infrastructure" : score >= 35 ? "Suspicious Patterns" : "Authentic & Safe"}
          </strong>
        </span>
        <span className="text-slate-400">Google Gemini AI</span>
      </div>
    </div>
  );
}
