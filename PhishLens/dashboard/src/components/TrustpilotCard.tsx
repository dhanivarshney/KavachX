import { useEffect, useState } from "react";
import { Star, ExternalLink, ShieldAlert, CheckCircle2, MessageSquare, AlertTriangle } from "lucide-react";
import { getTrustpilotReputation } from "../api/phishlens";
import type { TrustpilotResponse } from "../api/phishlens";

interface TrustpilotCardProps {
  domain: string;
}

export default function TrustpilotCard({ domain }: TrustpilotCardProps) {
  const [data, setData] = useState<TrustpilotResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!domain) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    getTrustpilotReputation(domain)
      .then((res) => {
        if (!cancelled) setData(res);
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
  }, [domain]);

  if (loading) {
    return (
      <div className="rounded-3xl border border-slate-800/80 bg-slate-900/40 p-5 backdrop-blur-xl animate-pulse space-y-3">
        <div className="h-4 bg-slate-800 rounded w-1/3"></div>
        <div className="h-8 bg-slate-800 rounded w-1/2"></div>
        <div className="h-4 bg-slate-800 rounded w-3/4"></div>
      </div>
    );
  }

  if (error || !data) {
    return null;
  }

  const isScam = data.is_unverified_scam_indicator;

  return (
    <div
      className={`rounded-3xl border p-5 sm:p-6 backdrop-blur-xl transition-all ${
        isScam
          ? "bg-rose-500/10 border-rose-500/30"
          : "bg-slate-900/60 border-slate-800/80"
      }`}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-4">
        <div className="flex items-center gap-3">
          <div
            className={`p-2.5 rounded-2xl ${
              isScam
                ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                : "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
            }`}
          >
            {isScam ? <ShieldAlert size={18} /> : <CheckCircle2 size={18} />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                Community Reputation
              </span>
              <span
                className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                  isScam
                    ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                    : "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                }`}
              >
                {isScam ? "Unreviewed Zero-Day Site" : "Verified Brand"}
              </span>
            </div>
            <h3 className="text-sm font-bold text-white flex items-center gap-1.5 mt-0.5">
              Trustpilot Intelligence
            </h3>
          </div>
        </div>

        {/* Live Trustpilot External Link */}
        <a
          href={data.trustpilot_url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-[11px] font-mono font-bold text-cyan-400 hover:text-cyan-300 bg-slate-800/80 hover:bg-slate-800 px-3 py-1.5 rounded-xl border border-slate-700/60 transition-colors"
        >
          <span>Trustpilot Page</span>
          <ExternalLink size={11} />
        </a>
      </div>

      {/* Main Score & Stars Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4 p-3.5 rounded-2xl bg-slate-950/60 border border-slate-800/60">
        <div>
          <span className="text-[10px] font-mono text-slate-500 block">Star Rating</span>
          <div className="flex items-center gap-1.5 mt-0.5">
            <div className="flex text-amber-400">
              {[1, 2, 3, 4, 5].map((star) => (
                <Star
                  key={star}
                  size={14}
                  className={star <= data.star_rating ? "fill-amber-400" : "text-slate-800"}
                />
              ))}
            </div>
            <span className="text-xs font-mono font-bold text-slate-200">
              {data.star_rating > 0 ? `${data.trust_score.toFixed(1)} / 5` : "0.0"}
            </span>
          </div>
        </div>

        <div>
          <span className="text-[10px] font-mono text-slate-500 block">Total Reviews</span>
          <div className="flex items-center gap-1.5 mt-0.5">
            <MessageSquare size={13} className="text-slate-500" />
            <span className="text-xs font-mono font-bold text-slate-200">{data.total_reviews}</span>
          </div>
        </div>

        <div>
          <span className="text-[10px] font-mono text-slate-500 block">Trust Level</span>
          <span
            className={`text-xs font-mono font-bold ${
              isScam ? "text-rose-400" : "text-amber-400"
            }`}
          >
            {data.rating_label}
          </span>
        </div>
      </div>

      {/* Community Verdict */}
      <div className="text-xs text-slate-300 leading-relaxed mb-3 bg-slate-950/40 p-3 rounded-2xl border border-slate-800/40">
        <p className="font-medium">{data.community_verdict}</p>
      </div>

      {/* Past Reviews / Common Complaints */}
      {data.top_complaints && data.top_complaints.length > 0 && (
        <div className="mt-3 pt-3 border-t border-slate-800/60">
          <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block mb-2 flex items-center gap-1.5">
            <AlertTriangle size={12} className={isScam ? "text-rose-400" : "text-amber-400"} />
            {isScam ? "Scam Indicators" : "Common Consumer Grievances"}
          </span>
          <div className="space-y-1.5">
            {data.top_complaints.map((item, i) => (
              <div key={i} className="text-xs text-slate-400 flex items-start gap-2">
                <span className="text-slate-600 mt-0.5">•</span>
                <span className="leading-snug">{item}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
