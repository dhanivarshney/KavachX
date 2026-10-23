import { useEffect, useState } from "react";
import { Star, ExternalLink, ShieldAlert, CheckCircle2, MessageSquare, AlertTriangle } from "lucide-react";
import { getTrustpilotReputation } from "../api/phishlens";
import type { TrustpilotResponse } from "../api/phishlens";

interface TrustpilotCardProps {
  domain: string;
}

export default function TrustpilotCard({ domain }: TrustpilotCardProps) {
  const [data, setData] = useState<TrustpilotResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(Boolean(domain));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!domain) return;
    let cancelled = false;

    // Extract bare hostname if full URL was passed
    let cleanHost = domain;
    try {
      if (domain.startsWith("http://") || domain.startsWith("https://")) {
        cleanHost = new URL(domain).hostname;
      }
    } catch {
      cleanHost = domain;
    }

    getTrustpilotReputation(cleanHost)
      .then((res) => {
        if (!cancelled) {
          setData(res);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message);
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [domain]);

  if (loading) {
    return (
      <div className="rounded-2xl border border-slate-200/90 bg-white p-5 shadow-card animate-pulse space-y-3">
        <div className="h-4 bg-slate-100 rounded w-1/4"></div>
        <div className="h-6 bg-slate-100 rounded w-1/3"></div>
        <div className="h-10 bg-slate-100 rounded"></div>
      </div>
    );
  }

  if (error || !data) {
    return null;
  }

  const isScam = data.is_unverified_scam_indicator;

  return (
    <div
      className={`rounded-2xl border p-5 sm:p-6 shadow-card transition-all ${
        isScam
          ? "bg-rose-50/20 border-rose-200"
          : "bg-white border-slate-200/90"
      }`}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-4">
        <div className="flex items-center gap-3">
          <div
            className={`p-2 rounded-xl shrink-0 ${
              isScam
                ? "bg-rose-100 text-rose-700 border border-rose-200"
                : "bg-blue-50 text-blue-700 border border-blue-100"
            }`}
          >
            {isScam ? <ShieldAlert size={18} /> : <CheckCircle2 size={18} />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Community Reputation
              </span>
              <span
                className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                  isScam
                    ? "bg-rose-50 text-rose-700 border-rose-200"
                    : "bg-emerald-50 text-emerald-700 border-emerald-200"
                }`}
              >
                {isScam ? "Unverified / Zero-Day Target" : "Established Footprint"}
              </span>
            </div>
            <h3 className="text-sm font-semibold text-slate-900 mt-0.5">
              Consumer Trust Intelligence
            </h3>
          </div>
        </div>

        {data.trustpilot_url && (
          <a
            href={data.trustpilot_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200/80 px-2.5 py-1 rounded-lg border border-slate-200 transition-colors"
          >
            <span>View Source</span>
            <ExternalLink size={12} />
          </a>
        )}
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4 p-3 rounded-xl bg-slate-50 border border-slate-200/60">
        <div>
          <span className="text-[11px] text-slate-500 block">Trust Rating</span>
          <div className="flex items-center gap-1.5 mt-0.5">
            <div className="flex text-amber-400">
              {[1, 2, 3, 4, 5].map((star) => (
                <Star
                  key={star}
                  size={13}
                  className={star <= data.star_rating ? "fill-amber-400" : "text-slate-300"}
                />
              ))}
            </div>
            <span className="text-xs font-semibold text-slate-900 font-sans">
              {data.star_rating > 0 ? `${data.trust_score.toFixed(1)} / 5` : "N/A"}
            </span>
          </div>
        </div>

        <div>
          <span className="text-[11px] text-slate-500 block">Community Reviews</span>
          <div className="flex items-center gap-1.5 mt-0.5">
            <MessageSquare size={13} className="text-slate-400" />
            <span className="text-xs font-semibold text-slate-800">{data.total_reviews}</span>
          </div>
        </div>

        <div>
          <span className="text-[11px] text-slate-500 block">Trust Classification</span>
          <span
            className={`text-xs font-semibold ${
              isScam ? "text-rose-600" : "text-emerald-700"
            }`}
          >
            {data.rating_label}
          </span>
        </div>
      </div>

      {/* Community Verdict Text */}
      <div className="text-xs text-slate-700 leading-relaxed mb-3 bg-white p-3 rounded-xl border border-slate-200/60">
        <p className="font-normal">{data.community_verdict}</p>
      </div>

      {/* Complaints or Indicators */}
      {data.top_complaints && data.top_complaints.length > 0 && (
        <div className="pt-2 border-t border-slate-100">
          <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-2 flex items-center gap-1.5">
            <AlertTriangle size={12} className={isScam ? "text-rose-500" : "text-amber-500"} />
            {isScam ? "Key Risk Indicators" : "Reported Consumer Concerns"}
          </span>
          <div className="space-y-1">
            {data.top_complaints.map((item, i) => (
              <div key={i} className="text-xs text-slate-600 flex items-start gap-2">
                <span className="text-slate-400 mt-0.5">•</span>
                <span className="leading-snug">{item}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
