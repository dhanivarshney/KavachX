import type { RiskBreakdownItem } from "../api/phishlens";
import { Link2, LayoutTemplate, ShieldAlert, Lock, Calendar, Cpu } from "lucide-react";

interface Props {
  breakdown: RiskBreakdownItem[];
}

const CATEGORY_META: Record<string, { label: string; desc: string; color: string; icon: any }> = {
  url: { label: "Web Address Check", desc: "Checks for misspelled brand names, look-alike letters, or fake links", color: "bg-orange-500", icon: Link2 },
  dom: { label: "Page Content & Forms", desc: "Checks if the page asks for passwords or hides secret fields", color: "bg-purple-500", icon: LayoutTemplate },
  threat_intel: { label: "Scam Blacklist Check", desc: "Checks global databases of reported scam websites", color: "bg-rose-500", icon: ShieldAlert },
  tls: { label: "Security Lock (SSL)", desc: "Checks if the connection is safely encrypted", color: "bg-sky-500", icon: Lock },
  domain_age: { label: "Website Age", desc: "New websites created just days ago are much riskier", color: "bg-amber-500", icon: Calendar },
  ml: { label: "AI Pattern Matcher", desc: "Uses smart AI to spot patterns common to fake websites", color: "bg-indigo-600", icon: Cpu },
};

function humanizeReason(reason: string): string {
  let r = reason;
  r = r.replace(/Domain closely resembles (.*?) \(possible typosquatting\)/i, "Look-alike name: Spelled almost like $1 to trick you");
  r = r.replace(/Deceptive combosquatting: impersonates (.*?) alongside credential lure keywords/i, "Fake replica: Copies $1 name while asking for verification or login");
  r = r.replace(/Domain or path contains suspicious keywords/i, "Contains words often used in scams (like login, verify, update, alert)");
  r = r.replace(/Domain has high character entropy/i, "Web address has scrambled or random letters");
  r = r.replace(/TLS certificate could not be validated/i, "Website does not have a trusted security certificate");
  r = r.replace(/URL contains multiple hyphens/i, "Web address has unusually many dashes (-)");
  r = r.replace(/URL is unusually long/i, "Web address is unusually long");
  r = r.replace(/URL uses an IP address as the domain/i, "Uses numbers instead of a real website name");
  r = r.replace(/URL contains an @ symbol/i, "Contains an '@' symbol, often used to hide the real destination");
  r = r.replace(/Page contains a password field/i, "Page asks you to enter a password");
  r = r.replace(/Page contains forms/i, "Page contains forms to collect your information");
  r = r.replace(/Machine learning model reduced the estimated risk/i, "AI verified that parts of this site look normal");
  return r;
}

export function SignalBreakdown({ breakdown }: Props) {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between border-b border-slate-100 pb-3">
        <div>
          <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider">Safety Breakdown</h3>
          <p className="text-[11px] text-slate-400">Everything we checked on this website</p>
        </div>
        <span className="text-xs font-semibold text-slate-400">Risk Level</span>
      </div>
      <div className="grid gap-3">
        {breakdown.map((item) => {
          const meta = CATEGORY_META[item.category] ?? { label: item.category, desc: "Security check", color: "bg-slate-400", icon: ShieldAlert };
          const Icon = meta.icon;
          const range = item.max_score - (item.min_score ?? 0);
          const offset = item.score - (item.min_score ?? 0);
          const pct = range > 0 ? Math.min(100, Math.max(0, (offset / range) * 100)) : 0;
          const isSafe = item.score <= 0;
          const isHighRisk = item.score >= item.max_score * 0.6;

          return (
            <div key={item.category} className="bg-slate-50 rounded-2xl p-4 border border-slate-200/80 hover:border-slate-300 transition-colors">
              <div className="flex items-start justify-between text-xs mb-2">
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-xl text-white ${meta.color} mt-0.5 shrink-0 shadow-sm`}><Icon size={14} /></div>
                  <div>
                    <span className="font-bold text-slate-800 text-xs block">{meta.label}</span>
                    <span className="text-[11px] text-slate-400 block">{meta.desc}</span>
                  </div>
                </div>
                <span className={`font-mono text-xs font-bold ${isSafe ? "text-emerald-600" : isHighRisk ? "text-rose-600" : "text-amber-600"}`}>
                  {isSafe ? "Passed" : `+${item.score} risk`}
                </span>
              </div>
              <div className="w-full bg-slate-200 rounded-full h-1.5 overflow-hidden mt-2">
                <div className={`h-full rounded-full ${isSafe ? "bg-emerald-500" : meta.color} transition-all duration-700`} style={{ width: `${Math.max(5, pct)}%` }} />
              </div>
              {item.reasons.length > 0 && (
                <div className="mt-3 pt-2 border-t border-slate-100 space-y-1">
                  {item.reasons.map((r, i) => (
                    <div key={i} className="text-[11px] text-slate-600 flex items-start gap-2">
                      <span className="text-rose-500 font-bold shrink-0">•</span>
                      <span className="leading-snug">{humanizeReason(r)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
