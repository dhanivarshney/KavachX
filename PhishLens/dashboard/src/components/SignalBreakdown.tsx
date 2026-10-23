import { useState } from "react";
import type { RiskBreakdownItem } from "../api/phishlens";
import {
  Link2,
  LayoutTemplate,
  ShieldAlert,
  Lock,
  Calendar,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

interface Props {
  breakdown: RiskBreakdownItem[];
}

interface CategoryDefinition {
  title: string;
  oneLiner: string;
  icon: typeof Link2;
}

const CATEGORY_DEFINITIONS: Record<string, CategoryDefinition> = {
  url: {
    title: "Web Address Check",
    oneLiner: "Inspects brand look-alikes, character entropy, misleading subdomains, and typosquatting.",
    icon: Link2,
  },
  dom: {
    title: "Page Content & Forms",
    oneLiner: "Inspects credential collection fields, login forms, hidden inputs, and unauthorized iframe frames.",
    icon: LayoutTemplate,
  },
  threat_intel: {
    title: "Scam Blacklist Check",
    oneLiner: "Cross-checks the domain against verified threat feeds and known phishing databases.",
    icon: ShieldAlert,
  },
  tls: {
    title: "Website Security Check",
    oneLiner: "Verifies SSL/TLS encryption certificates and transport layer trustworthiness.",
    icon: Lock,
  },
  domain_age: {
    title: "Domain Age Check",
    oneLiner: "Checks domain registration age; newly registered domains present heightened risk.",
    icon: Calendar,
  },
  ml: {
    title: "AI / Machine Learning Analysis",
    oneLiner: "Evaluates lexical, structural, and semantic threat distributions using predictive modeling.",
    icon: Cpu,
  },
};

function humanizeReason(reason: string): string {
  let r = reason;
  r = r.replace(/Domain closely resembles (.*?) \(possible typosquatting\)/i, "Look-alike spelling closely mimics '$1' to mislead users");
  r = r.replace(/Deceptive combosquatting: impersonates (.*?) alongside credential lure keywords/i, "Combosquatting: Replicates brand '$1' combined with sensitive login keywords");
  r = r.replace(/Domain or path contains suspicious keywords/i, "Web address contains high-risk authentication lure words (e.g. login, verify, update)");
  r = r.replace(/Domain has high character entropy/i, "Web address contains scrambled or randomly generated characters");
  r = r.replace(/TLS certificate could not be validated/i, "Security certificate could not be established or verified");
  r = r.replace(/URL contains multiple hyphens/i, "Web address contains an abnormal frequency of hyphens (-)");
  r = r.replace(/URL is unusually long/i, "Web address length is unusually long (>75 characters)");
  r = r.replace(/URL uses an IP address as the domain/i, "Uses raw IP address instead of a registered domain name");
  r = r.replace(/URL contains an @ symbol/i, "Contains an '@' character commonly used in URL obfuscation");
  r = r.replace(/Page contains a password field/i, "Document contains a password input field");
  r = r.replace(/Page contains forms/i, "Page contains interactive submission forms");
  r = r.replace(/Machine learning model reduced the estimated risk/i, "Predictive model confirmed lexical indicators consistent with legitimate domains");
  return r;
}

export function SignalBreakdown({ breakdown }: Props) {
  const [expandedKeys, setExpandedKeys] = useState<Record<string, boolean>>({});

  const toggleExpand = (cat: string) => {
    setExpandedKeys((prev) => ({ ...prev, [cat]: !prev[cat] }));
  };

  // Ensure all standard 6 checks are displayed even if not yet present in partial breakdown
  const order = ["url", "dom", "threat_intel", "tls", "domain_age", "ml"];

  // Create a unified lookup
  const breakdownMap = new Map<string, RiskBreakdownItem>();
  for (const item of breakdown) {
    breakdownMap.set(item.category, item);
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-100">
        <div>
          <h3 className="text-sm font-semibold text-slate-900 tracking-tight">
            Security Vector Breakdown
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Individual evaluations across 6 inspection layers
          </p>
        </div>
        <span className="text-[11px] font-medium text-slate-500 bg-slate-100 px-2.5 py-1 rounded-lg">
          {breakdown.length} Vectors Audited
        </span>
      </div>

      <div className="space-y-3">
        {order.map((key) => {
          const item = breakdownMap.get(key);
          const meta = CATEGORY_DEFINITIONS[key] ?? {
            title: key,
            oneLiner: "Security evaluation layer",
            icon: ShieldAlert,
          };
          const Icon = meta.icon;
          const isExpanded = Boolean(expandedKeys[key]);

          // Status calculation
          let statusLabel = "No Threat Detected";
          let statusBadgeClass = "bg-emerald-50 text-emerald-700 border-emerald-200";
          let StatusIcon = CheckCircle2;
          let isWarning = false;
          let isDanger = false;

          if (!item) {
            statusLabel = "Not Evaluated";
            statusBadgeClass = "bg-slate-50 text-slate-500 border-slate-200";
            StatusIcon = HelpCircle;
          } else if (item.score > (item.max_score * 0.5)) {
            statusLabel = "High Risk Flagged";
            statusBadgeClass = "bg-rose-50 text-rose-700 border-rose-200";
            StatusIcon = XCircle;
            isDanger = true;
          } else if (item.score > 0) {
            statusLabel = "Caution Advised";
            statusBadgeClass = "bg-amber-50 text-amber-700 border-amber-200";
            StatusIcon = AlertTriangle;
            isWarning = true;
          }

          return (
            <div
              key={key}
              className={`rounded-xl border transition-all duration-200 ${
                isDanger
                  ? "bg-rose-50/20 border-rose-200/90"
                  : isWarning
                  ? "bg-amber-50/20 border-amber-200/90"
                  : "bg-white border-slate-200/90 hover:border-slate-300"
              }`}
            >
              <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                {/* Left: Icon & Description */}
                <div className="flex items-start gap-3">
                  <div
                    className={`p-2 rounded-lg shrink-0 mt-0.5 ${
                      isDanger
                        ? "bg-rose-100 text-rose-700"
                        : isWarning
                        ? "bg-amber-100 text-amber-700"
                        : "bg-slate-100 text-slate-700"
                    }`}
                  >
                    <Icon size={16} className="stroke-[2.2]" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-900 text-xs">
                        {meta.title}
                      </span>
                      {item && (
                        <span className="text-[10px] font-mono font-medium text-slate-500">
                          (Score: {item.score}/{item.max_score})
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 leading-snug">
                      {meta.oneLiner}
                    </p>
                  </div>
                </div>

                {/* Right: Status Pill & Accordion Toggle */}
                <div className="flex items-center gap-2 self-start sm:self-center shrink-0">
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium border ${statusBadgeClass}`}
                  >
                    <StatusIcon size={12} className="stroke-[2.5]" />
                    <span>{statusLabel}</span>
                  </span>

                  {item && (
                    <button
                      onClick={() => toggleExpand(key)}
                      aria-expanded={isExpanded}
                      className="p-1 rounded-lg hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors cursor-pointer"
                      title={isExpanded ? "Hide technical details" : "Show technical details"}
                    >
                      {isExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                    </button>
                  )}
                </div>
              </div>

              {/* Finding Reasons (Always visible if red flags exist) */}
              {item && item.reasons.length > 0 && (
                <div className="px-4 pb-3.5 pt-1 space-y-1.5 border-t border-slate-100/80">
                  <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400">
                    Detected Signals:
                  </span>
                  {item.reasons.map((r, i) => (
                    <div
                      key={i}
                      className="text-xs text-slate-700 flex items-start gap-2 bg-slate-50/80 p-2 rounded-lg border border-slate-200/50"
                    >
                      <span
                        className={`font-bold mt-0.5 ${
                          isDanger ? "text-rose-600" : "text-amber-600"
                        }`}
                      >
                        •
                      </span>
                      <span className="leading-relaxed">{humanizeReason(r)}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Technical Accordion Details */}
              {isExpanded && item && (
                <div className="px-4 py-3 bg-slate-50/60 border-t border-slate-100 text-xs font-mono text-slate-600 space-y-1 rounded-b-xl">
                  <div className="flex justify-between py-0.5">
                    <span className="text-slate-500">Telemetry Source:</span>
                    <span className="font-semibold text-slate-800">{item.source}</span>
                  </div>
                  <div className="flex justify-between py-0.5">
                    <span className="text-slate-500">Risk Weight Allocation:</span>
                    <span className="font-semibold text-slate-800">
                      {item.score} pts (Range: {item.min_score ?? 0} to {item.max_score})
                    </span>
                  </div>
                  <div className="flex justify-between py-0.5">
                    <span className="text-slate-500">Vector Category:</span>
                    <span className="font-semibold text-slate-800">{item.category}</span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
