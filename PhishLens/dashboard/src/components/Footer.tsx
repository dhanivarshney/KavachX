import { BRANDING } from "../config/branding";
import { ShieldCheck, Lock } from "lucide-react";

const CURRENT_YEAR = new Date().getFullYear();

export default function Footer() {
  return (
    <footer className="border-t border-slate-200/80 bg-white mt-auto py-8">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-slate-100">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
              <ShieldCheck size={16} />
            </div>
            <div>
              <span className="font-semibold text-slate-900 text-xs tracking-tight">
                {BRANDING.productName}
              </span>
              <p className="text-[11px] text-slate-500">{BRANDING.tagline}</p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs text-slate-500">
            <span className="inline-flex items-center gap-1.5">
              <Lock size={12} className="text-slate-400" />
              <span>TLS / AI Heuristics</span>
            </span>
            <span>•</span>
            <span>Enterprise Grade</span>
            <span>•</span>
            <span className="font-mono text-[11px]">{BRANDING.version}</span>
          </div>
        </div>

        {/* Disclaimer Note */}
        <div className="pt-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-[11px] text-slate-400">
          <p className="max-w-3xl leading-relaxed">
            {BRANDING.disclaimer}
          </p>
          <div className="text-right shrink-0">
            © {CURRENT_YEAR} {BRANDING.companyName}. All rights reserved.
          </div>
        </div>
      </div>
    </footer>
  );
}
