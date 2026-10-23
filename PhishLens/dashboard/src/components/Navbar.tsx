import { useState, useEffect } from "react";
import { NavLink } from "react-router-dom";
import { ShieldCheck, Globe, MessageSquare, FileText, BarChart3, Menu, X, Activity, ShieldAlert } from "lucide-react";
import { BRANDING } from "../config/branding";
import { getHealth } from "../api/phishlens";

export default function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [systemHealth, setSystemHealth] = useState<"ok" | "degraded" | "checking" | "offline">("checking");

  useEffect(() => {
    let mounted = true;

    async function checkSystemHealth() {
      try {
        const res = await getHealth();
        if (mounted) {
          setSystemHealth(res.status === "ok" ? "ok" : "degraded");
        }
      } catch {
        if (mounted) {
          setSystemHealth("offline");
        }
      }
    }

    checkSystemHealth();
    const interval = setInterval(checkSystemHealth, 30000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { name: "Web Scanner", path: "/", icon: Globe },
    { name: "SMS Guard", path: "/smishing", icon: MessageSquare },
    { name: "Trust Report", path: "/trust-report", icon: FileText },
    { name: "SOS Recovery", path: "/damage-control", icon: ShieldAlert },
    { name: "Analytics", path: "/analytics", icon: BarChart3 },
  ];

  const getLinkClasses = ({ isActive }: { isActive: boolean }) =>
    `inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
      isActive
        ? "bg-slate-900 text-white shadow-sm"
        : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
    }`;

  const getMobileLinkClasses = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-colors ${
      isActive
        ? "bg-slate-900 text-white"
        : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
    }`;

  return (
    <header className="sticky top-0 z-40 bg-white/95 backdrop-blur border-b border-slate-200/80 transition-colors">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand */}
        <NavLink to="/" className="flex items-center gap-3 group focus:outline-none">
          <div className="p-2 rounded-xl bg-blue-600 text-white shadow-sm group-hover:bg-blue-700 transition-colors">
            <ShieldCheck size={20} className="stroke-[2.2]" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-900 text-sm tracking-tight">
                {BRANDING.productName}
              </span>
              <span className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-100/80">
                {BRANDING.version.split(" ")[0]}
              </span>
            </div>
            <span className="text-[11px] text-slate-500 font-normal">
              {BRANDING.descriptor}
            </span>
          </div>
        </NavLink>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-1 bg-slate-100/80 p-1 rounded-xl border border-slate-200/60">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink key={item.path} to={item.path} end={item.path === "/"} className={getLinkClasses}>
                <Icon size={14} className="stroke-[2]" />
                <span>{item.name}</span>
              </NavLink>
            );
          })}
        </nav>

        {/* System Health / Status Indicator */}
        <div className="hidden lg:flex items-center">
          {systemHealth === "ok" ? (
            <div
              title="All threat detection engines and backend services are operational."
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-50/80 border border-emerald-200/80 text-[11px] font-medium text-emerald-800"
            >
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>{BRANDING.statusOperational}</span>
            </div>
          ) : systemHealth === "degraded" ? (
            <div
              title="Backend feedback database or ML model is degraded."
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-50/80 border border-amber-200/80 text-[11px] font-medium text-amber-800"
            >
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              <span>{BRANDING.statusDegraded}</span>
            </div>
          ) : (
            <div
              title="Security engine workspace is running with client-side and cached heuristics."
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-100 border border-slate-200 text-[11px] font-medium text-slate-600"
            >
              <Activity size={12} className="text-slate-400" />
              <span>{BRANDING.statusWorkspace}</span>
            </div>
          )}
        </div>

        {/* Mobile Menu Button */}
        <div className="flex md:hidden items-center gap-2">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation menu"
            className="p-2 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-slate-200 bg-white px-4 pt-2 pb-4 space-y-1 shadow-lg animate-in fade-in duration-150">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === "/"}
                onClick={() => setMobileMenuOpen(false)}
                className={getMobileLinkClasses}
              >
                <Icon size={16} />
                <span>{item.name}</span>
              </NavLink>
            );
          })}
          <div className="pt-3 mt-2 border-t border-slate-100 flex items-center justify-between px-3 text-xs text-slate-500">
            <span>System State:</span>
            <span className="font-medium text-slate-700">
              {systemHealth === "ok"
                ? BRANDING.statusOperational
                : systemHealth === "degraded"
                ? BRANDING.statusDegraded
                : BRANDING.statusWorkspace}
            </span>
          </div>
        </div>
      )}
    </header>
  );
}
