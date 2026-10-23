import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { ShieldCheck, BarChart3, Globe, MessageSquare, Star } from "lucide-react";
import Home from "./pages/Home";
import Stats from "./pages/Stats";
import Smishing from "./pages/Smishing";
import TrustpilotHub from "./pages/TrustpilotHub";

function Navbar() {
  const getNavClass = ({ isActive }: { isActive: boolean }) =>
    `inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
      isActive
        ? "bg-blue-600 text-white shadow-sm shadow-blue-500/20"
        : "text-slate-500 hover:text-slate-800 hover:bg-slate-100"
    }`;

  return (
    <header className="sticky top-0 z-40 bg-white/90 backdrop-blur-xl border-b border-slate-200">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand */}
        <NavLink to="/" className="flex items-center gap-3 group">
          <div className="relative p-2 rounded-xl bg-blue-600 text-white shadow-lg shadow-blue-600/20 group-hover:shadow-blue-600/30 transition-shadow">
            <ShieldCheck size={20} />
            <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-white" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-900 text-sm tracking-tight">PhishLens</span>
              <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded-md bg-blue-50 text-blue-600 border border-blue-100">
                AI v2.4
              </span>
            </div>
            <span className="text-[10px] text-slate-400">Anti-Fraud Detection Platform</span>
          </div>
        </NavLink>

        {/* Nav Links */}
        <nav className="flex items-center gap-1 bg-slate-50 p-1 rounded-2xl border border-slate-200/80">
          <NavLink to="/" end className={getNavClass}>
            <Globe size={13} />
            <span>Web Guard</span>
          </NavLink>
          <NavLink to="/smishing" className={getNavClass}>
            <MessageSquare size={13} />
            <span>SMS Guard</span>
          </NavLink>
          <NavLink to="/trustpilot" className={getNavClass}>
            <Star size={13} />
            <span>Trustpilot</span>
          </NavLink>
          <NavLink to="/stats" className={getNavClass}>
            <BarChart3 size={13} />
            <span>Metrics</span>
          </NavLink>
        </nav>

        {/* Status */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-50 border border-emerald-200 text-[11px] font-semibold text-emerald-700">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          <span>All Shields Active</span>
        </div>
      </div>
    </header>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col bg-slate-50 text-slate-800">
        <Navbar />
        <main className="flex-1 max-w-6xl w-full mx-auto p-4 sm:p-6 lg:p-8">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/smishing" element={<Smishing />} />
            <Route path="/trustpilot" element={<TrustpilotHub />} />
            <Route path="/stats" element={<Stats />} />
          </Routes>
        </main>
        <footer className="border-t border-slate-200 bg-white py-6 text-center text-xs text-slate-400">
          PhishLens AI • Proactive Phishing, Smishing & Fraud Detection Platform
        </footer>
      </div>
    </BrowserRouter>
  );
}
