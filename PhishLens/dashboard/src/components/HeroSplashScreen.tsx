import { useState, useEffect } from "react";
import { Shield, Sparkles, ArrowRight } from "lucide-react";

interface HeroSplashScreenProps {
  onComplete?: () => void;
  durationSeconds?: number;
}

export default function HeroSplashScreen({
  onComplete,
  durationSeconds = 3,
}: HeroSplashScreenProps) {
  const [visible, setVisible] = useState(true);
  const [fading, setFading] = useState(false);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const totalMs = durationSeconds * 1000;
    const intervalMs = 30;
    const step = (intervalMs / totalMs) * 100;

    const progressTimer = setInterval(() => {
      setProgress((prev) => {
        const next = prev + step;
        if (next >= 100) {
          clearInterval(progressTimer);
          return 100;
        }
        return next;
      });
    }, intervalMs);

    const fadeTimer = setTimeout(() => {
      setFading(true);
    }, (durationSeconds - 0.5) * 1000);

    const completeTimer = setTimeout(() => {
      setVisible(false);
      if (onComplete) onComplete();
    }, durationSeconds * 1000);

    return () => {
      clearInterval(progressTimer);
      clearTimeout(fadeTimer);
      clearTimeout(completeTimer);
    };
  }, [durationSeconds, onComplete]);

  if (!visible) return null;

  return (
    <div
      className={`fixed inset-0 z-50 flex flex-col items-center justify-center bg-slate-950 text-white transition-opacity duration-500 overflow-hidden select-none ${
        fading ? "opacity-0 pointer-events-none" : "opacity-100"
      }`}
    >
      {/* Background Cyber Glow & Radial Gradients */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(14,165,233,0.15)_0,transparent_70%)] pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none" />

      {/* Cyber Grid Lines Overlay */}
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage: `linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)`,
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative z-10 flex flex-col items-center text-center px-4 max-w-xl mx-auto space-y-6">
        {/* Logo Container with Glowing Aura */}
        <div className="relative group">
          <div className="absolute -inset-4 bg-gradient-to-r from-cyan-500/30 via-blue-500/30 to-emerald-500/30 rounded-3xl blur-2xl animate-pulse" />
          <div className="relative p-3 rounded-3xl bg-slate-900/90 border border-cyan-500/40 shadow-2xl shadow-cyan-500/20">
            <img
              src="/kavachx-logo.png"
              alt="KavachX Logo"
              className="w-32 h-32 sm:w-40 sm:h-40 object-contain drop-shadow-[0_0_35px_rgba(6,182,212,0.6)]"
            />
          </div>
        </div>

        {/* Project Name - BDA BDA */}
        <div className="space-y-2">
          <h1 className="text-5xl sm:text-7xl font-black tracking-wider uppercase font-mono">
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-300 drop-shadow-md">
              KAVACH
            </span>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-green-500 drop-shadow-[0_0_20px_rgba(52,211,153,0.8)]">
              X
            </span>
          </h1>
          <p className="text-xs sm:text-sm font-mono font-bold tracking-[0.3em] uppercase text-cyan-400">
            SMART SECURITY • STRONG PROTECTION
          </p>
        </div>

        {/* Badge description */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-900/80 border border-slate-800 text-xs text-slate-400 font-mono">
          <Shield size={13} className="text-emerald-400" />
          <span>Next-Gen Anti-Fraud & Phishing Intelligence Platform</span>
          <Sparkles size={13} className="text-cyan-400" />
        </div>

        {/* Progress Bar & Status */}
        <div className="w-full max-w-xs space-y-2 pt-2">
          <div className="flex justify-between items-center text-[11px] font-mono text-slate-400 font-semibold">
            <span className="animate-pulse flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
              Initializing Security Engines...
            </span>
            <span>{Math.min(100, Math.round(progress))}%</span>
          </div>
          <div className="w-full h-1.5 bg-slate-800/80 rounded-full overflow-hidden p-[1px] border border-slate-700/60">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-500 via-blue-500 to-emerald-400 transition-all duration-75 shadow-[0_0_12px_rgba(6,182,212,0.8)]"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Quick Skip Button */}
        <button
          onClick={() => {
            setFading(true);
            setTimeout(() => {
              setVisible(false);
              if (onComplete) onComplete();
            }, 300);
          }}
          className="text-[11px] font-mono text-slate-500 hover:text-slate-300 transition-colors flex items-center gap-1 cursor-pointer pt-2 group"
        >
          <span>Skip into Dashboard</span>
          <ArrowRight size={12} className="group-hover:translate-x-0.5 transition-transform" />
        </button>
      </div>
    </div>
  );
}
