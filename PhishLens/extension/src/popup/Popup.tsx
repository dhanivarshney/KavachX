import { useEffect, useState } from "react";
import browser from "webextension-polyfill";

import { requestBackendAnalysis, submitFeedbackReport } from "../services/analysis-api";
import { DEFAULT_SETTINGS, getExtensionSettings } from "../services/settings";
import type { AnalysisMode, AnalysisResponse, DOMFeatures, ExtensionSettings, PopupAnalysis, RiskLabel } from "../types/analysis";
import { SIGNAL_GLOSSARY } from "../utils/glossary";
import { buildReportSummary } from "../utils/report-summary";
import { analyzeLocally, stripFragment } from "../utils/risk-score";
import { formatSignalScore, groupReasonsBySignal, primarySignalReason } from "../utils/signal-categories";
import "./popup.css";

const EMPTY_DOM_FEATURES: DOMFeatures = {
  has_password_field: false,
  num_forms: 0,
  external_form_action: false,
  num_iframes: 0,
  external_links_ratio: 0,
  has_hidden_inputs: false,
  brand_text_mismatch: false,
  favicon_hotlinked_brand: false,
};

export function Popup() {
  const [analysis, setAnalysis] = useState<PopupAnalysis | null>(null);
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedbackStatus, setFeedbackStatus] = useState<string | null>(null);
  const [reportStatus, setReportStatus] = useState<string | null>(null);
  const [isWebmailTab, setIsWebmailTab] = useState(false);
  const [emailAnalysis, setEmailAnalysis] = useState<any | null>(null);
  const [emailMeta, setEmailMeta] = useState<any | null>(null);
  const [scanningEmail, setScanningEmail] = useState(false);
  const [emailNotice, setEmailNotice] = useState<string | null>(null);

  useEffect(() => {
    void runAnalysis();
  }, []);

  const statusText = analysis ? labelText(analysis.label) : "Checking";
  const statusSymbol = analysis ? labelSymbol(analysis.label) : null;
  const signalGroups = analysis ? groupReasonsBySignal(analysis.reasons, analysis.sources, analysis.risk_breakdown) : [];

  async function scanWebmailEmail() {
    setScanningEmail(true);
    setEmailNotice(null);

    try {
      const tab = await getActiveTab();
      if (!tab?.id) {
        setScanningEmail(false);
        return;
      }

      // Execute live DOM extractor directly inside the active tab
      const results = await browser.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          // ════════════════════════════════════════════════════════════════
          // KavachX Gmail Signal Extractor — reads EVERY available signal
          // ════════════════════════════════════════════════════════════════

          const mainEl = document.querySelector("div[role='main']") as HTMLElement | null;

          // ── Find the EXPANDED / open message container ─────────────────
          // Gmail wraps the expanded message in div.adn.ads
          // If multiple emails in thread, pick the LAST one (most recent = open)
          const allExpanded = mainEl?.querySelectorAll("div.adn.ads");
          const openMsg: HTMLElement | null =
            (allExpanded && allExpanded.length > 0
              ? allExpanded[allExpanded.length - 1]
              : null) as HTMLElement |
            null ||
            mainEl?.querySelector("div[data-message-id]") as HTMLElement ||
            mainEl?.querySelector("div.h7") as HTMLElement ||
            mainEl;

          // ── SIGNAL 1: Is this email in Gmail's SPAM folder? ────────────
          const hash = window.location.hash || "";
          const isSpamFolder = hash.includes("#spam") || hash.includes("/spam") ||
            document.title.toLowerCase().includes("spam");

          // ── SIGNAL 2: Did Gmail flag this as phishing? ─────────────────
          // Gmail shows a red warning box for known phishing emails
          const gmailPhishingWarning = !!(
            document.querySelector(".aH2 .Bs") ||         // classic phishing banner
            document.querySelector("[data-tooltip*='phishing']") ||
            document.querySelector(".md.nH.iY") ||        // spam warning header
            document.querySelector(".Bs.nH.iY") ||        // alt spam warning
            Array.from(document.querySelectorAll(".aH2")).some(
              (el) => el.textContent?.toLowerCase().includes("phishing") ||
                      el.textContent?.toLowerCase().includes("suspicious")
            )
          );

          // ── SIGNAL 3: Subject ──────────────────────────────────────────
          const subjectEl =
            mainEl?.querySelector("h2.hP") ||
            mainEl?.querySelector("h2[data-thread-perm-id]") ||
            mainEl?.querySelector("h2") ||
            document.querySelector("[role='heading'][aria-level='2']");

          let subject = subjectEl?.textContent?.trim() || "";
          if (!subject) {
            const titleFull = document.title || "";
            subject = titleFull
              .replace(/\s*[-–]\s*(Gmail|Inbox|Spam|mail\.google\.com)[^-–]*$/i, "")
              .trim();
          }

          // ── SIGNAL 4: Sender (scoped to open message ONLY) ─────────────
          let senderEmail = "";
          let senderName = "";

          // Strategy A: span[email] in open message wrapper (most reliable)
          const senderSpanInMsg =
            openMsg?.querySelector("span[email]") ||
            openMsg?.querySelector(".gD[email]");
          if (senderSpanInMsg) {
            senderEmail = senderSpanInMsg.getAttribute("email") || "";
            senderName = senderSpanInMsg.getAttribute("name") || senderSpanInMsg.textContent?.trim() || "";
          }

          // Strategy B: .gD scoped to open message
          if (!senderEmail && openMsg) {
            const gdEl = openMsg.querySelector(".gD");
            if (gdEl) {
              senderEmail = gdEl.getAttribute("email") || gdEl.getAttribute("data-hovercard-id") || "";
              senderName = senderName || gdEl.textContent?.trim() || "";
            }
          }

          // Strategy C: data-hovercard-id scoped to open message
          if (!senderEmail && openMsg) {
            const hcEl = openMsg.querySelector("[data-hovercard-id*='@']");
            if (hcEl) {
              senderEmail = hcEl.getAttribute("data-hovercard-id") || "";
              senderName = senderName || hcEl.textContent?.trim() || "";
            }
          }

          // Strategy D: display name fallback
          if (!senderName && openMsg) {
            const nameEl = openMsg.querySelector("span.go") || openMsg.querySelector("h3.iw") || openMsg.querySelector("span.gD");
            senderName = nameEl?.textContent?.trim() || "";
          }

          // Strategy E: regex last resort over open message ONLY
          if (!senderEmail) {
            const msgText = openMsg?.innerText || mainEl?.innerText || "";
            const match = msgText.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
            if (match) senderEmail = match[0];
          }

          // ── SIGNAL 5: "via" third-party sending domain ─────────────────
          // Gmail shows "Sender Name via thirdpartydomain.com" for relayed mail
          // This appears in span.go or the sender header area
          let viaDomain = "";
          if (openMsg) {
            const headerArea = openMsg.querySelector(".gE.iv.gt") || openMsg.querySelector(".g2") || openMsg;
            const headerText = (headerArea as HTMLElement)?.innerText || "";
            const viaMatch = headerText.match(/via\s+([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/i);
            if (viaMatch) viaDomain = viaMatch[1].toLowerCase();

            // Also check the "mailed-by" / "signed-by" span
            const mailedBy = openMsg.querySelector("[data-tooltip*='Mailed by']") ||
                             openMsg.querySelector(".go");
            if (!viaDomain && mailedBy) {
              const mbText = mailedBy.getAttribute("data-tooltip") || mailedBy.textContent || "";
              const mbMatch = mbText.match(/(?:mailed|signed|via)\s+by\s+([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/i);
              if (mbMatch) viaDomain = mbMatch[1].toLowerCase();
            }
          }

          // ── SIGNAL 6: Reply-To (different from sender = major phishing signal) ──
          let replyTo = "";
          if (openMsg) {
            // Gmail sometimes shows the reply-to in the expanded headers
            const allEmailAttrs = openMsg.querySelectorAll("[email]");
            allEmailAttrs.forEach((el) => {
              const e = el.getAttribute("email") || "";
              if (e && e !== senderEmail && e.includes("@")) {
                replyTo = replyTo || e; // first different email = likely reply-to
              }
            });
          }

          // ── SIGNAL 7: Body text ─────────────────────────────────────────
          const bodyEl: HTMLElement | null =
            openMsg?.querySelector("div.a3s") as HTMLElement ||
            openMsg?.querySelector(".a3s.aiL") as HTMLElement ||
            openMsg?.querySelector("div.ii.gt div") as HTMLElement ||
            document.querySelector("div.a3s") as HTMLElement ||
            document.querySelector("div[aria-label='Message body']") as HTMLElement;

          const bodySnippet = bodyEl?.innerText?.slice(0, 2000) || "";

          // ── SIGNAL 8: Embedded links ────────────────────────────────────
          const links: string[] = [];
          if (bodyEl) {
            bodyEl.querySelectorAll("a[href]").forEach((a) => {
              const href = (a as HTMLAnchorElement).href;
              if (href && (href.startsWith("http://") || href.startsWith("https://")) &&
                  !href.includes("mail.google.com") && !href.includes("outlook.live.com")) {
                links.push(href);
              }
            });
          }

          // ── SIGNAL 9: Attachments with dangerous extensions ─────────────
          const dangerousAttachExt = [".exe", ".zip", ".rar", ".bat", ".cmd", ".scr", ".js", ".vbs", ".apk"];
          let hasDangerousAttachment = false;
          const attachArea = openMsg?.querySelector("div.aQH") || document.querySelector("div.aQH");
          if (attachArea) {
            const attachText = (attachArea as HTMLElement).innerText?.toLowerCase() || "";
            hasDangerousAttachment = dangerousAttachExt.some((ext) => attachText.includes(ext));
          }

          return {
            found: Boolean(bodySnippet || senderEmail || subject),
            senderName: senderName.replace(/<[^>]+>/g, "").trim(),
            senderEmail: senderEmail.replace(/<|>/g, "").trim(),
            subject,
            bodySnippet,
            links,
            // Extra Gmail-native signals
            isSpamFolder,
            gmailPhishingWarning,
            viaDomain,
            replyTo,
            hasDangerousAttachment,
          };
        },
      });


      const extracted = results?.[0]?.result as
        | {
            found: boolean;
            senderName: string;
            senderEmail: string;
            subject: string;
            bodySnippet: string;
            links: string[];
            isSpamFolder: boolean;
            gmailPhishingWarning: boolean;
            viaDomain: string;
            replyTo: string;
            hasDangerousAttachment: boolean;
          }
        | undefined;

      if (!extracted || !extracted.found || (!extracted.bodySnippet && !extracted.senderEmail)) {
        setEmailNotice("Open an email thread in Gmail first, then click Scan.");
        setScanningEmail(false);
        return;
      }

      const meta = {
        senderName: extracted.senderName || "Unknown Sender",
        senderEmail: extracted.senderEmail || "",
        subject: extracted.subject || "(No Subject)",
        linksCount: extracted.links.length,
        isSpamFolder: extracted.isSpamFolder,
        gmailFlagged: extracted.gmailPhishingWarning,
      };
      setEmailMeta(meta);

      // Analyze via backend API
      try {
        const response = await fetch("http://localhost:8000/analyze/email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            sender_name: meta.senderName,
            sender_email: meta.senderEmail,
            subject: meta.subject,
            body_snippet: extracted.bodySnippet,
            links: extracted.links,
            // Gmail-native signals
            is_spam_folder: extracted.isSpamFolder,
            gmail_flagged_phishing: extracted.gmailPhishingWarning,
            via_domain: extracted.viaDomain,
            reply_to: extracted.replyTo,
            has_dangerous_attachment: extracted.hasDangerousAttachment,
          }),
        });

        if (response.ok) {
          const data = await response.json();
          setEmailAnalysis(data);

          // Inject or refresh security banner in the Gmail tab
          await browser.scripting.executeScript({
            target: { tabId: tab.id },
            func: (analysisData: any) => {
              const bodyEl = document.querySelector("div.a3s, .a3s.aiL, div.ii.gt");
              if (!bodyEl) return;
              const existing = bodyEl.querySelector(".kavachx-injected-banner");
              if (existing) existing.remove();

              const banner = document.createElement("div");
              banner.className = "kavachx-injected-banner";
              const isDanger = analysisData.risk_label === "dangerous";
              const isSusp = analysisData.risk_label === "suspicious";

              banner.style.cssText = `
                background: ${isDanger ? "#fff1f2" : isSusp ? "#fffbeb" : "#f0fdf4"} !important;
                border: 2px solid ${isDanger ? "#fecdd3" : isSusp ? "#fde68a" : "#bbf7d0"} !important;
                border-radius: 10px !important;
                padding: 12px 16px !important;
                margin: 10px 0 14px 0 !important;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
                box-shadow: 0 4px 12px rgba(0,0,0,0.06) !important;
                display: block !important;
                z-index: 99999 !important;
              `;

              banner.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                  <span style="font-weight:800; font-size:13px; color:#0f172a;">🛡️ KavachX: <span style="color:${
                    isDanger ? "#be123c" : isSusp ? "#b45309" : "#15803d"
                  };">${analysisData.safety_summary}</span></span>
                  <span style="font-size:10px; font-weight:800; padding:2px 8px; border-radius:9999px; background:${
                    isDanger ? "#ffe4e6" : isSusp ? "#fef3c7" : "#dcfce7"
                  }; color:${
                isDanger ? "#be123c" : isSusp ? "#b45309" : "#15803d"
              }; text-transform:uppercase;">Score ${analysisData.threat_score}/100</span>
                </div>
                <div style="font-size:12px; color:#334155; line-height:1.4;">${analysisData.ai_advice}</div>
                <div style="font-size:11px; color:#64748b; margin-top:4px;">Domain Audit: ${
                  analysisData.sender_audit.details
                } • ${analysisData.embedded_links.length} links inspected</div>
              `;

              if (bodyEl.firstChild) {
                bodyEl.insertBefore(banner, bodyEl.firstChild);
              } else {
                bodyEl.appendChild(banner);
              }
            },
            args: [data],
          });
        }
      } catch (backendErr) {
        setEmailNotice("Backend offline. Make sure uvicorn is running on port 8000.");
      }
    } catch (err: any) {
      setEmailNotice(err?.message || "Failed to scan email.");
    } finally {
      setScanningEmail(false);
    }
  }

  async function runAnalysis() {
    setLoading(true);
    setError(null);

    try {
      const tab = await getActiveTab();
      const url = tab?.url;
      const currentSettings = await getExtensionSettings();
      setSettings(currentSettings);

      const isWebmail = Boolean(
        url &&
          (url.includes("mail.google.com") ||
            url.includes("outlook.live.com") ||
            url.includes("outlook.office.com") ||
            url.includes("outlook.office365.com"))
      );
      setIsWebmailTab(isWebmail);

      if (isWebmail) {
        // Proactively scan open email right away
        void scanWebmailEmail();
      }

      if (!tab?.id || !url || !url.startsWith("http")) {
        setError("This page cannot be analyzed by the extension.");
        setLoading(false);
        return;
      }

      const cached = await readCachedAnalysis(url);
      if (cached) {
        setAnalysis({ ...cached, mode: "cached" });
      }

      // The fragment never reaches the backend: it has no analytical value there
      // and can carry OAuth/reset tokens that should stay in the browser.
      const networkUrl = stripFragment(url);
      const domFeatures = await collectDomFeatures(tab.id);
      // Shown while the backend request is in flight, so it is "checking", not a
      // final local-only verdict: the backend is being asked right now.
      const localAnalysis = toPopupAnalysis(networkUrl, analyzeLocally(url, domFeatures), false, "checking");
      setAnalysis(localAnalysis);

      const backendAnalysis = await requestBackendAnalysis(networkUrl, domFeatures, currentSettings);
      if (backendAnalysis) {
        const nextAnalysis = toPopupAnalysis(networkUrl, backendAnalysis, true, "backend-enriched");
        setAnalysis(nextAnalysis);
        await writeCachedAnalysis(url, nextAnalysis);
        await showDangerOverlay(tab.id, nextAnalysis, currentSettings);
      } else {
        const fallbackAnalysis = { ...localAnalysis, mode: "backend-unavailable" as const };
        setAnalysis(fallbackAnalysis);
        await writeCachedAnalysis(url, fallbackAnalysis);
        await showDangerOverlay(tab.id, fallbackAnalysis, currentSettings);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleFeedback(expectedLabel: RiskLabel) {
    if (!analysis) {
      return;
    }

    setFeedbackStatus("Sending feedback...");
    const ok = await submitFeedbackReport(
      {
        url: analysis.url,
        observed_label: analysis.label,
        expected_label: expectedLabel,
      },
      settings,
    );
    setFeedbackStatus(
      ok
        ? `Feedback sent: observed ${analysis.label}, expected ${expectedLabel}. No page content or form values were sent.`
        : "Backend unavailable. Feedback was not sent.",
    );
  }

  async function copyReport() {
    if (!analysis) {
      return;
    }

    try {
      await navigator.clipboard.writeText(buildReportSummary(analysis));
      setReportStatus("Report copied without full URL or page content.");
    } catch {
      setReportStatus("Clipboard unavailable. Try again from the browser popup.");
    }
  }

  function openOptionsPage() {
    void browser.runtime.openOptionsPage();
  }

  function openDashboard() {
    void browser.tabs.create({ url: "http://localhost:5173" });
  }

  return (
    <main className="popup-shell" aria-busy={loading}>
      <header className="header">
        <div>
          <p className="eyebrow">KavachX</p>
          <h1>Website Safety</h1>
        </div>
        <div className="header-actions">
          <button className="tool-button" type="button" aria-label="Open Dashboard" onClick={openDashboard} style={{ background: "#2563eb", color: "#ffffff", fontWeight: 600 }}>
            Dashboard ↗
          </button>
          <button className="tool-button" type="button" aria-label="Open settings" onClick={openOptionsPage}>
            Settings
          </button>
          <button className="tool-button" type="button" aria-label="Refresh analysis" onClick={() => void runAnalysis()}>
            Refresh
          </button>
        </div>
      </header>

      {error ? <div className="notice">{error}</div> : null}
      {analysis ? <div className={`mode-banner ${analysis.mode}`}>{modeBannerText(analysis)}</div> : null}

      {isWebmailTab && (
        <section
          style={{
            margin: "10px 0 14px",
            padding: "14px",
            borderRadius: "10px",
            background:
              emailAnalysis?.risk_label === "dangerous"
                ? "#fff1f2"
                : emailAnalysis?.risk_label === "suspicious"
                ? "#fffbeb"
                : "#f0fdf4",
            border: `1.5px solid ${
              emailAnalysis?.risk_label === "dangerous"
                ? "#fecdd3"
                : emailAnalysis?.risk_label === "suspicious"
                ? "#fde68a"
                : "#bbf7d0"
            }`,
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "8px",
            }}
          >
            <span
              style={{
                fontSize: "12px",
                fontWeight: 700,
                color: "#0f172a",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              <span>✉️</span>
              <span>Webmail Phishing Guard</span>
            </span>
            <button
              type="button"
              onClick={scanWebmailEmail}
              disabled={scanningEmail}
              style={{
                fontSize: "11px",
                fontWeight: 600,
                background: scanningEmail ? "#94a3b8" : "#2563eb",
                color: "#fff",
                border: "none",
                borderRadius: "5px",
                padding: "4px 10px",
                cursor: scanningEmail ? "wait" : "pointer",
                transition: "background 0.2s",
              }}
            >
              {scanningEmail ? "⏳ Scanning Email..." : "🔄 Scan Open Email"}
            </button>
          </div>

          {emailNotice && (
            <div
              style={{
                background: "#fef3c7",
                border: "1px solid #fde68a",
                borderRadius: "6px",
                padding: "6px 10px",
                fontSize: "11px",
                color: "#92400e",
                marginBottom: "8px",
                fontWeight: 600,
              }}
            >
              ⚠️ {emailNotice}
            </div>
          )}

          {emailAnalysis ? (
            <div style={{ fontSize: "11px", color: "#334155", display: "flex", flexDirection: "column", gap: "7px" }}>
              {/* Score + status bar */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontWeight: 700, fontSize: "12px" }}>
                  {emailAnalysis.safety_summary}
                </span>
                <span style={{
                  padding: "2px 8px",
                  borderRadius: "9999px",
                  fontWeight: 800,
                  fontSize: "10px",
                  background: emailAnalysis.risk_label === "dangerous" ? "#ffe4e6" : emailAnalysis.risk_label === "suspicious" ? "#fef3c7" : "#dcfce7",
                  color: emailAnalysis.risk_label === "dangerous" ? "#be123c" : emailAnalysis.risk_label === "suspicious" ? "#b45309" : "#15803d",
                }}>
                  {emailAnalysis.threat_score}/100
                </span>
              </div>

              {/* Score progress bar */}
              <div style={{ height: "6px", borderRadius: "9999px", background: "#e2e8f0", overflow: "hidden" }}>
                <div style={{
                  height: "100%",
                  width: `${emailAnalysis.threat_score}%`,
                  background: emailAnalysis.risk_label === "dangerous" ? "#be123c" : emailAnalysis.risk_label === "suspicious" ? "#d97706" : "#16a34a",
                  borderRadius: "9999px",
                  transition: "width 0.4s ease",
                }} />
              </div>

              {/* Signal breakdown */}
              {emailAnalysis.signal_breakdown && (
                <div style={{ background: "#f8fafc", borderRadius: "8px", padding: "8px", border: "1px solid #e2e8f0" }}>
                  <div style={{ fontWeight: 700, marginBottom: "5px", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.05em", color: "#64748b" }}>
                    Signal Breakdown
                  </div>
                  {[
                    { key: "sender_domain_signals", label: "Sender Domain" },
                    { key: "subject_signals", label: "Subject" },
                    { key: "body_language_signals", label: "Body Language" },
                    { key: "gmail_context_signals", label: "Gmail Context" },
                    { key: "link_threat_signals", label: "Embedded Links" },
                  ].map(({ key, label }) => {
                    const val = (emailAnalysis.signal_breakdown as any)[key] as number;
                    const pct = Math.min((val / 50) * 100, 100);
                    const barColor = val >= 25 ? "#be123c" : val >= 10 ? "#d97706" : val > 0 ? "#2563eb" : "#16a34a";
                    return (
                      <div key={key} style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "3px" }}>
                        <span style={{ width: "90px", flexShrink: 0, color: "#475569", fontSize: "10px" }}>{label}</span>
                        <div style={{ flex: 1, height: "5px", background: "#e2e8f0", borderRadius: "9999px", overflow: "hidden" }}>
                          <div style={{ width: `${pct}%`, height: "100%", background: barColor, borderRadius: "9999px" }} />
                        </div>
                        <span style={{ width: "24px", textAlign: "right", fontWeight: 700, color: barColor, fontSize: "10px" }}>{val}</span>
                      </div>
                    );
                  })}
                </div>
              )}


              {/* Sender info */}
              {emailMeta && (
                <div style={{ background: "#f1f5f9", borderRadius: "7px", padding: "7px 9px", lineHeight: 1.5 }}>
                  <div><strong>From:</strong> {emailMeta.senderName || "—"} &lt;{emailMeta.senderEmail || "unknown"}&gt;</div>
                  <div><strong>Subject:</strong> {emailMeta.subject || "(No Subject)"}</div>
                  <div style={{ display: "flex", gap: "6px", marginTop: "4px", flexWrap: "wrap" }}>
                    <span><strong>Links:</strong> {emailMeta.linksCount}</span>
                    {emailMeta.isSpamFolder && (
                      <span style={{ padding: "1px 7px", borderRadius: "9999px", background: "#fef3c7", color: "#92400e", fontSize: "10px", fontWeight: 700 }}>
                        📂 In Spam Folder
                      </span>
                    )}
                    {emailMeta.gmailFlagged && (
                      <span style={{ padding: "1px 7px", borderRadius: "9999px", background: "#ffe4e6", color: "#be123c", fontSize: "10px", fontWeight: 700 }}>
                        🚩 Gmail Flagged Phishing
                      </span>
                    )}
                  </div>
                </div>
              )}


              {/* Spoofing warning */}
              {emailAnalysis.sender_audit?.is_spoofed && (
                <div style={{ color: "#b91c1c", fontWeight: 700, background: "#fff1f2", padding: "6px 8px", borderRadius: "6px", border: "1px solid #fecdd3" }}>
                  🚨 Impersonation Detected: {emailAnalysis.sender_audit.details}
                </div>
              )}

              {/* Sender domain note (non-spoofed) */}
              {!emailAnalysis.sender_audit?.is_spoofed && emailAnalysis.sender_audit?.details && (
                <div style={{ color: "#475569", fontSize: "10px" }}>
                  🔍 Domain: {emailAnalysis.sender_audit.details}
                </div>
              )}

              {/* Detected traps */}
              {emailAnalysis.detected_traps?.length > 0 && (
                <div style={{ color: "#9a3412", fontWeight: 600, background: "#fff7ed", padding: "6px 8px", borderRadius: "6px", border: "1px solid #fed7aa" }}>
                  ⚡ Phishing Signals: {emailAnalysis.detected_traps.join(" • ")}
                </div>
              )}

              {/* AI Advice */}
              <div style={{ background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: "7px", padding: "7px 9px", lineHeight: 1.5, color: "#1e293b" }}>
                {emailAnalysis.ai_advice}
              </div>

              {/* SOS button */}
              <div>
                <a
                  href="http://localhost:5173/damage-control"
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: "inline-block",
                    padding: "5px 12px",
                    background: "#e11d48",
                    color: "#fff",
                    textDecoration: "none",
                    borderRadius: "6px",
                    fontSize: "10px",
                    fontWeight: 700,
                  }}
                >
                  🆘 Open SOS Incident Recovery
                </a>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: "11px", color: "#64748b", lineHeight: 1.4 }}>
              Active on webmail. Open any email message in Gmail to view real-time phishing and spoofing analysis.
            </div>
          )}
        </section>
      )}


      <section
        className={`risk-panel ${analysis?.label ?? "safe"}`}
        aria-live="polite"
        aria-atomic="true"
        aria-label={analysis ? `Risk level: ${statusText}, score ${analysis.risk_score} out of 100` : "Awaiting analysis"}
      >
        <div>
          <span className="status">
            {statusSymbol ? <span className="status-symbol" aria-hidden="true">{statusSymbol}</span> : null}
            {statusText}
          </span>
          <strong className="score">{analysis?.risk_score ?? "--"}</strong>
        </div>
        <span className="score-label" aria-hidden="true">risk score</span>
      </section>

      <section className="details">
        <div className="url-block">
          <span>URL</span>
          <p>{analysis?.url ?? "Waiting for active tab..."}</p>
        </div>

        <div className="meta-grid">
          <div>
            <span>Confidence</span>
            <strong title={analysis && !analysis.sources.ml ? HEURISTIC_CONFIDENCE_NOTE : undefined}>
              {confidenceDisplay(analysis)}
            </strong>
          </div>
          <div>
            <span>Backend</span>
            <strong>{analysis ? modeLabel(analysis.mode) : "--"}</strong>
          </div>
        </div>
        {analysis ? (
          <div className="source-list" aria-label="Analysis sources">
            {sourceList(analysis).map((source) => (
              <span key={source}>{source}</span>
            ))}
          </div>
        ) : null}
      </section>

      <section className="reasons">
        <h2>Safety Checks</h2>
        {loading && !analysis ? <p className="muted">Analyzing current page...</p> : null}
        {analysis ? <p className="primary-signal">{primarySignalReason(signalGroups)}</p> : null}
        <div className="signal-groups">
          {signalGroups.map((group) => (
            <section className="signal-group" key={group.id}>
              <h3>
                <span title={SIGNAL_GLOSSARY[group.id]}>{group.title}</span>
                <strong>{formatSignalScore(group)}</strong>
              </h3>
              <ul>
                {group.reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </section>

      <section className="feedback">
        <h2>Feedback</h2>
        <div className="feedback-actions">
          <button type="button" disabled={!analysis} onClick={() => void handleFeedback("safe")}>
            Mark as safe
          </button>
          <button type="button" disabled={!analysis} onClick={() => void handleFeedback("dangerous")}>
            Report as Scam
          </button>
        </div>
        {feedbackStatus ? <p role="status">{feedbackStatus}</p> : null}
      </section>

      <section className="report-copy">
        <h2>Report</h2>
        <button type="button" disabled={!analysis} onClick={() => void copyReport()}>
          Copy Safety Summary
        </button>
        {reportStatus ? <p role="status">{reportStatus}</p> : null}
      </section>
    </main>
  );
}

// Tab type comes from @types/chrome (kept alongside the polyfill purely for
// this MV3-shaped type — the value itself comes from browser.tabs at runtime,
// which is interchangeable in both engines).
async function getActiveTab(): Promise<chrome.tabs.Tab | undefined> {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0] as chrome.tabs.Tab | undefined;
}

function isDOMFeatures(obj: unknown): obj is DOMFeatures {
  if (typeof obj !== "object" || obj === null) return false;
  const c = obj as Record<string, unknown>;
  return (
    typeof c.has_password_field === "boolean" &&
    typeof c.num_forms === "number" &&
    typeof c.external_form_action === "boolean" &&
    typeof c.num_iframes === "number" &&
    typeof c.external_links_ratio === "number" &&
    typeof c.has_hidden_inputs === "boolean" &&
    typeof c.brand_text_mismatch === "boolean" &&
    typeof c.favicon_hotlinked_brand === "boolean"
  );
}

async function collectDomFeatures(tabId: number): Promise<DOMFeatures> {
  try {
    const response = (await browser.tabs.sendMessage(tabId, { type: "PHISHLENS_COLLECT_DOM" })) as
      | { ok?: boolean; dom_features?: unknown }
      | undefined;
    if (!response?.ok || !isDOMFeatures(response.dom_features)) {
      return EMPTY_DOM_FEATURES;
    }
    return response.dom_features;
  } catch {
    // The content script isn't injected on this page (e.g. chrome://, the
    // Web Store) — browser.tabs.sendMessage rejects instead of setting
    // chrome.runtime.lastError when promise-based.
    return EMPTY_DOM_FEATURES;
  }
}

function toPopupAnalysis(
  url: string,
  response: AnalysisResponse,
  backendAvailable: boolean,
  mode: AnalysisMode,
): PopupAnalysis {
  return {
    ...response,
    url,
    backendAvailable,
    mode,
    analyzedAt: new Date().toISOString(),
  };
}

async function readCachedAnalysis(url: string): Promise<PopupAnalysis | null> {
  const key = await cacheKey(url);
  const items = await browser.storage.local.get([key]);
  const cached = items[key] as PopupAnalysis | undefined;
  if (!cached) {
    return null;
  }

  const ageMs = Date.now() - new Date(cached.analyzedAt).getTime();
  if (ageMs >= 5 * 60 * 1000) {
    await browser.storage.local.remove([key]);
    return null;
  }
  return cached;
}

function stripSensitiveUrlParts(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return url.split("?")[0].split("#")[0];
  }
}

async function writeCachedAnalysis(url: string, value: PopupAnalysis): Promise<void> {
  const key = await cacheKey(url);
  // The key is already a hash of the full URL. Strip query string and fragment
  // from the persisted value so tokens in query params are not stored at rest.
  const sanitized: PopupAnalysis = { ...value, url: stripSensitiveUrlParts(url) };
  await browser.storage.local.set({ [key]: sanitized });
}

export async function cacheKey(url: string): Promise<string> {
  const data = new TextEncoder().encode(url);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hex = Array.from(new Uint8Array(hashBuffer), (b) => b.toString(16).padStart(2, "0")).join("");
  return `analysis:${hex.slice(0, 16)}`;
}

// The heuristic-only confidence formula is measurably overconfident (a
// reliability diagram against the committed dataset put the ~0.90 bin, which
// holds most rows, at ~52% real accuracy — see docs/ml-methodology.md). So the
// popup only shows a numeric confidence when the ML model actually contributed;
// otherwise it shows "Heuristic" rather than presenting an uncalibrated number
// as a probability.
export const HEURISTIC_CONFIDENCE_NOTE =
  "Heuristic-only signals do not produce a calibrated probability. This reflects how strongly signals fired, not a likelihood. See the ML methodology docs.";

export function confidenceDisplay(analysis: PopupAnalysis | null): string {
  if (!analysis) {
    return "--";
  }
  if (!analysis.sources.ml) {
    return "Heuristic";
  }
  return `${Math.round(analysis.confidence * 100)}%`;
}

export function modeLabel(mode: AnalysisMode): string {
  if (mode === "backend-enriched") {
    return "Backend enriched";
  }
  if (mode === "backend-unavailable") {
    return "Backend unavailable";
  }
  if (mode === "cached") {
    return "Cached";
  }
  return "Checking";
}

export function modeBannerText(analysis: PopupAnalysis): string {
  if (analysis.mode === "backend-enriched") {
    return "Backend enrichment is active for this result.";
  }
  if (analysis.mode === "backend-unavailable") {
    const skipped: string[] = [];
    if (!analysis.sources.tls) skipped.push("TLS");
    if (!analysis.sources.phishtank) skipped.push("threat intelligence");
    if (!analysis.sources.domain_age) skipped.push("domain age");
    if (!analysis.sources.ml) skipped.push("ML");
    const suffix = skipped.length > 0 ? ` ${skipped.join(", ")} ${skipped.length === 1 ? "was" : "were"} not checked.` : "";
    return `Backend unavailable — showing local heuristic analysis.${suffix}`;
  }
  if (analysis.mode === "cached") {
    return "Showing a recent cached result while refreshing.";
  }
  return "Local result. Waiting for backend enrichment...";
}

export function sourceList(analysis: PopupAnalysis): string[] {
  const sources = ["heuristics"];
  if (analysis.sources.tls) {
    sources.push("tls");
  }
  if (analysis.sources.phishtank) {
    sources.push("phishtank");
  }
  if (analysis.sources.domain_age) {
    sources.push("domain age");
  }
  if (analysis.sources.ml) {
    sources.push("ml");
  }
  if (analysis.sources.demo) {
    sources.push("demo");
  }
  return sources;
}

export function labelText(label: RiskLabel): string {
  if (label === "dangerous") {
    return "Dangerous";
  }
  if (label === "suspicious") {
    return "Suspicious";
  }
  return "Safe";
}

export function labelSymbol(label: RiskLabel): string {
  if (label === "dangerous") {
    return "✕";
  }
  if (label === "suspicious") {
    return "!";
  }
  return "✓";
}

async function showDangerOverlay(
  tabId: number,
  value: PopupAnalysis,
  currentSettings: ExtensionSettings,
): Promise<void> {
  if (!currentSettings.dangerOverlayEnabled || value.label !== "dangerous") {
    return;
  }

  await executeScript(tabId, "warning/overlay.js");
  await sendOverlayMessage(tabId, {
    type: "PHISHLENS_SHOW_WARNING",
    riskScore: value.risk_score,
    reasons: value.reasons.slice(0, 4),
  });
}

async function executeScript(tabId: number, file: string): Promise<void> {
  // Same passthrough situation as browser.action: webextension-polyfill
  // predates `scripting`, but both engines support it as a native Promise
  // API already.
  await browser.scripting.executeScript({ target: { tabId }, files: [file] });
}

async function sendOverlayMessage(tabId: number, message: unknown): Promise<void> {
  await browser.tabs.sendMessage(tabId, message);
}
