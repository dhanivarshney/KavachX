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

  useEffect(() => {
    void runAnalysis();
  }, []);

  const statusText = analysis ? labelText(analysis.label) : "Checking";
  const statusSymbol = analysis ? labelSymbol(analysis.label) : null;
  const signalGroups = analysis ? groupReasonsBySignal(analysis.reasons, analysis.sources, analysis.risk_breakdown) : [];

  async function scanWebmailEmail() {
    try {
      const tab = await getActiveTab();
      if (!tab?.id) return;
      const res = (await browser.tabs.sendMessage(tab.id, {
        type: "KAVACHX_GET_CURRENT_EMAIL_ANALYSIS",
      })) as { ok?: boolean; analysis?: any; meta?: any } | undefined;
      if (res?.analysis) {
        setEmailAnalysis(res.analysis);
        setEmailMeta(res.meta);
      }
    } catch {
      //
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

      if (isWebmail && tab?.id) {
        try {
          const res = (await browser.tabs.sendMessage(tab.id, {
            type: "KAVACHX_GET_CURRENT_EMAIL_ANALYSIS",
          })) as { ok?: boolean; analysis?: any; meta?: any } | undefined;
          if (res?.analysis) {
            setEmailAnalysis(res.analysis);
            setEmailMeta(res.meta);
          }
        } catch {
          //
        }
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
              style={{
                fontSize: "11px",
                fontWeight: 600,
                background: "#2563eb",
                color: "#fff",
                border: "none",
                borderRadius: "5px",
                padding: "3px 8px",
                cursor: "pointer",
              }}
            >
              🔄 Scan Open Email
            </button>
          </div>

          {emailAnalysis ? (
            <div
              style={{
                fontSize: "11px",
                color: "#334155",
                display: "flex",
                flexDirection: "column",
                gap: "6px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <span>
                  <strong>Status:</strong> {emailAnalysis.safety_summary}
                </span>
                <span
                  style={{
                    padding: "2px 7px",
                    borderRadius: "9999px",
                    fontWeight: 800,
                    fontSize: "10px",
                    background:
                      emailAnalysis.risk_label === "dangerous"
                        ? "#ffe4e6"
                        : emailAnalysis.risk_label === "suspicious"
                        ? "#fef3c7"
                        : "#dcfce7",
                    color:
                      emailAnalysis.risk_label === "dangerous"
                        ? "#be123c"
                        : emailAnalysis.risk_label === "suspicious"
                        ? "#b45309"
                        : "#15803d",
                  }}
                >
                  Score {emailAnalysis.threat_score}/100
                </span>
              </div>
              {emailMeta && (
                <>
                  <div>
                    <strong>Sender:</strong> {emailMeta.senderName || "Unknown"} (
                    {emailMeta.senderEmail})
                  </div>
                  <div>
                    <strong>Subject:</strong> {emailMeta.subject || "No Subject"}
                  </div>
                  <div>
                    <strong>Embedded Links:</strong> {emailMeta.linksCount} found
                  </div>
                </>
              )}
              {emailAnalysis.sender_audit?.is_spoofed && (
                <div style={{ color: "#b91c1c", fontWeight: 700 }}>
                  ⚠️ Impersonation: {emailAnalysis.sender_audit.details}
                </div>
              )}
              {emailAnalysis.detected_traps?.length > 0 && (
                <div style={{ color: "#9a3412", fontWeight: 600 }}>
                  ⚡ Traps: {emailAnalysis.detected_traps.join(", ")}
                </div>
              )}
              <div>
                <strong>Advice:</strong> {emailAnalysis.ai_advice}
              </div>
              <div style={{ marginTop: "6px" }}>
                <a
                  href="http://localhost:5173/#/damage-control"
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: "inline-block",
                    padding: "4px 10px",
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
