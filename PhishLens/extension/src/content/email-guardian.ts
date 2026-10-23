/**
 * KavachX Email Guardian — Real-time Phishing & Spoofing Detector for Webmail
 * Protects users inside Gmail (mail.google.com) and Outlook Web (outlook.live.com / outlook.office.com)
 */

interface SenderAudit {
  claimed_brand: string | null;
  actual_domain: string;
  is_spoofed: boolean;
  is_freemail_for_business: boolean;
  details: string;
}

interface ExtractedLinkResult {
  url: string;
  risk_score: number;
  label: string;
  reasons: string[];
}

interface EmailAnalysisResponse {
  threat_score: number;
  risk_label: "safe" | "suspicious" | "dangerous";
  confidence: number;
  sender_audit: SenderAudit;
  detected_traps: string[];
  embedded_links: ExtractedLinkResult[];
  ai_advice: string;
  safety_summary: string;
  banner_color: "rose" | "amber" | "emerald";
}

const BACKEND_URL = "http://localhost:8000/analyze/email";
const DAMAGE_CONTROL_URL = "http://localhost:5173/#/damage-control";

// Clean sender email helper
function extractCleanEmail(raw: string): string {
  const match = raw.match(/<([^>]+)>/);
  if (match && match[1]) return match[1].trim();
  const emailMatch = raw.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  return emailMatch ? emailMatch[0].trim() : raw.trim();
}

// Local fallback heuristic in case backend server is unreachable
function localEmailAudit(
  senderName: string,
  senderEmail: string,
  subject: string,
  bodySnippet: string,
  links: string[]
): EmailAnalysisResponse {
  const cleanEmail = extractCleanEmail(senderEmail);
  const domain = cleanEmail.includes("@") ? cleanEmail.split("@")[1].toLowerCase() : "";
  const nameClean = (senderName || "").toLowerCase();
  const subjClean = (subject || "").toLowerCase();
  const bodyClean = (bodySnippet || "").toLowerCase();
  const combined = `${nameClean} ${subjClean} ${bodyClean}`;

  const brandDomains: Record<string, string[]> = {
    paypal: ["paypal.com", "paypal.me"],
    google: ["google.com", "gmail.com"],
    apple: ["apple.com", "icloud.com"],
    netflix: ["netflix.com"],
    amazon: ["amazon.com", "amazon.in"],
    microsoft: ["microsoft.com", "outlook.com", "office.com"],
    sbi: ["sbi.co.in", "onlinesbi.sbi"],
    hdfc: ["hdfcbank.com"],
  };

  let claimedBrand: string | null = null;
  for (const b of Object.keys(brandDomains)) {
    if (nameClean.includes(b) || subjClean.includes(b)) {
      claimedBrand = b;
      break;
    }
  }

  let isSpoofed = false;
  let details = "Sender domain standard.";
  if (claimedBrand) {
    const allowed = brandDomains[claimedBrand];
    const match = allowed.some((d) => domain === d || domain.endsWith("." + d));
    if (!match) {
      isSpoofed = true;
      details = `Display name claims '${claimedBrand.toUpperCase()}', but sending domain is '${domain}'.`;
    } else {
      details = `Sender matches verified ${claimedBrand.toUpperCase()} domain.`;
    }
  }

  const traps: string[] = [];
  if (/suspend|terminat|deactivat|on hold|cancel/i.test(combined)) {
    traps.push("Account Suspension Threat");
  }
  if (/verify|confirm|validate|kyc|password|billing/i.test(combined)) {
    traps.push("Credential Verification Demand");
  }
  if (/immediate action|within 24 hours|urgent|final warning/i.test(combined)) {
    traps.push("Urgent Countdown Lure");
  }

  let score = 5;
  if (isSpoofed) score += 50;
  score += traps.length * 15;
  if (links.some((l) => /bit\.ly|tinyurl|is\.gd|t\.co/i.test(l))) {
    score += 25;
    traps.push("Obfuscated Link Shortener");
  }

  score = Math.min(Math.max(score, 0), 100);

  const riskLabel: "safe" | "suspicious" | "dangerous" =
    score >= 65 || isSpoofed ? "dangerous" : score >= 35 ? "suspicious" : "safe";
  const bannerColor = riskLabel === "dangerous" ? "rose" : riskLabel === "suspicious" ? "amber" : "emerald";

  return {
    threat_score: score,
    risk_label: riskLabel,
    confidence: 0.85,
    sender_audit: {
      claimed_brand: claimedBrand ? claimedBrand.toUpperCase() : null,
      actual_domain: domain,
      is_spoofed: isSpoofed,
      is_freemail_for_business: false,
      details,
    },
    detected_traps: traps,
    embedded_links: links.slice(0, 3).map((u) => ({
      url: u,
      risk_score: score > 50 ? 70 : 10,
      label: riskLabel,
      reasons: ["Local security heuristic scan"],
    })),
    ai_advice:
      riskLabel === "dangerous"
        ? "DO NOT click links, download attachments, or reply. Sender impersonation detected."
        : riskLabel === "suspicious"
        ? "Caution: Check sender email carefully before opening links."
        : "Email sender and embedded links appear normal. Practice safe web browsing.",
    safety_summary:
      riskLabel === "dangerous"
        ? "High-Risk Phishing Attempt Flagged"
        : riskLabel === "suspicious"
        ? "Suspicious Email Sender or Content"
        : "Verified Legitimate Sender",
    banner_color: bannerColor,
  };
}

// Request analysis from KavachX backend with fallback
async function requestEmailAnalysis(payload: {
  sender_name: string;
  sender_email: string;
  subject: string;
  body_snippet: string;
  links: string[];
}): Promise<EmailAnalysisResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);

  try {
    const res = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    if (res.ok) {
      const data: EmailAnalysisResponse = await res.json();
      return data;
    }
  } catch (err) {
    // Backend offline or timeout — fall back to local heuristic
  } finally {
    clearTimeout(timer);
  }

  return localEmailAudit(
    payload.sender_name,
    payload.sender_email,
    payload.subject,
    payload.body_snippet,
    payload.links
  );
}

// Render the KavachX Email Guardian Banner
function renderSecurityBanner(
  container: HTMLElement,
  data: EmailAnalysisResponse,
  bannerEl: HTMLElement
) {
  bannerEl.innerHTML = "";
  bannerEl.setAttribute("data-kavachx-state", "ready");

  const isDark =
    window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const isDangerous = data.risk_label === "dangerous";
  const isSuspicious = data.risk_label === "suspicious";

  // Palette configs
  let bg = "#f0fdf4";
  let border = "#bbf7d0";
  let badgeBg = "#dcfce7";
  let badgeText = "#15803d";
  let titleColor = "#166534";
  let icon = "🛡️";
  let statusBadge = "VERIFIED SAFE";

  if (isDangerous) {
    bg = "#fff1f2";
    border = "#fecdd3";
    badgeBg = "#ffe4e6";
    badgeText = "#be123c";
    titleColor = "#9f1239";
    icon = "🚨";
    statusBadge = "CRITICAL PHISHING THREAT";
  } else if (isSuspicious) {
    bg = "#fffbeb";
    border = "#fde68a";
    badgeBg = "#fef3c7";
    badgeText = "#b45309";
    titleColor = "#92400e";
    icon = "⚠️";
    statusBadge = "SUSPICIOUS EMAIL";
  }

  bannerEl.style.cssText = [
    `background: ${bg}`,
    `border: 1px solid ${border}`,
    "border-radius: 12px",
    "padding: 14px 18px",
    "margin: 10px 0 16px 0",
    "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    "box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04)",
    "position: relative",
    "z-index: 10",
    "box-sizing: border-box",
    "width: 100%",
  ].join(";");

  // Header row
  const header = document.createElement("div");
  header.style.cssText =
    "display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 8px;";

  const titleGroup = document.createElement("div");
  titleGroup.style.cssText = "display: flex; align-items: center; gap: 8px;";

  const iconSpan = document.createElement("span");
  iconSpan.textContent = icon;
  iconSpan.style.fontSize = "18px";

  const brandTitle = document.createElement("span");
  brandTitle.innerHTML = `<strong style="font-weight: 800; color: #0f172a; font-size: 13px; letter-spacing: 0.02em;">KavachX</strong> <span style="font-size: 12px; color: ${titleColor}; font-weight: 700;">${data.safety_summary}</span>`;

  titleGroup.append(iconSpan, brandTitle);

  const badgeRow = document.createElement("div");
  badgeRow.style.cssText = "display: flex; align-items: center; gap: 8px;";

  const riskBadge = document.createElement("span");
  riskBadge.textContent = `${statusBadge} • Score ${data.threat_score}/100`;
  riskBadge.style.cssText = `background: ${badgeBg}; color: ${badgeText}; font-size: 11px; font-weight: 800; padding: 3px 9px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.04em;`;

  const dismissBtn = document.createElement("button");
  dismissBtn.innerHTML = "&times;";
  dismissBtn.title = "Dismiss KavachX Alert";
  dismissBtn.style.cssText =
    "background: transparent; border: none; font-size: 18px; line-height: 1; cursor: pointer; color: #64748b; padding: 0 4px;";
  dismissBtn.onclick = () => bannerEl.remove();

  badgeRow.append(riskBadge, dismissBtn);
  header.append(titleGroup, badgeRow);

  // Body advisory text
  const advisory = document.createElement("div");
  advisory.style.cssText =
    "font-size: 12px; line-height: 1.5; color: #334155; margin-bottom: 8px;";
  advisory.textContent = data.ai_advice;

  // Specific threat highlights (if suspicious/dangerous)
  const threatsList = document.createElement("div");
  threatsList.style.cssText =
    "display: flex; flex-direction: column; gap: 4px; margin-bottom: 10px;";

  if (data.sender_audit.is_spoofed) {
    const item = document.createElement("div");
    item.style.cssText =
      "font-size: 11px; color: #b91c1c; font-weight: 600; display: flex; align-items: center; gap: 6px;";
    item.innerHTML = `<span>⚠️</span> <span><strong>Brand Impersonation:</strong> ${data.sender_audit.details}</span>`;
    threatsList.appendChild(item);
  }

  for (const trap of data.detected_traps) {
    const item = document.createElement("div");
    item.style.cssText =
      "font-size: 11px; color: #9a3412; font-weight: 600; display: flex; align-items: center; gap: 6px;";
    item.innerHTML = `<span>⚡</span> <span><strong>Urgency Trap:</strong> ${trap}</span>`;
    threatsList.appendChild(item);
  }

  // Footer Actions Row
  const footerRow = document.createElement("div");
  footerRow.style.cssText =
    "display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; padding-top: 8px; border-top: 1px solid rgba(0,0,0,0.06);";

  const detailsToggle = document.createElement("button");
  detailsToggle.textContent = "🔍 View Forensic Audit";
  detailsToggle.style.cssText =
    "background: transparent; border: 1px solid #cbd5e1; border-radius: 6px; padding: 4px 10px; font-size: 11px; font-weight: 600; color: #475569; cursor: pointer;";

  const auditDetails = document.createElement("div");
  auditDetails.style.cssText =
    "display: none; width: 100%; margin-top: 8px; padding: 10px; background: rgba(255,255,255,0.7); border-radius: 8px; font-size: 11px; color: #334155; border: 1px dashed #cbd5e1;";
  
  auditDetails.innerHTML = `
    <div style="margin-bottom: 4px;"><strong>Sending Domain:</strong> ${data.sender_audit.actual_domain || "Unknown"}</div>
    <div style="margin-bottom: 4px;"><strong>Target Brand:</strong> ${data.sender_audit.claimed_brand || "None"}</div>
    <div style="margin-bottom: 4px;"><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(0)}%</div>
    <div style="margin-bottom: 4px;"><strong>Links Inspected:</strong> ${data.embedded_links.length} found</div>
    ${data.embedded_links
      .map(
        (l) =>
          `<div style="font-family: monospace; font-size: 10px; color: ${
            l.risk_score > 50 ? "#dc2626" : "#16a34a"
          }; margin-top: 2px;">• [Score ${l.risk_score}] ${l.url.slice(0, 60)}${l.url.length > 60 ? "..." : ""}</div>`
      )
      .join("")}
  `;

  detailsToggle.onclick = () => {
    if (auditDetails.style.display === "none") {
      auditDetails.style.display = "block";
      detailsToggle.textContent = "▲ Hide Audit";
    } else {
      auditDetails.style.display = "none";
      detailsToggle.textContent = "🔍 View Forensic Audit";
    }
  };

  const actionGroup = document.createElement("div");
  actionGroup.style.cssText = "display: flex; align-items: center; gap: 8px;";

  if (isDangerous || isSuspicious) {
    const sosBtn = document.createElement("a");
    sosBtn.href = DAMAGE_CONTROL_URL;
    sosBtn.target = "_blank";
    sosBtn.rel = "noopener noreferrer";
    sosBtn.textContent = "🆘 Incident Recovery / SOS";
    sosBtn.style.cssText =
      "background: #e11d48; color: #ffffff; text-decoration: none; border-radius: 6px; padding: 5px 12px; font-size: 11px; font-weight: 700; display: inline-flex; align-items: center; gap: 4px; cursor: pointer; box-shadow: 0 1px 3px rgba(225, 29, 72, 0.25);";
    actionGroup.appendChild(sosBtn);
  }

  footerRow.append(detailsToggle, actionGroup);

  bannerEl.append(header, advisory);
  if (threatsList.children.length > 0) {
    bannerEl.append(threatsList);
  }
  bannerEl.append(footerRow, auditDetails);
}

// Create loading state placeholder banner
function createPlaceholderBanner(): HTMLElement {
  const banner = document.createElement("div");
  banner.className = "kavachx-email-banner";
  banner.setAttribute("data-kavachx-state", "analyzing");
  banner.style.cssText = [
    "background: #f8fafc",
    "border: 1px dashed #cbd5e1",
    "border-radius: 10px",
    "padding: 10px 14px",
    "margin: 8px 0 12px 0",
    "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    "font-size: 12px",
    "color: #64748b",
    "display: flex",
    "align-items: center",
    "gap: 8px",
    "box-sizing: border-box",
  ].join(";");
  banner.innerHTML = `
    <span style="font-size: 14px;">🛡️</span>
    <span><strong>KavachX:</strong> Analyzing email for spoofing and phishing vectors...</span>
  `;
  return banner;
}

// ── Gmail Scanner ───────────────────────────────────────────────────────────
function scanGmail() {
  // Gmail expanded message container: .adn.ads or [data-message-id] or .h7
  const messageNodes = document.querySelectorAll<HTMLElement>("div.adn.ads, div[data-message-id]");

  messageNodes.forEach(async (node) => {
    if (node.getAttribute("data-kavachx-scanned") === "true") return;

    // Look for sender element
    const senderEl = node.querySelector<HTMLElement>("span.gD, span[email]");
    if (!senderEl) return;

    const senderEmail = senderEl.getAttribute("email") || senderEl.textContent || "";
    const senderName = senderEl.getAttribute("name") || senderEl.textContent || "";
    if (!senderEmail || !senderEmail.includes("@")) return;

    // Subject is usually top thread header: h2.hP
    const subjectEl = document.querySelector<HTMLElement>("h2.hP, h2[data-thread-perm-id]");
    const subject = subjectEl ? subjectEl.textContent || "" : "";

    // Body container: .a3s.aiL or .a3s
    const bodyEl = node.querySelector<HTMLElement>(".a3s.aiL, div.a3s");
    if (!bodyEl) return;

    node.setAttribute("data-kavachx-scanned", "true");

    // Extract links inside the body
    const links: string[] = [];
    bodyEl.querySelectorAll<HTMLAnchorElement>("a[href]").forEach((a) => {
      const href = a.href;
      if (
        href &&
        (href.startsWith("http://") || href.startsWith("https://")) &&
        !href.includes("mail.google.com")
      ) {
        links.push(href);
      }
    });

    const bodySnippet = bodyEl.innerText ? bodyEl.innerText.slice(0, 1500) : "";

    // Inject placeholder
    const placeholder = createPlaceholderBanner();
    bodyEl.parentElement?.insertBefore(placeholder, bodyEl);

    // Analyze
    const analysis = await requestEmailAnalysis({
      sender_name: senderName,
      sender_email: senderEmail,
      subject,
      body_snippet: bodySnippet,
      links,
    });

    renderSecurityBanner(bodyEl, analysis, placeholder);
  });
}

// ── Outlook Scanner ─────────────────────────────────────────────────────────
function scanOutlook() {
  // Outlook Reading Pane or Message Body container
  const readingPanes = document.querySelectorAll<HTMLElement>(
    "div[aria-label='Reading Pane'], div[role='region'][aria-label*='Message'], div.rps_"
  );

  readingPanes.forEach(async (pane) => {
    if (pane.getAttribute("data-kavachx-scanned") === "true") return;

    const senderEl = pane.querySelector<HTMLElement>(
      "div[data-testid*='sender'], span[title*='@'], div[aria-label*='From'] span"
    );
    if (!senderEl) return;

    const senderEmail = senderEl.getAttribute("title") || senderEl.textContent || "";
    const senderName = senderEl.textContent || "";
    if (!senderEmail || !senderEmail.includes("@")) return;

    const subjectEl = document.querySelector<HTMLElement>(
      "div[role='heading'][aria-level='1'], .allowTextSelection"
    );
    const subject = subjectEl ? subjectEl.textContent || "" : "";

    const bodyEl = pane.querySelector<HTMLElement>(
      "div[aria-label='Message body'], #UniqueMessageBody, div.rps_"
    );
    if (!bodyEl) return;

    pane.setAttribute("data-kavachx-scanned", "true");

    const links: string[] = [];
    bodyEl.querySelectorAll<HTMLAnchorElement>("a[href]").forEach((a) => {
      const href = a.href;
      if (
        href &&
        (href.startsWith("http://") || href.startsWith("https://")) &&
        !href.includes("outlook.live.com") &&
        !href.includes("outlook.office.com")
      ) {
        links.push(href);
      }
    });

    const bodySnippet = bodyEl.innerText ? bodyEl.innerText.slice(0, 1500) : "";

    const placeholder = createPlaceholderBanner();
    bodyEl.parentElement?.insertBefore(placeholder, bodyEl);

    const analysis = await requestEmailAnalysis({
      sender_name: senderName,
      sender_email: senderEmail,
      subject,
      body_snippet: bodySnippet,
      links,
    });

    renderSecurityBanner(bodyEl, analysis, placeholder);
  });
}

// ── Master Observation Engine ───────────────────────────────────────────────
function runEmailGuardian() {
  const hostname = window.location.hostname;
  if (hostname.includes("mail.google.com")) {
    scanGmail();
  } else if (
    hostname.includes("outlook.live.com") ||
    hostname.includes("outlook.office.com") ||
    hostname.includes("outlook.office365.com")
  ) {
    scanOutlook();
  }
}

// Debounce helper
let timeoutId: number | null = null;
function scheduleScan() {
  if (timeoutId !== null) {
    window.clearTimeout(timeoutId);
  }
  timeoutId = window.setTimeout(() => {
    runEmailGuardian();
    timeoutId = null;
  }, 400);
}

// Initial sweep when document loads
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", scheduleScan);
} else {
  scheduleScan();
}

// MutationObserver to catch dynamically opened emails in Single Page Webmail
const observer = new MutationObserver(() => {
  scheduleScan();
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
});

console.log("[KavachX] Email Guardian active and monitoring webmail security.");
