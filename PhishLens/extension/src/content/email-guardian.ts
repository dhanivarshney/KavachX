/**
 * KavachX Email Guardian — Real-time Webmail Phishing & Spoofing Detector
 * Engineered for Gmail (mail.google.com) and Outlook Web (outlook.live.com / outlook.office.com)
 */

import browser from "webextension-polyfill";

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

const DAMAGE_CONTROL_URL = "http://localhost:5173/#/damage-control";

console.log("[KavachX] Email Guardian active on:", window.location.href);

// Clean sender email helper
function extractCleanEmail(raw: string): string {
  if (!raw) return "";
  const match = raw.match(/<([^>]+)>/);
  if (match && match[1]) return match[1].trim().toLowerCase();
  const emailMatch = raw.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  return emailMatch ? emailMatch[0].trim().toLowerCase() : raw.trim().toLowerCase();
}

// Clean sender name helper
function cleanSenderName(raw: string): string {
  if (!raw) return "";
  return raw.replace(/<[^>]+>/g, "").replace(/"/g, "").trim();
}

// Local fallback heuristic in case background service-worker or backend is unavailable
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
    icici: ["icicibank.com"],
    axis: ["axisbank.com"],
    facebook: ["facebook.com", "meta.com"],
    instagram: ["instagram.com"],
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
      details = `Sender matches verified ${claimedBrand.toUpperCase()} domain infrastructure.`;
    }
  }

  const traps: string[] = [];
  if (/suspend|terminat|deactivat|on hold|cancel/i.test(combined)) {
    traps.push("Account Suspension / Deactivation Threat");
  }
  if (/verify|confirm|validate|kyc|password|billing|credential/i.test(combined)) {
    traps.push("Credential Verification Demand");
  }
  if (/immediate action|within 24 hours|within 12 hours|urgent|final warning/i.test(combined)) {
    traps.push("Urgent Countdown Lure");
  }

  let score = 5;
  if (isSpoofed) score += 50;
  score += traps.length * 15;
  if (links.some((l) => /bit\.ly|tinyurl|is\.gd|t\.co|ow\.ly/i.test(l))) {
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
      risk_score: score > 50 ? 75 : 10,
      label: riskLabel,
      reasons: ["KavachX Client Heuristic Scan"],
    })),
    ai_advice:
      riskLabel === "dangerous"
        ? "DO NOT click links, download attachments, or reply. Brand impersonation or high threat detected."
        : riskLabel === "suspicious"
        ? "Caution: Check sender address carefully before taking action or clicking links."
        : "Verified sender identity. Standard legitimate communication.",
    safety_summary:
      riskLabel === "dangerous"
        ? "Critical Phishing Alert: Impersonation Vector"
        : riskLabel === "suspicious"
        ? "Suspicious Sender or Urgent Lure"
        : "Verified Legitimate Sender",
    banner_color: bannerColor,
  };
}

// Request analysis via background service worker to completely bypass Webmail CSP & CORS
async function requestEmailAnalysis(payload: {
  sender_name: string;
  sender_email: string;
  subject: string;
  body_snippet: string;
  links: string[];
}): Promise<EmailAnalysisResponse> {
  try {
    const response = (await browser.runtime.sendMessage({
      type: "KAVACHX_ANALYZE_EMAIL",
      payload,
    })) as { ok?: boolean; data?: EmailAnalysisResponse; error?: string } | undefined;

    if (response?.ok && response.data) {
      console.log("[KavachX] Backend email analysis successful:", response.data);
      return response.data;
    }
  } catch (err) {
    console.warn("[KavachX] Background request failed, using local fallback heuristic:", err);
  }

  // Fallback to local heuristic
  return localEmailAudit(
    payload.sender_name,
    payload.sender_email,
    payload.subject,
    payload.body_snippet,
    payload.links
  );
}

// Render the KavachX Security Banner
function renderSecurityBanner(
  data: EmailAnalysisResponse,
  bannerEl: HTMLElement
) {
  bannerEl.innerHTML = "";
  bannerEl.setAttribute("data-kavachx-state", "ready");

  const isDangerous = data.risk_label === "dangerous";
  const isSuspicious = data.risk_label === "suspicious";

  // Light-theme palette
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
    `background: ${bg} !important`,
    `border: 1px solid ${border} !important`,
    "border-radius: 12px !important",
    "padding: 14px 18px !important",
    "margin: 12px 0 16px 0 !important",
    "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important",
    "box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05) !important",
    "position: relative !important",
    "z-index: 9999 !important",
    "box-sizing: border-box !important",
    "width: 100% !important",
    "display: block !important",
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
    "background: transparent; border: none; font-size: 20px; line-height: 1; cursor: pointer; color: #64748b; padding: 0 4px;";
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
    <div style="margin-bottom: 4px;"><strong>Claimed Brand:</strong> ${data.sender_audit.claimed_brand || "None"}</div>
    <div style="margin-bottom: 4px;"><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(0)}%</div>
    <div style="margin-bottom: 4px;"><strong>Links Inspected:</strong> ${data.embedded_links.length} found</div>
    ${data.embedded_links
      .map(
        (l) =>
          `<div style="font-family: monospace; font-size: 10px; color: ${
            l.risk_score > 50 ? "#dc2626" : "#16a34a"
          }; margin-top: 2px;">• [Risk ${l.risk_score}] ${l.url.slice(0, 70)}${l.url.length > 70 ? "..." : ""}</div>`
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
    sosBtn.textContent = "🆘 SOS Recovery Mode";
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

// Create loading placeholder banner
function createPlaceholderBanner(): HTMLElement {
  const banner = document.createElement("div");
  banner.className = "kavachx-email-banner";
  banner.setAttribute("data-kavachx-state", "analyzing");
  banner.style.cssText = [
    "background: #f8fafc !important",
    "border: 1px dashed #94a3b8 !important",
    "border-radius: 10px !important",
    "padding: 10px 14px !important",
    "margin: 10px 0 14px 0 !important",
    "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important",
    "font-size: 12px !important",
    "color: #475569 !important",
    "display: flex !important",
    "align-items: center !important",
    "gap: 8px !important",
    "box-sizing: border-box !important",
    "position: relative !important",
    "z-index: 9999 !important",
    "width: 100% !important",
  ].join(";");
  banner.innerHTML = `
    <span style="font-size: 16px;">🛡️</span>
    <span><strong>KavachX:</strong> Analyzing email sender authenticity and embedded links...</span>
  `;
  return banner;
}

// ── Gmail Scanner ───────────────────────────────────────────────────────────
function scanGmail() {
  // Find all open message body containers in Gmail
  const bodyCandidates = document.querySelectorAll<HTMLElement>(
    "div.a3s, .a3s.aiL, div.ii.gt, div[dir='ltr'].adn, div[role='listitem'] div[dir='ltr']"
  );

  bodyCandidates.forEach(async (bodyEl) => {
    // Skip if element has already been processed or is not rendered
    if (bodyEl.getAttribute("data-kavachx-scanned") === "true") return;
    if (bodyEl.offsetHeight === 0 && bodyEl.offsetWidth === 0) return;

    // Skip drafts or compose boxes
    if (bodyEl.closest("div[role='dialog'], div[aria-label*='Compose']")) return;

    // Find message card container to extract sender
    const card =
      bodyEl.closest<HTMLElement>(
        "div[role='listitem'], div.adn, div.h7, div.gs, table.cf, div.ii.gt"
      ) ||
      bodyEl.parentElement?.parentElement ||
      document.body;

    // Sender extraction strategy
    const senderEl = card.querySelector<HTMLElement>(
      "span[email], span.gD, [data-hovercard-id], span.go"
    );

    let senderEmail =
      senderEl?.getAttribute("email") ||
      senderEl?.getAttribute("data-hovercard-id") ||
      "";
    let senderName =
      senderEl?.getAttribute("name") ||
      senderEl?.textContent ||
      "";

    // If still missing email, search header text for an @ email pattern
    if (!senderEmail || !senderEmail.includes("@")) {
      const headerSection = card.querySelector<HTMLElement>(".gE, .iv, .gt, h3, .gK, tr.acZ");
      const textToSearch = headerSection ? headerSection.innerText : card.innerText.slice(0, 500);
      const match = textToSearch.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
      if (match) {
        senderEmail = match[0];
      }
    }

    // Global fallback from main viewing pane
    if (!senderEmail || !senderEmail.includes("@")) {
      const globalSender = document.querySelector<HTMLElement>(
        "div[role='main'] span[email], div[role='main'] [data-hovercard-id], div[role='main'] span.gD"
      );
      if (globalSender) {
        senderEmail =
          globalSender.getAttribute("email") ||
          globalSender.getAttribute("data-hovercard-id") ||
          "";
        senderName = senderName || globalSender.getAttribute("name") || globalSender.textContent || "";
      }
    }

    // If no email address found at all, skip for now
    if (!senderEmail || !senderEmail.includes("@")) return;

    // Mark as scanned immediately
    bodyEl.setAttribute("data-kavachx-scanned", "true");

    const subjectEl = document.querySelector<HTMLElement>(
      "h2.hP, h2[data-thread-perm-id], div[role='main'] h2"
    );
    const subject = subjectEl?.textContent?.trim() || "";

    // Extract links
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

    console.log("[KavachX] Detected Gmail email to scan:", {
      senderName: cleanSenderName(senderName),
      senderEmail: extractCleanEmail(senderEmail),
      subject,
      linksFound: links.length,
    });

    // Inject placeholder
    const placeholder = createPlaceholderBanner();
    if (bodyEl.parentElement) {
      bodyEl.parentElement.insertBefore(placeholder, bodyEl);
    } else {
      bodyEl.prepend(placeholder);
    }

    // Perform analysis
    const analysis = await requestEmailAnalysis({
      sender_name: cleanSenderName(senderName),
      sender_email: extractCleanEmail(senderEmail),
      subject,
      body_snippet: bodySnippet,
      links,
    });

    renderSecurityBanner(analysis, placeholder);
  });
}

// ── Outlook Scanner ─────────────────────────────────────────────────────────
function scanOutlook() {
  const readingPanes = document.querySelectorAll<HTMLElement>(
    "div[aria-label='Reading Pane'], div[role='region'][aria-label*='Message'], div.rps_, #UniqueMessageBody, div[aria-label='Message body']"
  );

  readingPanes.forEach(async (pane) => {
    if (pane.getAttribute("data-kavachx-scanned") === "true") return;

    const senderEl = pane.querySelector<HTMLElement>(
      "div[data-testid*='sender'], span[title*='@'], div[aria-label*='From'] span, [data-hovercard-id]"
    ) || document.querySelector<HTMLElement>("div[data-testid*='sender'], span[title*='@']");

    let senderEmail = senderEl?.getAttribute("title") || senderEl?.textContent || "";
    let senderName = senderEl?.textContent || "";

    if (!senderEmail || !senderEmail.includes("@")) {
      const text = pane.innerText.slice(0, 600);
      const match = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
      if (match) senderEmail = match[0];
    }

    if (!senderEmail || !senderEmail.includes("@")) return;

    const bodyEl =
      pane.querySelector<HTMLElement>(
        "div[aria-label='Message body'], #UniqueMessageBody, div.rps_"
      ) || pane;

    pane.setAttribute("data-kavachx-scanned", "true");

    const subjectEl = document.querySelector<HTMLElement>(
      "div[role='heading'][aria-level='1'], .allowTextSelection"
    );
    const subject = subjectEl?.textContent?.trim() || "";

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

    console.log("[KavachX] Detected Outlook email to scan:", {
      senderEmail: extractCleanEmail(senderEmail),
      subject,
      linksFound: links.length,
    });

    const placeholder = createPlaceholderBanner();
    if (bodyEl.parentElement) {
      bodyEl.parentElement.insertBefore(placeholder, bodyEl);
    } else {
      bodyEl.prepend(placeholder);
    }

    const analysis = await requestEmailAnalysis({
      sender_name: cleanSenderName(senderName),
      sender_email: extractCleanEmail(senderEmail),
      subject,
      body_snippet: bodySnippet,
      links,
    });

    renderSecurityBanner(analysis, placeholder);
  });
}

// ── Master Scanner ──────────────────────────────────────────────────────────
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
let scanTimer: number | null = null;
function triggerScan() {
  if (scanTimer !== null) {
    window.clearTimeout(scanTimer);
  }
  scanTimer = window.setTimeout(() => {
    runEmailGuardian();
    scanTimer = null;
  }, 350);
}

// Initial triggers
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", triggerScan);
} else {
  triggerScan();
}

// MutationObserver for dynamic email opening in SPA
const observer = new MutationObserver(() => {
  triggerScan();
});

if (document.body) {
  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

// Backup periodic scan every 1.5 seconds to guarantee detection across all SPA transitions
setInterval(() => {
  runEmailGuardian();
}, 1500);

console.log("[KavachX] Email Guardian initialized successfully.");
