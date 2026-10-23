"""KavachX Email Phishing & Spoofing Analysis Engine — v2 (real signal scoring)."""

import os
import re
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas.analysis import AnalysisRequest
from app.services.scoring_service import analyze_url

router = APIRouter(prefix="/analyze", tags=["email"])


# ── Request / Response models ──────────────────────────────────────────────────

class EmailAnalysisRequest(BaseModel):
    sender_name: str | None = ""
    sender_email: str
    subject: str | None = ""
    body_snippet: str | None = ""
    links: list[str] = []


class ExtractedLinkResult(BaseModel):
    url: str
    risk_score: int
    label: str
    reasons: list[str]


class SenderAudit(BaseModel):
    claimed_brand: str | None
    actual_domain: str
    is_spoofed: bool
    is_freemail_for_business: bool
    details: str


class EmailAnalysisResponse(BaseModel):
    threat_score: int
    risk_label: str          # safe | suspicious | dangerous
    confidence: float
    sender_audit: SenderAudit
    detected_traps: list[str]
    embedded_links: list[ExtractedLinkResult]
    ai_advice: str
    safety_summary: str
    banner_color: str        # rose | amber | emerald
    signal_breakdown: dict   # NEW: individual signal scores for transparency


# ── Static data tables ─────────────────────────────────────────────────────────

KNOWN_BRAND_DOMAINS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co.in", "gmail.com", "accounts.google.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com", "kotakbank.com"],
    "facebook": ["facebook.com", "meta.com", "fb.com"],
    "instagram": ["instagram.com"],
    "india post": ["indiapost.gov.in"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "income tax": ["incometax.gov.in"],
    "vercel": ["vercel.com", "vercel.app"],
    "github": ["github.com"],
    "linkedin": ["linkedin.com", "e.linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "dropbox": ["dropbox.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["google.com"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "infosys": ["infosys.com"],
    "tcs": ["tcs.com"],
    "wipro": ["wipro.com"],
    "zomato": ["zomato.com"],
    "swiggy": ["swiggy.com"],
    "flipkart": ["flipkart.com"],
    "myntra": ["myntra.com"],
    "snapdeal": ["snapdeal.com"],
}

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "protonmail.com",
    "zoho.com", "mail.com", "icloud.com", "rediffmail.com",
}

# Third-party bulk-mail / marketing automation sending domains
# Legitimate when configured properly, but commonly abused in phishing/spam
BULK_MAILER_DOMAINS = {
    "brevosend.com", "sendinblue.com", "mailchimp.com", "sendgrid.net",
    "amazonses.com", "mailgun.org", "postmarkapp.com", "sparkpostmail.com",
    "mg.mailer.com", "em.mailer.com", "mandrillapp.com", "constantcontact.com",
    "klaviyomail.com", "hubspotemail.net", "createsend.com",
}

# TLDs overwhelmingly used in phishing campaigns (low cost / easy registration)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".fun", ".press", ".space",
    ".info", ".buzz", ".click", ".link", ".live",
}

# High-value business keywords in sender name that should never use freemail / bulk-mailer
ENTERPRISE_KEYWORDS = [
    "support", "service", "security", "helpdesk", "desk",
    "billing", "official", "bank", "finance", "account", "admin",
    "noreply", "no-reply", "verify", "verification", "team", "alert",
    "kyc", "aadhaar", "pan", "irs", "tax", "government", "gov",
]

URGENCY_PATTERNS: list[tuple[str, str, int]] = [
    # (regex, label, score_weight)
    (r"(account|subscription|service|membership)\s*(has been|is|will be)\s*(suspended|terminated|deactivated|on hold|cancelled)",
     "Account Suspension Threat", 15),
    (r"(unauthorized|suspicious|unknown)\s*(sign.?in|login|activity|transaction|access)",
     "Fabricated Security Alert", 12),
    (r"(confirm|verify|update|validate)\s*(your)?\s*(identity|account|billing|card|password|ssn|pan|kyc|aadhaar)",
     "Urgent Credential / KYC Demand", 15),
    (r"(immediate action required|within 24 hours|within 12 hours|urgent response|final warning|last notice|last reminder)",
     "False Urgency Countdown", 12),
    (r"(invoice|receipt|order confirmed|payment receipt)\s*#?[0-9a-zA-Z\-]+.*(\$|rs\.?|usd|inr)",
     "Fake Invoice / Purchase Bait", 10),
    (r"(won|winner|lottery|prize|refund approved|tax refund|unclaimed|reward)\s*.+(\$|rs\.?|[0-9]+)",
     "Prize / Refund Hook", 15),
    (r"(click here|click the link|click below|click on this)\s*(to|and)?\s*(verify|confirm|update|activate|secure)",
     "Deceptive CTA (Click Here to Verify)", 10),
    (r"(your (account|card|funds|money) (will be|will|is being|are) (blocked|frozen|charged|debited|debited))",
     "Fear-Based Financial Threat", 15),
    (r"(otp|one.?time.?password|one.?time.?pin).*share|share.*(otp|one.?time)",
     "OTP Solicitation (Critical)", 20),
    (r"(dear (customer|user|member|sir|ma'am|valued)|respected (customer|user))",
     "Generic Salutation (Impersonation Indicator)", 5),
]

# ── Helper functions ───────────────────────────────────────────────────────────

def _extract_domain(email: str) -> str:
    cleaned = email.strip().lower()
    if "<" in cleaned and ">" in cleaned:
        m = re.search(r"<([^>]+)>", cleaned)
        if m:
            cleaned = m.group(1).strip()
    if "@" in cleaned:
        return cleaned.split("@")[-1].strip()
    return cleaned


def _get_tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return "." + parts[-1] if len(parts) > 1 else ""


def _has_numeric_subdomain(domain: str) -> bool:
    """Flags domains like 11654627.brevosend.com — numeric subdomain = bulk mailer / throwaway."""
    parts = domain.split(".")
    return len(parts) >= 3 and parts[0].isdigit()


def _domain_looks_random(domain: str) -> bool:
    """Heuristic: subdomain with long random-looking hex/alphanum string."""
    parts = domain.split(".")
    if len(parts) >= 3:
        sub = parts[0]
        if len(sub) >= 8 and re.match(r'^[a-f0-9]+$', sub):
            return True  # looks like hex hash
        if len(sub) >= 10 and not re.search(r'(mail|smtp|send|relay|em\d|mg\d)', sub):
            consonants = sum(1 for c in sub if c in "bcdfghjklmnpqrstvwxyz")
            if consonants / max(len(sub), 1) > 0.7:
                return True  # too many consonants = random string
    return False


def _audit_sender(sender_name: str, sender_email: str, subject: str) -> tuple[SenderAudit, int]:
    """
    Returns (SenderAudit, spoofing_score_contribution).
    """
    name_clean = (sender_name or "").lower()
    subj_clean = (subject or "").lower()
    domain = _extract_domain(sender_email)
    tld = _get_tld(domain)
    score = 0
    flags: list[str] = []

    # 1. Brand impersonation check
    claimed_brand = None
    for brand in KNOWN_BRAND_DOMAINS:
        if brand in name_clean or brand in subj_clean:
            claimed_brand = brand
            break

    is_freemail = domain in FREEMAIL_DOMAINS
    is_bulk_mailer = any(domain == b or domain.endswith("." + b) for b in BULK_MAILER_DOMAINS)
    is_spoofed = False

    if claimed_brand:
        allowed = KNOWN_BRAND_DOMAINS[claimed_brand]
        matches = any(domain == d or domain.endswith("." + d) for d in allowed)
        if not matches:
            is_spoofed = True
            score += 45
            flags.append(f"Brand impersonation: '{claimed_brand.title()}' claimed but sending from '{domain}'")
        else:
            flags.append(f"Verified {claimed_brand.title()} official domain infrastructure")
    elif is_freemail and any(w in name_clean for w in ENTERPRISE_KEYWORDS):
        is_spoofed = True
        score += 30
        flags.append(f"Enterprise/support entity using public freemail domain ({domain})")

    # 2. Numeric subdomain (e.g. 11654627.brevosend.com)
    if _has_numeric_subdomain(domain):
        score += 15
        flags.append(f"Numeric subdomain detected ({domain}) — typical of bulk-mailer abuse")

    # 3. Random-looking subdomain
    if _domain_looks_random(domain):
        score += 12
        flags.append(f"Randomized subdomain pattern in '{domain}'")

    # 4. Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        score += 18
        flags.append(f"High-risk TLD '{tld}' — commonly used in phishing registrations")

    # 5. Bulk mailer domain (without brand claim — lower weight)
    if is_bulk_mailer and not claimed_brand:
        score += 8
        flags.append(f"Sending via bulk-mailer platform ({domain})")

    # 6. Display name vs domain mismatch — name contains a domain-like word different from actual domain
    # e.g. sender_name = "PayPal Support" but domain = brevosend.com
    name_domains = re.findall(r'\b([a-z0-9-]+\.(com|in|net|org|co))\b', name_clean)
    for nd, _ in name_domains:
        if nd not in domain and domain not in nd:
            score += 12
            flags.append(f"Display name references '{nd}' but actual domain is '{domain}'")
            break

    # 7. Empty or missing sender email (highly suspicious)
    if not sender_email or "@" not in sender_email:
        score += 20
        flags.append("Sender email is missing or malformed")

    details = "; ".join(flags) if flags else "Sender domain appears standard."

    return (
        SenderAudit(
            claimed_brand=claimed_brand.title() if claimed_brand else None,
            actual_domain=domain,
            is_spoofed=is_spoofed,
            is_freemail_for_business=is_freemail and (is_spoofed or any(w in name_clean for w in ENTERPRISE_KEYWORDS)),
            details=details,
        ),
        score,
    )


def _score_subject(subject: str) -> tuple[list[str], int]:
    """Score the subject line for phishing signals."""
    s = (subject or "").lower()
    traps: list[str] = []
    score = 0

    if re.search(r"(urgent|important|action required|immediate|verify now|your account|don't ignore)", s):
        traps.append("Urgency / Fear keyword in subject")
        score += 8
    if re.search(r"(won|winner|prize|lottery|free|gift|congratulations|selected)", s):
        traps.append("Prize / Reward lure in subject")
        score += 10
    if re.search(r"(invoice|receipt|order|delivery|shipment|tracking)", s) and re.search(r"#[0-9a-z]{4,}", s):
        traps.append("Fake order/invoice number in subject")
        score += 8
    if re.search(r"(password|otp|pin|security code)\s*(expired|reset|changed|update)", s):
        traps.append("Password/OTP reset lure in subject")
        score += 12
    if re.search(r"(re:|fwd:).*\[.*\]", s):
        traps.append("Thread-spoofing header in subject")
        score += 5

    return traps, score


def _score_body(body: str) -> tuple[list[str], int]:
    """Score body text for urgency patterns and lure language."""
    text = (body or "").lower()
    traps: list[str] = []
    total = 0

    for pattern, label, weight in URGENCY_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            traps.append(label)
            total += weight

    # Cap body contribution at 40
    return traps, min(total, 40)


def _build_ai_advice(
    threat_score: int,
    sender_audit: SenderAudit,
    detected_traps: list[str],
    analyzed_links: list[ExtractedLinkResult],
    subject: str,
) -> str:
    """Build a context-aware advice string without calling an external API."""
    if threat_score >= 70:
        brand_part = f"This email is impersonating **{sender_audit.claimed_brand}**. " if sender_audit.claimed_brand else ""
        return (
            f"⛔ HIGH RISK — Do NOT click any links, download attachments, or reply. "
            f"{brand_part}"
            f"Signals: {', '.join(detected_traps[:3]) if detected_traps else 'Suspicious domain & link patterns'}. "
            f"If you clicked a link, change your passwords immediately and report to cybercrime.gov.in."
        )
    elif threat_score >= 40:
        trap_str = ", ".join(detected_traps[:2]) if detected_traps else "sender domain discrepancy"
        return (
            f"⚠️ CAUTION — This email has suspicious characteristics: {trap_str}. "
            f"The sending domain '{sender_audit.actual_domain}' may not be the legitimate sender. "
            f"Verify with the company directly before clicking any links or sharing information."
        )
    elif threat_score >= 20:
        return (
            f"🔍 LOW CONCERN — No major phishing signals detected, but the sender uses "
            f"'{sender_audit.actual_domain}'. Standard caution: don't share OTPs or passwords via email."
        )
    else:
        return (
            f"✅ APPEARS LEGITIMATE — Sender domain '{sender_audit.actual_domain}' matches expected patterns "
            f"and no deceptive language was detected. Practice standard web hygiene."
        )


# ── Main endpoint ─────────────────────────────────────────────────────────────

@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email_phishing(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:

    # 1. Sender audit
    sender_audit, sender_score = _audit_sender(
        payload.sender_name or "",
        payload.sender_email,
        payload.subject or "",
    )

    # 2. Subject scoring
    subject_traps, subject_score = _score_subject(payload.subject or "")

    # 3. Body / linguistic scoring
    body_traps, body_score = _score_body(payload.body_snippet or "")

    all_traps = list(dict.fromkeys(subject_traps + body_traps))  # deduplicate, preserve order

    # 4. Embedded link analysis via 6-Shield Web Guard
    all_links: set[str] = set(payload.links)
    text_links = re.findall(r"https?://[^\s<>\"']+", payload.body_snippet or "")
    all_links.update(text_links)

    analyzed_links: list[ExtractedLinkResult] = []
    max_link_score = 0
    has_dangerous_link = False

    for link in list(all_links)[:5]:
        try:
            req = AnalysisRequest(url=link)
            res = await analyze_url(req)
            if res.risk_score > max_link_score:
                max_link_score = res.risk_score
            if res.label == "dangerous":
                has_dangerous_link = True
            analyzed_links.append(
                ExtractedLinkResult(
                    url=link,
                    risk_score=res.risk_score,
                    label=res.label,
                    reasons=res.reasons[:3],
                )
            )
        except Exception:
            pass

    # Link score contribution (max 35)
    link_score = 0
    if has_dangerous_link:
        link_score = 35
    elif max_link_score >= 60:
        link_score = 25
    elif max_link_score >= 40:
        link_score = 15
    elif max_link_score >= 20:
        link_score = 8

    # 5. Synthesise total threat score
    # Base = 0 (no fake starting points)
    threat_score = sender_score + subject_score + body_score + link_score
    threat_score = min(max(threat_score, 0), 100)

    signal_breakdown = {
        "sender_domain_signals": sender_score,
        "subject_signals": subject_score,
        "body_language_signals": body_score,
        "link_threat_signals": link_score,
        "total": threat_score,
    }

    # 6. Verdict
    force_dangerous = has_dangerous_link or (sender_audit.is_spoofed and len(all_traps) >= 1)

    if threat_score >= 65 or force_dangerous:
        risk_label = "dangerous"
        banner_color = "rose"
        safety_summary = "⛔ High-Risk Phishing Email Detected"
    elif threat_score >= 30:
        risk_label = "suspicious"
        banner_color = "amber"
        safety_summary = "⚠️ Suspicious Email — Exercise Caution"
    else:
        risk_label = "safe"
        banner_color = "emerald"
        safety_summary = "✅ Appears Legitimate"

    ai_advice = _build_ai_advice(
        threat_score, sender_audit, all_traps, analyzed_links, payload.subject or ""
    )

    confidence = round(
        0.75
        + (0.1 if len(analyzed_links) > 0 else 0.0)
        + (0.05 if payload.body_snippet and len(payload.body_snippet) > 100 else 0.0),
        2,
    )

    return EmailAnalysisResponse(
        threat_score=threat_score,
        risk_label=risk_label,
        confidence=confidence,
        sender_audit=sender_audit,
        detected_traps=all_traps,
        embedded_links=analyzed_links,
        ai_advice=ai_advice,
        safety_summary=safety_summary,
        banner_color=banner_color,
        signal_breakdown=signal_breakdown,
    )
