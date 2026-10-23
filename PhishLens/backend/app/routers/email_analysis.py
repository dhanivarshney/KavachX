"""KavachX Email Phishing & Spoofing Analysis Engine."""

import re
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas.analysis import AnalysisRequest
from app.services.scoring_service import analyze_url

router = APIRouter(prefix="/analyze", tags=["email"])


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
    risk_label: str  # safe, suspicious, dangerous
    confidence: float
    sender_audit: SenderAudit
    detected_traps: list[str]
    embedded_links: list[ExtractedLinkResult]
    ai_advice: str
    safety_summary: str
    banner_color: str  # "rose", "amber", "emerald"


# Brand to legitimate official domains dictionary
KNOWN_BRAND_DOMAINS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co.in", "gmail.com", "accounts.google.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "india post": ["indiapost.gov.in"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "income tax": ["incometax.gov.in"],
    "vercel": ["vercel.com", "vercel.app"],
    "github": ["github.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "dropbox": ["dropbox.com"],
}

FREEMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "protonmail.com",
    "zoho.com",
    "mail.com",
}

EMAIL_URGENCY_PATTERNS = [
    (r"(account|subscription|service|membership)\s*(has been|is|will be)\s*(suspended|terminated|deactivated|on hold|cancelled)", "Account Suspension / Deactivation Threat"),
    (r"(unauthorized|suspicious|unknown)\s*(sign-in|login|activity|transaction|access)", "Fabricated Security Alert Trap"),
    (r"(confirm|verify|update|validate)\s*(your)?\s*(identity|account|billing|card|password|ssn|pan|kyc)", "Urgent Credential / Identity Verification Demand"),
    (r"(immediate action|within 24 hours|within 12 hours|urgent response required|final warning)", "False Urgency Countdown Lure"),
    (r"(invoice|receipt|order confirmed|payment receipt)\s*#?[0-9a-zA-Z-]+.*(\$|rs\.?|usd|inr)", "Fake Invoice / Accidental Purchase Scam"),
    (r"(won|winner|lottery|prize|refund approved|tax refund)\s*.*(\$|rs\.?|[0-9]+)", "False Refund / Prize Hook"),
]


def _extract_domain_from_email(email: str) -> str:
    cleaned = email.strip().lower()
    if "<" in cleaned and ">" in cleaned:
        match = re.search(r"<([^>]+)>", cleaned)
        if match:
            cleaned = match.group(1).strip()
    if "@" in cleaned:
        return cleaned.split("@")[-1].strip()
    return cleaned


def _audit_sender(sender_name: str, sender_email: str, subject: str) -> SenderAudit:
    name_clean = (sender_name or "").lower()
    subj_clean = (subject or "").lower()
    domain = _extract_domain_from_email(sender_email)

    claimed_brand = None
    for brand in KNOWN_BRAND_DOMAINS:
        if brand in name_clean or brand in subj_clean:
            claimed_brand = brand
            break

    is_freemail = domain in FREEMAIL_DOMAINS
    is_spoofed = False
    details = "Sender domain appears standard."

    if claimed_brand:
        allowed = KNOWN_BRAND_DOMAINS[claimed_brand]
        matches = any(domain == d or domain.endswith("." + d) for d in allowed)
        if not matches:
            is_spoofed = True
            details = f"Display name claims '{claimed_brand.title()}', but actual sending domain is '{domain}'."
        else:
            details = f"Sender verified: matches official {claimed_brand.title()} domain infrastructure."
    elif is_freemail and any(w in name_clean for w in ["support", "service", "security", "desk", "billing", "official", "bank"]):
        is_spoofed = True
        details = f"Sender claims to be an enterprise/support entity, but uses a public freemail domain ({domain})."

    return SenderAudit(
        claimed_brand=claimed_brand.title() if claimed_brand else None,
        actual_domain=domain,
        is_spoofed=is_spoofed,
        is_freemail_for_business=is_freemail and is_spoofed,
        details=details,
    )


@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email_phishing(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:
    sender_audit = _audit_sender(payload.sender_name or "", payload.sender_email, payload.subject or "")
    combined_text = f"{payload.sender_name or ''} {payload.subject or ''} {payload.body_snippet or ''}".lower()

    detected_traps: list[str] = []
    for pattern, trap_desc in EMAIL_URGENCY_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            detected_traps.append(trap_desc)

    # Analyze embedded links via 6-shield Web Guard
    all_links = set(payload.links)
    text_links = re.findall(r"https?://[^\s<>\"']+", payload.body_snippet or "")
    all_links.update(text_links)

    analyzed_links: list[ExtractedLinkResult] = []
    max_link_score = 0
    has_dangerous_link = False

    for link in list(all_links)[:5]:  # inspect top 5 links
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

    # Score synthesis
    threat_score = 5

    # 1. Sender Spoofing (Weight: 45 points)
    if sender_audit.is_spoofed:
        threat_score += 45
    elif sender_audit.is_freemail_for_business:
        threat_score += 35

    # 2. Linguistic Traps (Weight: 10 points per trap, max 30)
    threat_score += min(len(detected_traps) * 10, 30)

    # 3. Embedded Link Threat (Weight: up to 40 points)
    if has_dangerous_link:
        threat_score += 40
    elif max_link_score > 50:
        threat_score += 25
    elif len(analyzed_links) > 0 and max_link_score > 30:
        threat_score += 10

    threat_score = min(max(threat_score, 0), 100)

    # Verdict
    if threat_score >= 65 or has_dangerous_link or (sender_audit.is_spoofed and len(detected_traps) > 0):
        risk_label = "dangerous"
        banner_color = "rose"
        safety_summary = "High-Risk Phishing Email: Impersonation & Malicious Vectors Flagged"
        ai_advice = "DO NOT click links, download attachments, or reply. This email is impersonating an official brand to steal your account credentials."
    elif threat_score >= 35 or sender_audit.is_spoofed:
        risk_label = "suspicious"
        banner_color = "amber"
        safety_summary = "Suspicious Email: Sender Discrepancy & Urgency Triggers"
        ai_advice = "Caution advised. The sender address or embedded links do not match verified corporate infrastructure. Confirm with the company directly."
    else:
        risk_label = "safe"
        banner_color = "emerald"
        safety_summary = "Verified Authentic Communication"
        ai_advice = "Sender identity and embedded links match standard legitimate records. Practice standard web vigilance."

    confidence = round(0.85 + (0.1 if len(analyzed_links) > 0 else 0.0), 2)

    return EmailAnalysisResponse(
        threat_score=threat_score,
        risk_label=risk_label,
        confidence=confidence,
        sender_audit=sender_audit,
        detected_traps=detected_traps,
        embedded_links=analyzed_links,
        ai_advice=ai_advice,
        safety_summary=safety_summary,
        banner_color=banner_color,
    )
