"""KavachX Email Phishing & Spoofing Analysis Engine — v3 (Gmail-signal-aware)."""

import re
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas.analysis import AnalysisRequest
from app.services.scoring_service import analyze_url

router = APIRouter(prefix="/analyze", tags=["email"])


# ── Request / Response models ─────────────────────────────────────────────────

class EmailAnalysisRequest(BaseModel):
    sender_name: str | None = ""
    sender_email: str = ""
    subject: str | None = ""
    body_snippet: str | None = ""
    links: list[str] = []
    # Gmail-native signals (sent by extension)
    is_spam_folder: bool = False
    gmail_flagged_phishing: bool = False
    via_domain: str | None = ""
    reply_to: str | None = ""
    has_dangerous_attachment: bool = False


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
    signal_breakdown: dict


# ── Static data ───────────────────────────────────────────────────────────────

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
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "zomato": ["zomato.com"],
    "swiggy": ["swiggy.com"],
    "flipkart": ["flipkart.com"],
    "myntra": ["myntra.com"],
}

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "protonmail.com",
    "zoho.com", "mail.com", "icloud.com", "rediffmail.com",
    "yahoo.in", "yahoo.co.in",
}

# Bulk-mailer / ESP sending domains — legit when configured, abused in spam/phishing
BULK_MAILER_DOMAINS = {
    "brevosend.com", "sendinblue.com", "mailchimp.com", "sendgrid.net",
    "amazonses.com", "mailgun.org", "postmarkapp.com", "sparkpostmail.com",
    "mandrillapp.com", "constantcontact.com", "klaviyomail.com",
    "hubspotemail.net", "createsend.com", "em.mailer.com", "mg.mailer.com",
    "mailjet.com", "elasticemail.com", "moosend.com", "campaignmonitor.com",
}

# TLDs overwhelmingly used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".fun", ".press", ".space",
    ".info", ".buzz", ".click", ".link", ".live", ".world",
}

# Enterprise-sounding words that should NEVER use freemail / bulk-mailer
ENTERPRISE_KEYWORDS = [
    "support", "service", "security", "helpdesk", "desk",
    "billing", "official", "bank", "finance", "account", "admin",
    "noreply", "no-reply", "verify", "verification", "team", "alert",
    "kyc", "aadhaar", "pan", "irs", "tax", "government", "gov",
    "it department", "hr department", "payroll", "compliance",
]

# Urgency/lure patterns → (regex, label, weight)
URGENCY_PATTERNS: list[tuple[str, str, int]] = [
    (r"(account|subscription|service|membership)\s*(has been|is|will be)\s*(suspended|terminated|deactivated|blocked|cancelled)",
     "Account Suspension / Termination Threat", 15),
    (r"(unauthorized|suspicious|unknown|unusual)\s*(sign.?in|login|activity|transaction|access|attempt)",
     "Fabricated Security Alert", 12),
    (r"(confirm|verify|update|validate|re-?verify)\s*(your)?\s*(identity|account|billing|card|password|ssn|pan|kyc|aadhaar|details|information)",
     "Credential / KYC Demand", 15),
    (r"(immediate action required|act now|within 24 hours|within 48 hours|within 12 hours|urgent response|final warning|last notice|last chance|expires today|expiring soon)",
     "False Urgency Countdown", 12),
    (r"(invoice|receipt|order confirmed|payment receipt|purchase)\s*#?[0-9a-zA-Z\-]+.*(\$|rs\.?|₹|usd|inr)",
     "Fake Invoice / Purchase Bait", 10),
    (r"(won|winner|lottery|prize|lucky|refund approved|tax refund|unclaimed|reward|congratulations.*selected|selected.*lucky)",
     "Prize / Lottery / Refund Hook", 15),
    (r"(click here|click the link|click below|click on this)\s*(to|and)?\s*(verify|confirm|update|activate|secure|claim|access)",
     "Deceptive CTA (Click to Verify)", 10),
    (r"(your (account|card|funds|money)\s*(will be|will|is being|has been)\s*(blocked|frozen|charged|debited|suspended|deactivated))",
     "Financial Fear Threat", 15),
    (r"(share|provide|send|give|enter)\s*(your)?\s*(otp|one.?time|pin|password|cvv|card number)",
     "OTP / Password Solicitation", 20),
    (r"(dear (customer|user|member|sir|ma'?am|valued client)|respected (customer|user|member))",
     "Generic Salutation (Impersonation Signal)", 5),
    (r"(your (package|parcel|shipment|delivery|order)\s*(is|has been|will be)\s*(held|delayed|pending|stopped|on hold))",
     "Fake Delivery / Package Scam", 12),
    (r"(remote\s*(access|desktop|session|control)|anydesk|teamviewer|quick\s*support|screen\s*share)",
     "Remote Access / RAT Request", 20),
    (r"(free (iphone|gift card|voucher|recharge|data|subscription|reward))",
     "Free Gift Lure", 10),
    (r"(kbc|kaun banega|crorepati|jio\s*lottery|airtel\s*lottery|bsnl\s*lottery)",
     "KBC / Telecom Lottery Scam (India)", 18),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(email: str) -> str:
    cleaned = email.strip().lower()
    if "<" in cleaned and ">" in cleaned:
        m = re.search(r"<([^>]+)>", cleaned)
        if m:
            cleaned = m.group(1).strip()
    return cleaned.split("@")[-1].strip() if "@" in cleaned else cleaned


def _get_tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return "." + parts[-1] if len(parts) > 1 else ""


def _has_numeric_subdomain(domain: str) -> bool:
    parts = domain.split(".")
    return len(parts) >= 3 and parts[0].isdigit()


def _domain_looks_throwaway(domain: str) -> bool:
    """Detect randomly generated / throwaway subdomains."""
    parts = domain.split(".")
    if len(parts) >= 3:
        sub = parts[0]
        # Hex hash subdomains (e.g. a3f2b1c7.brevosend.com)
        if len(sub) >= 6 and re.match(r'^[a-f0-9]+$', sub):
            return True
        # Long random alphanumeric
        if len(sub) >= 12:
            consonant_ratio = sum(1 for c in sub if c in "bcdfghjklmnpqrstvwxyz") / len(sub)
            if consonant_ratio > 0.65:
                return True
    return False


def _audit_sender(
    sender_name: str,
    sender_email: str,
    subject: str,
    via_domain: str,
    reply_to: str,
) -> tuple[SenderAudit, int, list[str]]:
    """
    Returns (SenderAudit, score_contribution, trap_labels_from_sender).
    """
    name_clean = (sender_name or "").lower()
    subj_clean = (subject or "").lower()
    domain = _extract_domain(sender_email)
    tld = _get_tld(domain)
    score = 0
    flags: list[str] = []
    traps: list[str] = []

    is_freemail = domain in FREEMAIL_DOMAINS
    is_bulk = any(domain == b or domain.endswith("." + b) for b in BULK_MAILER_DOMAINS)

    # ── Brand impersonation check ──────────────────────────────────────────────
    claimed_brand = None
    for brand in KNOWN_BRAND_DOMAINS:
        if brand in name_clean or brand in subj_clean:
            claimed_brand = brand
            break

    is_spoofed = False
    if claimed_brand:
        allowed = KNOWN_BRAND_DOMAINS[claimed_brand]
        matched = any(domain == d or domain.endswith("." + d) for d in allowed)
        if not matched:
            is_spoofed = True
            score += 50
            traps.append(f"Brand impersonation — '{claimed_brand.title()}' claimed, sending from '{domain}'")
            flags.append(f"Display name claims '{claimed_brand.title()}' but email is from '{domain}'")
        else:
            flags.append(f"Verified {claimed_brand.title()} official domain")
    elif is_freemail and any(w in name_clean for w in ENTERPRISE_KEYWORDS):
        is_spoofed = True
        score += 30
        traps.append(f"Enterprise entity using public freemail ({domain})")
        flags.append(f"Official-sounding name but using personal freemail domain ({domain})")

    # ── Numeric subdomain (e.g. 11654627.brevosend.com) ───────────────────────
    if _has_numeric_subdomain(domain):
        score += 18
        traps.append(f"Numeric subdomain ({domain.split('.')[0]}) — bulk-mailer pattern")
        flags.append(f"Numeric subdomain detected — typical of throwaway bulk-mail accounts")

    # ── Throwaway/random subdomain ────────────────────────────────────────────
    if _domain_looks_throwaway(domain):
        score += 14
        traps.append("Randomised subdomain — throwaway sender address")

    # ── Suspicious TLD ────────────────────────────────────────────────────────
    if tld in SUSPICIOUS_TLDS:
        score += 20
        traps.append(f"High-risk TLD '{tld}' — phishing registrations overwhelmingly use these")
        flags.append(f"Domain uses high-risk TLD '{tld}'")

    # ── Bulk mailer without brand claim (lower weight — could be legit marketing) ──
    if is_bulk and not claimed_brand:
        score += 10
        flags.append(f"Sent via bulk-mailer platform ({domain})")

    # ── via_domain mismatch: Gmail shows "via thirdparty.com" ────────────────
    via = (via_domain or "").lower().strip()
    if via and via != domain and not any(via == d or via.endswith("." + d) for d in BULK_MAILER_DOMAINS):
        score += 15
        traps.append(f"Relay mismatch — sent 'via {via}' but from-domain is '{domain}'")
        flags.append(f"Email relayed via '{via}' which doesn't match the declared sender domain")

    # ── Reply-To different from sender ────────────────────────────────────────
    rt = (reply_to or "").strip().lower()
    rt_domain = _extract_domain(rt) if rt and "@" in rt else ""
    if rt_domain and rt_domain != domain:
        score += 20
        traps.append(f"Reply-To hijack — replies go to '{rt_domain}', not '{domain}'")
        flags.append(f"Reply-To '{rt_domain}' differs from sender '{domain}' — classic phishing trick")

    # ── Display name contains a domain-like word different from actual domain ──
    name_domains = re.findall(r'\b([a-z0-9\-]+\.(com|in|net|org|co\.in))\b', name_clean)
    for nd, _ in name_domains:
        if nd not in domain and domain not in nd:
            score += 12
            traps.append(f"Display-name domain spoofing: name says '{nd}', actual is '{domain}'")
            flags.append(f"Display name references '{nd}' but actual domain is '{domain}'")
            break

    # ── Missing / malformed sender email ──────────────────────────────────────
    if not sender_email or "@" not in sender_email:
        score += 20
        traps.append("Sender email missing or malformed")
        flags.append("No valid sender email could be extracted")

    details = "; ".join(flags) if flags else "Sender domain appears standard — no known spoofing patterns."

    return (
        SenderAudit(
            claimed_brand=claimed_brand.title() if claimed_brand else None,
            actual_domain=domain,
            is_spoofed=is_spoofed,
            is_freemail_for_business=is_freemail and is_spoofed,
            details=details,
        ),
        score,
        traps,
    )


def _score_subject(subject: str) -> tuple[list[str], int]:
    s = (subject or "").lower()
    traps: list[str] = []
    score = 0
    if re.search(r"\b(urgent|important|action required|immediate|verify now|don.?t ignore|warning|alert)\b", s):
        traps.append("Urgency/fear keyword in subject")
        score += 8
    if re.search(r"\b(won|winner|prize|lottery|free|gift|congratulations|selected|lucky draw)\b", s):
        traps.append("Prize/reward lure in subject")
        score += 10
    if re.search(r"\b(invoice|receipt|order|delivery|shipment|tracking)\b", s) and re.search(r"#[0-9a-zA-Z]{4,}", s):
        traps.append("Fake order/invoice number in subject")
        score += 8
    if re.search(r"\b(password|otp|pin|security.?code)\b.*\b(expired|reset|changed|update|required)\b", s):
        traps.append("OTP/password reset lure in subject")
        score += 12
    if re.search(r"\b(account (suspended|blocked|deactivated|terminated|on hold))\b", s):
        traps.append("Account suspension bait in subject")
        score += 12
    if re.search(r"\b(re:|fwd:|fw:)\b.+\[.+\]", s):
        traps.append("Thread-spoofing header pattern in subject")
        score += 6
    return traps, score


def _score_body(body: str) -> tuple[list[str], int]:
    text = (body or "").lower()
    traps: list[str] = []
    total = 0
    seen: set[str] = set()
    for pattern, label, weight in URGENCY_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE) and label not in seen:
            traps.append(label)
            total += weight
            seen.add(label)
    return traps, min(total, 45)  # body contribution capped at 45


def _build_verdict(
    threat_score: int,
    sender_audit: SenderAudit,
    all_traps: list[str],
    analyzed_links: list[ExtractedLinkResult],
    is_spam_folder: bool,
    gmail_flagged: bool,
    has_dangerous_attachment: bool,
) -> tuple[str, str, str, str]:
    """Returns (risk_label, banner_color, safety_summary, ai_advice)."""

    force_dangerous = (
        gmail_flagged
        or has_dangerous_attachment
        or (sender_audit.is_spoofed and len(all_traps) >= 2)
    )

    if threat_score >= 60 or force_dangerous:
        label, color = "dangerous", "rose"
        summary = "⛔ High-Risk Phishing Email Detected"
        brand_note = f" It impersonates **{sender_audit.claimed_brand}**." if sender_audit.claimed_brand else ""
        gmail_note = " Gmail itself has flagged this as phishing." if gmail_flagged else ""
        attach_note = " A dangerous attachment was detected." if has_dangerous_attachment else ""
        trap_note = (f" Key signals: {', '.join(all_traps[:3])}." if all_traps else "")
        advice = (
            f"⛔ DO NOT click links, reply, or download attachments.{brand_note}{gmail_note}{attach_note}{trap_note} "
            f"If you already interacted, change passwords immediately and report at cybercrime.gov.in or call 1930."
        )

    elif threat_score >= 30 or is_spam_folder or sender_audit.is_spoofed:
        label, color = "suspicious", "amber"
        summary = "⚠️ Suspicious Email — Verify Before Acting"
        spam_note = " This email is in your spam folder." if is_spam_folder else ""
        spoof_note = f" The sender domain '{sender_audit.actual_domain}' may not be genuine." if sender_audit.is_spoofed else ""
        trap_note = (f" Suspicious patterns: {', '.join(all_traps[:2])}." if all_traps else "")
        advice = (
            f"⚠️ Exercise caution.{spam_note}{spoof_note}{trap_note} "
            f"Do not share personal information or OTPs. Verify directly with the company if needed."
        )

    else:
        label, color = "safe", "emerald"
        summary = "✅ Appears Legitimate"
        advice = (
            f"✅ No major phishing signals detected. Sender domain '{sender_audit.actual_domain}' "
            f"shows no known spoofing patterns. Standard caution: never share OTPs or passwords over email."
        )

    return label, color, summary, advice


# ── Main endpoint ─────────────────────────────────────────────────────────────

@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email_phishing(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:

    # ── 1. Sender audit + domain signals ──────────────────────────────────────
    sender_audit, sender_score, sender_traps = _audit_sender(
        payload.sender_name or "",
        payload.sender_email or "",
        payload.subject or "",
        payload.via_domain or "",
        payload.reply_to or "",
    )

    # ── 2. Subject scoring ────────────────────────────────────────────────────
    subject_traps, subject_score = _score_subject(payload.subject or "")

    # ── 3. Body linguistic scoring ────────────────────────────────────────────
    body_traps, body_score = _score_body(payload.body_snippet or "")

    # ── 4. Gmail-native context signals ───────────────────────────────────────
    context_score = 0
    context_traps: list[str] = []

    if payload.is_spam_folder:
        context_score += 25          # Gmail's own spam filter already flagged it
        context_traps.append("Gmail placed this email in the Spam folder")

    if payload.gmail_flagged_phishing:
        context_score += 40          # Gmail explicitly showed a phishing warning
        context_traps.append("Gmail's phishing detector flagged this email as phishing")

    if payload.has_dangerous_attachment:
        context_score += 30
        context_traps.append("Dangerous file attachment detected (.exe / .apk / .scr / .zip etc.)")

    # ── 5. Embedded link analysis ─────────────────────────────────────────────
    all_links: set[str] = set(payload.links)
    text_links = re.findall(r"https?://[^\s<>\"']+", payload.body_snippet or "")
    all_links.update(text_links)

    analyzed_links: list[ExtractedLinkResult] = []
    max_link_score = 0
    has_dangerous_link = False

    for link in list(all_links)[:6]:
        try:
            req = AnalysisRequest(url=link)
            res = await analyze_url(req)
            if res.risk_score > max_link_score:
                max_link_score = res.risk_score
            if res.label == "dangerous":
                has_dangerous_link = True
            analyzed_links.append(ExtractedLinkResult(
                url=link,
                risk_score=res.risk_score,
                label=res.label,
                reasons=res.reasons[:3],
            ))
        except Exception:
            pass

    link_score = 0
    link_traps: list[str] = []
    if has_dangerous_link:
        link_score = 40
        link_traps.append(f"Dangerous embedded link detected (max link score: {max_link_score}/100)")
    elif max_link_score >= 60:
        link_score = 28
        link_traps.append(f"High-risk embedded link (score: {max_link_score}/100)")
    elif max_link_score >= 40:
        link_score = 16
        link_traps.append(f"Suspicious embedded link (score: {max_link_score}/100)")
    elif max_link_score >= 20:
        link_score = 8

    # ── 6. Combine all signals ────────────────────────────────────────────────
    all_traps: list[str] = list(dict.fromkeys(
        sender_traps + subject_traps + body_traps + context_traps + link_traps
    ))

    threat_score = min(max(sender_score + subject_score + body_score + context_score + link_score, 0), 100)

    signal_breakdown = {
        "sender_domain_signals": min(sender_score, 99),
        "subject_signals": subject_score,
        "body_language_signals": body_score,
        "gmail_context_signals": context_score,
        "link_threat_signals": link_score,
        "total": threat_score,
    }

    # ── 7. Verdict ────────────────────────────────────────────────────────────
    risk_label, banner_color, safety_summary, ai_advice = _build_verdict(
        threat_score,
        sender_audit,
        all_traps,
        analyzed_links,
        payload.is_spam_folder,
        payload.gmail_flagged_phishing,
        payload.has_dangerous_attachment,
    )

    # Confidence is higher when we have more data sources
    data_richness = (
        (0.1 if payload.body_snippet and len(payload.body_snippet) > 200 else 0.0) +
        (0.05 if len(analyzed_links) > 0 else 0.0) +
        (0.05 if payload.is_spam_folder or payload.gmail_flagged_phishing else 0.0)
    )
    confidence = round(min(0.75 + data_richness, 0.98), 2)

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
