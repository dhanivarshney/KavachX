"""KavachX Email Phishing & Spoofing Analysis Engine — v4 (context-aware, low false positives)."""

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
    risk_label: str
    confidence: float
    sender_audit: SenderAudit
    detected_traps: list[str]
    embedded_links: list[ExtractedLinkResult]
    ai_advice: str
    safety_summary: str
    banner_color: str
    signal_breakdown: dict


# ── TRUSTED domains — these get a score REDUCTION ────────────────────────────
# Add any domain here that is a known legitimate sender.
# Trust bonus: -25 applied after all other scoring.
TRUSTED_DOMAINS: set[str] = {
    # Job portals
    "naukri.com", "naukricampus.com", "shine.com", "monster.com",
    "indeed.com", "glassdoor.com", "internshala.com", "letsintern.com",
    "hirist.com", "foundit.in", "apna.co", "cutshort.io",
    # LinkedIn / professional
    "linkedin.com", "e.linkedin.com", "em.linkedin.com",
    # GitHub / developer tools
    "github.com", "notifications.github.com",
    # Google services
    "google.com", "google.co.in", "accounts.google.com", "googlemail.com",
    "workspace.google.com",
    # Microsoft
    "microsoft.com", "office.com", "teams.microsoft.com",
    # Colleges/edu (handled by suffix below)
    # Payment + fintech (legit)
    "razorpay.com", "cashfree.com", "billdesk.com", "payu.in",
    # Indian banks (official)
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotakbank.com", "onlinesbi.sbi",
    # Govt India
    "gov.in", "nic.in", "uidai.gov.in", "incometax.gov.in",
    # Large corps
    "amazon.com", "amazon.in", "flipkart.com", "zomato.com",
    "swiggy.com", "ola.com", "uber.com",
    "infosys.com", "tcs.com", "wipro.com", "hcl.com", "accenture.com",
    "ibm.com", "oracle.com", "salesforce.com", "adobe.com",
    "zoho.com", "freshworks.com", "atlassian.com",
    # FOSS / developer
    "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
    # Comms
    "slack.com", "zoom.us", "notion.so", "trello.com",
    # Email infra of trusted senders
    "naukricampus.com", "talent.naukri.com",
}

# ── KNOWN BRAND domains (for spoofing detection) ──────────────────────────────
KNOWN_BRAND_DOMAINS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co.in", "gmail.com", "accounts.google.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com", "kotakbank.com"],
    "facebook": ["facebook.com", "meta.com", "fb.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com", "e.linkedin.com", "em.linkedin.com"],
    "india post": ["indiapost.gov.in"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "income tax": ["incometax.gov.in"],
    "github": ["github.com", "notifications.github.com"],
    "twitter": ["twitter.com", "x.com"],
    "dropbox": ["dropbox.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "zomato": ["zomato.com"],
    "flipkart": ["flipkart.com"],
    "naukri": ["naukri.com", "naukricampus.com", "iimjobs.com"],
    "infosys": ["infosys.com"],
    "tcs": ["tcs.com"],
    "wipro": ["wipro.com"],
    "razorpay": ["razorpay.com"],
}

# Bulk-mail platforms — legitimate when used by trusted brands, abused by spammers
BULK_MAILER_DOMAINS: set[str] = {
    "brevosend.com", "sendinblue.com", "mailchimp.com", "sendgrid.net",
    "amazonses.com", "mailgun.org", "postmarkapp.com", "sparkpostmail.com",
    "mandrillapp.com", "constantcontact.com", "klaviyomail.com",
    "hubspotemail.net", "createsend.com", "mailjet.com",
    "elasticemail.com", "moosend.com",
}

FREEMAIL_DOMAINS: set[str] = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "protonmail.com",
    "mail.com", "rediffmail.com", "yahoo.in", "yahoo.co.in",
}

SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".fun", ".press", ".space",
    ".buzz", ".click", ".link", ".live", ".world",
}

ENTERPRISE_KEYWORDS = [
    "support", "service", "security", "helpdesk", "billing", "official",
    "bank", "finance", "account", "admin", "noreply", "no-reply",
    "verify", "verification", "alert", "kyc", "aadhaar", "pan",
    "irs", "tax", "government", "gov", "compliance",
]

# ── SAFE CONTEXT patterns — if these match, cancel a specific phishing pattern ──
# Format: (safe_pattern, list_of_trap_labels_it_cancels)
SAFE_CONTEXT_PATTERNS: list[tuple[str, list[str]]] = [
    # Internship / job offer context — "selected" / "congratulations" are normal
    (
        r"(internship|job offer|offer letter|appointment|joining|campus|placement|recruit|hired|position|role|interview)",
        ["Prize/Lottery/Refund Hook", "Prize/Reward lure in subject", "Prize/reward lure in subject",
         "Prize / Lottery / Refund Hook"],
    ),
    # OTP from bank own domain — legitimate 2FA
    (
        r"(your (otp|one.?time password|verification code) (is|:|for))",
        ["OTP / Password Solicitation"],
    ),
    # Newsletter / marketing unsubscribe footer — normal for legit mailers
    (
        r"(unsubscribe|manage (your )?(preferences|subscription)|email preferences|update preferences)",
        ["Generic Salutation (Impersonation Signal)"],
    ),
    # Transactional delivery context — "order", "shipment" from known e-commerce
    (
        r"(order (confirmed|placed|shipped|dispatched|delivered)|track (your )?(order|package|shipment))",
        ["Fake Delivery / Package Scam"],
    ),
    # Password reset that YOU initiated — subject says "you requested"
    (
        r"(you (recently )?(requested|initiated|triggered)|if you did not request)",
        ["OTP/password reset lure in subject"],
    ),
]

# ── URGENCY / LURE patterns — (regex, label, weight) ─────────────────────────
URGENCY_PATTERNS: list[tuple[str, str, int]] = [
    (r"(account|subscription|service|membership)\s*(has been|is|will be)\s*(suspended|terminated|deactivated|blocked|cancelled)",
     "Account Suspension/Termination Threat", 15),
    (r"(unauthorized|suspicious|unknown|unusual)\s*(sign.?in|login|activity|transaction|access|attempt)",
     "Fabricated Security Alert", 12),
    (r"(confirm|verify|update|validate|re-?verify)\s*(your)?\s*(identity|account|billing|card|password|ssn|pan|kyc|aadhaar|details)",
     "Credential/KYC Verification Demand", 15),
    (r"(immediate action required|act now|within 24 hours|within 48 hours|urgent response|final warning|last notice|last chance|expires today|expiring soon)",
     "False Urgency Countdown", 12),
    (r"(invoice|receipt|order confirmed|payment receipt)\s*#?[0-9a-zA-Z\-]+.*(\$|rs\.?|₹|usd|inr)(?!.*track)",
     "Fake Invoice/Purchase Bait", 10),
    # Prize pattern — but only when NOT in job context (we cancel it with SAFE_CONTEXT_PATTERNS above)
    (r"(won|winner|lottery|prize|lucky draw|refund approved|tax refund|unclaimed reward|kbc|kaun banega)",
     "Prize/Lottery/Refund Hook", 15),
    (r"(click here|click the link|click below)\s*(to|and)?\s*(verify|confirm|update|activate|secure|claim)",
     "Deceptive CTA (Click to Verify)", 10),
    (r"(your (account|card|funds|money)\s*(will be|has been|is being)\s*(blocked|frozen|charged|debited|suspended))",
     "Financial Fear/Freeze Threat", 15),
    (r"(share|provide|send|give|enter)\s*(your)?\s*(otp|one.?time|pin|cvv|card number)(?!.*is\s+\d)",
     "OTP / Password Solicitation", 20),
    (r"(remote\s*(access|desktop|session|control)|anydesk|teamviewer|quick\s*support)",
     "Remote Access / RAT Request", 25),
    (r"(free (iphone|gift card|voucher|recharge|data)(?!.*plan|.*service))",
     "Free Gift Lure", 10),
    (r"(dear (customer|user|member|sir|ma'?am|valued client)|respected (customer|user|member))\b(?!.*team|.*campus|.*naukri)",
     "Generic Salutation (Impersonation Signal)", 5),
    (r"(your (package|parcel|shipment)\s*(is|has been)\s*(held|delayed|stopped|pending customs))",
     "Fake Delivery/Package Scam", 12),
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


def _base_domain(domain: str) -> str:
    """Extract registrable domain: 'mail.naukri.com' → 'naukri.com'."""
    parts = domain.split(".")
    if len(parts) >= 2:
        # Handle .co.in, .gov.in, .ac.in style
        if len(parts) >= 3 and parts[-2] in ("co", "gov", "ac", "org", "net", "edu"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain


def _is_trusted(domain: str) -> bool:
    """True if domain or its base domain is in TRUSTED_DOMAINS, or has .edu/.gov/.ac.in TLD."""
    base = _base_domain(domain)
    if base in TRUSTED_DOMAINS or domain in TRUSTED_DOMAINS:
        return True
    # Government / academic TLDs
    if domain.endswith(".gov.in") or domain.endswith(".nic.in") or \
       domain.endswith(".ac.in") or domain.endswith(".edu.in") or \
       domain.endswith(".edu"):
        return True
    return False


def _has_numeric_subdomain(domain: str) -> bool:
    parts = domain.split(".")
    return len(parts) >= 3 and parts[0].isdigit()


def _domain_looks_throwaway(domain: str) -> bool:
    parts = domain.split(".")
    if len(parts) >= 3:
        sub = parts[0]
        if len(sub) >= 6 and re.match(r'^[a-f0-9]+$', sub):
            return True
        if len(sub) >= 12:
            consonant_ratio = sum(1 for c in sub if c in "bcdfghjklmnpqrstvwxyz") / len(sub)
            if consonant_ratio > 0.65:
                return True
    return False


def _apply_safe_context(traps: list[str], combined_text: str) -> list[str]:
    """
    Remove trap labels that are cancelled by safe context patterns.
    e.g. 'Prize/Lottery Hook' cancelled when body talks about internship/job offers.
    """
    active_traps = list(traps)
    for safe_pattern, cancels in SAFE_CONTEXT_PATTERNS:
        if re.search(safe_pattern, combined_text, re.IGNORECASE):
            active_traps = [t for t in active_traps if t not in cancels]
    return active_traps


# ── Sender audit ──────────────────────────────────────────────────────────────

def _audit_sender(
    sender_name: str,
    sender_email: str,
    subject: str,
    via_domain: str,
    reply_to: str,
) -> tuple[SenderAudit, int, list[str]]:
    name_clean = (sender_name or "").lower()
    subj_clean = (subject or "").lower()
    domain = _extract_domain(sender_email)
    base = _base_domain(domain)
    tld = _get_tld(domain)
    score = 0
    flags: list[str] = []
    traps: list[str] = []

    trusted = _is_trusted(domain)
    is_freemail = base in FREEMAIL_DOMAINS
    is_bulk = any(domain == b or domain.endswith("." + b) for b in BULK_MAILER_DOMAINS)

    # ── Brand impersonation ────────────────────────────────────────────────────
    claimed_brand: str | None = None
    for brand in KNOWN_BRAND_DOMAINS:
        if brand in name_clean or brand in subj_clean:
            claimed_brand = brand
            break

    is_spoofed = False
    if claimed_brand:
        allowed = KNOWN_BRAND_DOMAINS[claimed_brand]
        matched = any(domain == d or domain.endswith("." + d) for d in allowed)
        # Also trust if via_domain matches allowed (e.g. LinkedIn via em.linkedin.com)
        via_matched = via_domain and any(
            via_domain == d or via_domain.endswith("." + d) for d in allowed
        )
        if not matched and not via_matched:
            is_spoofed = True
            score += 50
            traps.append(f"Brand impersonation — '{claimed_brand.title()}' claimed, email from '{domain}'")
            flags.append(f"Display name claims '{claimed_brand.title()}' but email is from '{domain}'")
        else:
            flags.append(f"Verified {claimed_brand.title()} official infrastructure")
    elif is_freemail and any(w in name_clean for w in ENTERPRISE_KEYWORDS):
        is_spoofed = True
        score += 30
        traps.append(f"Enterprise entity using public freemail ({domain})")
        flags.append(f"Official-sounding name but uses personal email provider ({domain})")

    # ── Only apply domain-level penalties if NOT a trusted sender ─────────────
    if not trusted and not claimed_brand:
        if _has_numeric_subdomain(domain):
            score += 18
            traps.append(f"Numeric subdomain ({domain.split('.')[0]}) — bulk-mailer abuse pattern")
            flags.append(f"Numeric subdomain in sender — typical of throwaway bulk-mail accounts")

        if _domain_looks_throwaway(domain) and not is_bulk:
            score += 12
            traps.append("Randomised subdomain — throwaway sender address")

        if tld in SUSPICIOUS_TLDS:
            score += 20
            traps.append(f"High-risk TLD '{tld}' — heavily used in phishing campaigns")
            flags.append(f"Domain TLD '{tld}' is associated with phishing registrations")

        if is_bulk:
            # Bulk mailer from untrusted, unbranded sender — mild flag
            score += 8
            flags.append(f"Sent via bulk-mail platform ({domain}) without a verified brand identity")

    # ── via_domain check — only flag if trusted sender not involved ───────────
    via = (via_domain or "").lower().strip()
    if via and not trusted and claimed_brand:
        # Already handled in brand spoofing above
        pass
    elif via and not trusted and not is_bulk:
        via_base = _base_domain(via)
        if via_base != base and not _is_trusted(via):
            score += 12
            traps.append(f"Email relayed via unrecognised domain '{via}'")
            flags.append(f"Sent 'via {via}' — relay domain not matching sender or trusted infrastructure")

    # ── Reply-To hijack ────────────────────────────────────────────────────────
    rt = (reply_to or "").strip().lower()
    rt_domain = _extract_domain(rt) if rt and "@" in rt else ""
    rt_base = _base_domain(rt_domain) if rt_domain else ""
    if rt_base and rt_base != base and not _is_trusted(rt_domain):
        score += 20
        traps.append(f"Reply-To hijack — replies redirected to '{rt_domain}' (not '{domain}')")
        flags.append(f"Reply-To '{rt_domain}' differs from sender — classic phishing interception trick")

    # ── Display name domain spoofing ───────────────────────────────────────────
    if not trusted:
        name_domains = re.findall(r'\b([a-z0-9\-]+\.(com|in|net|org|co\.in))\b', name_clean)
        for nd, _ in name_domains:
            if nd not in domain and domain not in nd and not _is_trusted(nd):
                score += 12
                traps.append(f"Display-name domain mismatch — name says '{nd}', actual domain is '{domain}'")
                flags.append(f"Display name references '{nd}' but actual sending domain is '{domain}'")
                break

    # ── Missing/malformed sender ───────────────────────────────────────────────
    if not sender_email or "@" not in sender_email:
        score += 20
        traps.append("Sender email missing or malformed")
        flags.append("No valid sender email extracted")

    # ── Trust bonus — well-known legitimate sender ─────────────────────────────
    if trusted and not is_spoofed:
        score = max(score - 25, 0)
        flags.append(f"Sender domain '{domain}' is a recognised legitimate service")

    details = "; ".join(flags) if flags else f"Sender '{domain}' — no known spoofing patterns detected."

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
    traps, score = [], 0
    if re.search(r"\b(urgent|action required|immediate|verify now|warning)\b", s) and \
       not re.search(r"\b(interview|internship|job|offer|campus)\b", s):
        traps.append("Urgency keyword in subject")
        score += 8
    if re.search(r"\b(won|winner|lottery|lucky draw|prize|kbc)\b", s):
        traps.append("Prize/reward lure in subject")
        score += 10
    if re.search(r"\b(invoice|receipt)\b.+#[0-9a-zA-Z]{4,}", s):
        traps.append("Fake invoice number in subject")
        score += 8
    if re.search(r"\b(password|otp|pin|security.?code)\b.+\b(expired|reset|required)\b", s):
        traps.append("OTP/password reset lure in subject")
        score += 12
    if re.search(r"\b(account (suspended|blocked|deactivated|terminated))\b", s):
        traps.append("Account suspension bait in subject")
        score += 12
    # "Congratulations" + job/internship → NOT a scam
    if re.search(r"\bcongratulations\b", s) and not re.search(r"\b(internship|job|offer|campus|select|hired)\b", s):
        traps.append("Congratulations lure (without job context)")
        score += 8
    return traps, score


def _score_body(body: str, combined_text: str) -> tuple[list[str], int]:
    text = (body or "").lower()
    traps, total, seen = [], 0, set()
    for pattern, label, weight in URGENCY_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE) and label not in seen:
            traps.append(label)
            total += weight
            seen.add(label)
    # Apply safe-context cancellation immediately
    traps = _apply_safe_context(traps, combined_text)
    # Recalculate total after cancellation
    total = sum(w for _, l, w in URGENCY_PATTERNS if l in traps)
    return traps, min(total, 40)


def _build_advice(
    threat_score: int,
    sender_audit: SenderAudit,
    all_traps: list[str],
    is_spam: bool,
    gmail_flagged: bool,
    has_attach: bool,
) -> tuple[str, str, str, str]:
    force_danger = gmail_flagged or has_attach or \
        (sender_audit.is_spoofed and any(
            t for t in all_traps if "otp" in t.lower() or "hijack" in t.lower() or "impersonation" in t.lower()
        ))

    if threat_score >= 60 or force_danger:
        label, color, summary = "dangerous", "rose", "⛔ High-Risk Phishing Email Detected"
        brand = f" Impersonates **{sender_audit.claimed_brand}**." if sender_audit.claimed_brand else ""
        gf = " Gmail itself flagged this as phishing." if gmail_flagged else ""
        at = " Dangerous attachment detected." if has_attach else ""
        tp = f" Signals: {', '.join(all_traps[:3])}." if all_traps else ""
        advice = f"⛔ DO NOT click links, reply, or open attachments.{brand}{gf}{at}{tp} If you already interacted, change passwords immediately and report at cybercrime.gov.in (1930)."

    elif threat_score >= 28 or is_spam or sender_audit.is_spoofed:
        label, color, summary = "suspicious", "amber", "⚠️ Suspicious — Verify Before Acting"
        sp = " This email is in your spam folder." if is_spam else ""
        sf = f" Sender domain '{sender_audit.actual_domain}' may not be genuine." if sender_audit.is_spoofed else ""
        tp = f" Patterns: {', '.join(all_traps[:2])}." if all_traps else ""
        advice = f"⚠️ Be cautious.{sp}{sf}{tp} Do not share OTPs, passwords, or personal information. Verify directly with the organisation."

    else:
        label, color, summary = "safe", "emerald", "✅ Appears Legitimate"
        advice = (
            f"✅ No phishing signals detected. Sender domain '{sender_audit.actual_domain}' "
            f"matches expected patterns. Standard caution: never share OTPs or passwords over email."
        )

    return label, color, summary, advice


# ── Main endpoint ─────────────────────────────────────────────────────────────

@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email_phishing(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:

    combined_text = " ".join([
        payload.sender_name or "",
        payload.subject or "",
        payload.body_snippet or "",
    ]).lower()

    # 1. Sender
    sender_audit, sender_score, sender_traps = _audit_sender(
        payload.sender_name or "",
        payload.sender_email or "",
        payload.subject or "",
        payload.via_domain or "",
        payload.reply_to or "",
    )

    # 2. Subject
    subject_traps, subject_score = _score_subject(payload.subject or "")

    # 3. Body (safe-context cancellation applied inside)
    body_traps, body_score = _score_body(payload.body_snippet or "", combined_text)

    # 4. Gmail context
    context_score, context_traps = 0, []
    if payload.is_spam_folder:
        context_score += 25
        context_traps.append("Gmail placed this email in the Spam folder")
    if payload.gmail_flagged_phishing:
        context_score += 40
        context_traps.append("Gmail's own phishing detector flagged this email")
    if payload.has_dangerous_attachment:
        context_score += 30
        context_traps.append("Dangerous file attachment (.exe/.apk/.scr/.zip etc.)")

    # 5. Links
    all_links: set[str] = set(payload.links)
    all_links.update(re.findall(r"https?://[^\s<>\"']+", payload.body_snippet or ""))

    analyzed_links: list[ExtractedLinkResult] = []
    max_link_score, has_dangerous_link = 0, False

    for link in list(all_links)[:6]:
        try:
            res = await analyze_url(AnalysisRequest(url=link))
            max_link_score = max(max_link_score, res.risk_score)
            if res.label == "dangerous":
                has_dangerous_link = True
            analyzed_links.append(ExtractedLinkResult(
                url=link, risk_score=res.risk_score, label=res.label, reasons=res.reasons[:3],
            ))
        except Exception:
            pass

    link_score, link_traps = 0, []
    if has_dangerous_link:
        link_score, link_traps = 40, [f"Dangerous embedded link (score {max_link_score}/100)"]
    elif max_link_score >= 60:
        link_score, link_traps = 25, [f"High-risk link detected (score {max_link_score}/100)"]
    elif max_link_score >= 40:
        link_score, link_traps = 14, [f"Suspicious link detected (score {max_link_score}/100)"]
    elif max_link_score >= 20:
        link_score = 6

    # 6. Combine + apply final context cancellation
    raw_traps = list(dict.fromkeys(sender_traps + subject_traps + body_traps + context_traps + link_traps))
    all_traps = _apply_safe_context(raw_traps, combined_text)

    threat_score = min(max(sender_score + subject_score + body_score + context_score + link_score, 0), 100)

    signal_breakdown = {
        "sender_domain_signals": min(sender_score, 99),
        "subject_signals": subject_score,
        "body_language_signals": body_score,
        "gmail_context_signals": context_score,
        "link_threat_signals": link_score,
        "total": threat_score,
    }

    # 7. Verdict
    risk_label, banner_color, safety_summary, ai_advice = _build_advice(
        threat_score, sender_audit, all_traps,
        payload.is_spam_folder, payload.gmail_flagged_phishing, payload.has_dangerous_attachment,
    )

    confidence = round(min(
        0.75
        + (0.08 if payload.body_snippet and len(payload.body_snippet) > 200 else 0.0)
        + (0.05 if analyzed_links else 0.0)
        + (0.05 if payload.is_spam_folder or payload.gmail_flagged_phishing else 0.0),
        0.98,
    ), 2)

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
