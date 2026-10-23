import re
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas.analysis import AnalysisRequest
from app.services.scoring_service import analyze_url

router = APIRouter(prefix="/analyze", tags=["smishing"])


class SmishingRequest(BaseModel):
    message: str
    sender_id: str | None = None


class ExtractedLinkResult(BaseModel):
    url: str
    risk_score: int
    label: str
    reasons: list[str]


class SmishingResponse(BaseModel):
    threat_score: int
    risk_label: str  # safe, suspicious, dangerous
    confidence: float
    impersonated_brand: str | None
    detected_traps: list[str]
    extracted_links: list[ExtractedLinkResult]
    ai_advice: str
    safety_summary: str


# Common Smishing Pattern Matchers
URGENCY_PATTERNS = [
    (r"(electricity|power|bijli)\s*(will be|bill|disconnect|cut off|power off)", "Threat of Electricity / Utility Disconnection"),
    (r"(account|sim|card|atm)\s*(will be|has been|is)\s*(blocked|suspended|deactivated|closed|frozen)", "False Account Block / Suspension Panic"),
    (r"(kyc|pan|aadhaar)\s*(update|expire|pending|mandatory|failed)", "Urgent KYC Expiration Pressure"),
    (r"(tonight|within 24 hours|within 2 hours|immediately|urgent|last notice|final warning)", "High-Pressure Countdown Trap"),
]

LURE_PATTERNS = [
    (r"(won|winner|lottery|lucky draw|cashback|prize)\s*(rs\.?|\$|[0-9]+)", "Fake Lottery / Cashback Reward Lure"),
    (r"(part[\s-]?time\s*job|earn\s*(rs\.?|\$|[0-9]+)\s*(per day|daily)|work from home)", "Fake WhatsApp Job / High Salary Scam"),
    (r"(pre-approved loan|instant credit|loan approved)", "Fake Pre-Approved Loan Bait"),
]

SECRET_DEMAND_PATTERNS = [
    (r"\b(otp|one time password|pin|upi pin|cvv|password)\b", "Soliciting Secret Codes (OTP/PIN)"),
    (r"(install|download)\s*(this)?\s*.*\.apk\b", "Dangerous Malicious App (.APK) Download Prompt"),
]

BRAND_MATCHERS = {
    "sbi": "State Bank of India (SBI)",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "paytm": "Paytm",
    "phonepe": "PhonePe",
    "gpay": "Google Pay",
    "india post": "India Post",
    "indiaofficial": "India Post",
    "electricity": "Electricity Board / Power Department",
    "income tax": "Income Tax Department",
    "fedex": "FedEx Courier",
    "dhl": "DHL Express",
    "netflix": "Netflix",
    "amazon": "Amazon",
    "paypal": "PayPal",
}


def extract_urls_from_text(text: str) -> list[str]:
    """Finds all HTTP/HTTPS links and bare domain links in text."""
    # Explicit URLs
    explicit = re.findall(r"https?://[^\s<>\"']+", text)
    # Bare shortlinks or domains
    bare = re.findall(r"\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly)/[^\s<>\"']+", text)
    # Add bare domain mentions like sbi-kyc-update.com/login
    generic_domains = re.findall(r"\b[a-zA-Z0-9-]+\.(?:com|in|org|net|xyz|top|live|ru|online|vip|biz|club|site)/[^\s<>\"']*", text)
    
    all_links = set(explicit)
    for b in bare:
        all_links.add(f"https://{b}")
    for g in generic_domains:
        if not g.startswith("http"):
            all_links.add(f"http://{g}")
        else:
            all_links.add(g)
            
    return list(all_links)


@router.post("/smishing", response_model=SmishingResponse)
async def analyze_smishing(payload: SmishingRequest) -> SmishingResponse:
    text = payload.message.strip()
    text_lower = text.lower()
    
    detected_traps: list[str] = []
    base_score = 0
    
    # 1. Detect Urgency Traps
    for pattern, desc in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            detected_traps.append(desc)
            base_score += 25
            
    # 2. Detect Prize / Job Lures
    for pattern, desc in LURE_PATTERNS:
        if re.search(pattern, text_lower):
            detected_traps.append(desc)
            base_score += 30
            
    # 3. Detect Secret Demands & Malicious Downloads
    for pattern, desc in SECRET_DEMAND_PATTERNS:
        if re.search(pattern, text_lower):
            detected_traps.append(desc)
            base_score += 35
            
    # 4. Detect Impersonated Brand
    impersonated_brand = None
    for keyword, brand_name in BRAND_MATCHERS.items():
        if keyword in text_lower or (payload.sender_id and keyword in payload.sender_id.lower()):
            impersonated_brand = brand_name
            break
            
    # 5. Extract and analyze embedded links
    extracted_urls = extract_urls_from_text(text)
    link_results: list[ExtractedLinkResult] = []
    has_dangerous_link = False
    
    for url in extracted_urls[:3]:  # inspect top 3 links
        try:
            link_analysis = await analyze_url(AnalysisRequest(url=url))
            link_results.append(
                ExtractedLinkResult(
                    url=url,
                    risk_score=link_analysis.risk_score,
                    label=link_analysis.label,
                    reasons=link_analysis.reasons[:3],
                )
            )
            if link_analysis.label == "dangerous":
                has_dangerous_link = True
                detected_traps.append(f"Contains Verified Dangerous Link: {url}")
                base_score += 45
            elif link_analysis.label == "suspicious":
                detected_traps.append(f"Contains Suspicious Unverified Link: {url}")
                base_score += 20
        except Exception:
            link_results.append(
                ExtractedLinkResult(
                    url=url,
                    risk_score=50,
                    label="suspicious",
                    reasons=["Unreachable or unverified link format"],
                )
            )

    # Calculate final threat score
    final_score = min(98, max(5, base_score))
    if has_dangerous_link:
        final_score = max(final_score, 85)
        
    if final_score >= 60:
        risk_label = "dangerous"
        safety_summary = "High Risk Scam Message: Do not click links, reply, or call any numbers mentioned."
        ai_advice = (
            f"This message shows classic fraud patterns ({', '.join(detected_traps[:2]) if detected_traps else 'unverified pressure'}). "
            "Real government authorities, banks, and utility providers never threaten immediate service cancellation over personal text messages."
        )
    elif final_score >= 25:
        risk_label = "suspicious"
        safety_summary = "Caution Required: This message contains unusual urgency or unverified links."
        ai_advice = "Verify this alert directly through the official app or customer helpline before taking any action. Never share OTP or PIN numbers."
    else:
        risk_label = "safe"
        safety_summary = "No immediate scam triggers detected in this text message."
        ai_advice = "The message appears regular, but always practice caution before tapping external links or sharing private details."

    return SmishingResponse(
        threat_score=final_score,
        risk_label=risk_label,
        confidence=0.92 if detected_traps else 0.75,
        impersonated_brand=impersonated_brand,
        detected_traps=detected_traps,
        extracted_links=link_results,
        ai_advice=ai_advice,
        safety_summary=safety_summary,
    )
