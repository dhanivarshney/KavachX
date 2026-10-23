import re
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/analyze", tags=["vishing"])


class VishingRequest(BaseModel):
    transcript: str
    caller_number: str | None = None


class VishingResponse(BaseModel):
    threat_score: int
    risk_label: str  # safe, suspicious, dangerous
    confidence: float
    detected_tactics: list[str]
    coercion_type: str | None
    safety_summary: str
    immediate_defense_advice: str


# Common Vishing Manipulation Patterns
DIGITAL_ARREST_PATTERNS = [
    (r"\b(cbi|police|customs|crime branch|cyber cell|narcotics|ed|enforcement directorate)\b", "Impersonating Law Enforcement / Police"),
    (r"(illegal parcel|drugs found|passport seized|money laundering|arrest warrant|fir registered)", "Fabricated Legal Crime / Illegal Parcel Accusation"),
    (r"(digital arrest|video interrogation|skype call|stay on video|do not disconnect|do not tell anyone)", "Digital Arrest & Isolation Coercion"),
    (r"(supreme court|secret government account|reserve bank verification|safety deposit)", "Fake Government Clearance Deposit Scheme"),
]

SECRET_THEFT_PATTERNS = [
    (r"\b(otp|one time password|verification code|6-digit code|six digit code)\b", "Demanding Secret Verification Code (OTP)"),
    (r"\b(upi pin|atm pin|security pin|card pin)\b", "Coercing UPI / Card Security PIN"),
    (r"(enter (your )?pin to receive|scan qr to receive (money|cashback))", "Classic UPI Reversal Scam ('PIN to Receive Money')"),
    (r"\b(cvv|card number|expiry date)\b", "Direct Debit/Credit Card Credential Harvesting"),
]

REMOTE_ACCESS_PATTERNS = [
    (r"\b(anydesk|teamviewer|quicksupport|rustdesk|ultraviewer)\b", "Demanding Remote Control App (AnyDesk/TeamViewer)"),
    (r"(download|install)\s*(support|help|verification)\s*(app|tool)", "Prompting Screen Sharing / Remote Access Software"),
    (r"(virus on computer|phone hacked|clean your device)", "Fake Tech Support Virus Panic"),
]

URGENCY_PATTERNS = [
    (r"(immediately|within (10|15|30|60) minutes|right now|before it's too late|last chance)", "High-Pressure Countdown Tactic"),
    (r"(card (is|has been) blocked|account frozen|sim deactivated)", "False Account Block Emergency"),
]


@router.post("/vishing", response_model=VishingResponse)
async def analyze_vishing(payload: VishingRequest) -> VishingResponse:
    transcript = payload.transcript.strip()
    transcript_lower = transcript.lower()

    detected_tactics: list[str] = []
    base_score = 0
    coercion_type = None

    # 1. Digital Arrest Checks
    digital_arrest_hits = 0
    for pattern, label in DIGITAL_ARREST_PATTERNS:
        if re.search(pattern, transcript_lower):
            detected_tactics.append(label)
            digital_arrest_hits += 1
            base_score += 35

    if digital_arrest_hits >= 2:
        coercion_type = "Digital Arrest / Fake Police Extortion Scam"

    # 2. Secret Demands
    secret_hits = 0
    for pattern, label in SECRET_THEFT_PATTERNS:
        if re.search(pattern, transcript_lower):
            detected_tactics.append(label)
            secret_hits += 1
            base_score += 40

    if secret_hits >= 1 and not coercion_type:
        coercion_type = "Financial Credential / OTP Theft Scam"

    # 3. Remote Access Traps
    remote_hits = 0
    for pattern, label in REMOTE_ACCESS_PATTERNS:
        if re.search(pattern, transcript_lower):
            detected_tactics.append(label)
            remote_hits += 1
            base_score += 45

    if remote_hits >= 1 and not coercion_type:
        coercion_type = "Tech Support / Remote Device Takeover Scam"

    # 4. Urgency
    for pattern, label in URGENCY_PATTERNS:
        if re.search(pattern, transcript_lower):
            detected_tactics.append(label)
            base_score += 20

    # Score calculation
    final_score = min(99, max(5, base_score))

    if final_score >= 60:
        risk_label = "dangerous"
        safety_summary = "DANGEROUS SCAM CALL: Hang up immediately and do not comply with any requests."
        immediate_defense_advice = (
            "🚨 CRITICAL SAFETY WARNING:\n"
            "1. Real police, CBI, and judges NEVER conduct arrests or interrogations over video/phone calls.\n"
            "2. Never read out OTPs or enter your UPI PIN to 'receive' money.\n"
            "3. Never install AnyDesk or TeamViewer at the instruction of an unknown caller.\n"
            "4. Report this number to the National Cyber Crime Helpline: 1930."
        )
    elif final_score >= 25:
        risk_label = "suspicious"
        safety_summary = "CAUTION: This call contains unusual pressure or sensitive financial inquiries."
        immediate_defense_advice = (
            "Verify the caller's identity independently by calling your official bank branch or customer service number. "
            "Never share verification codes or passwords over phone calls."
        )
    else:
        risk_label = "safe"
        safety_summary = "No high-risk scam or extortion patterns detected in this transcript."
        immediate_defense_advice = (
            "The conversation appears normal, but remember: legitimate organizations will never ask for your private passwords or OTPs."
        )

    return VishingResponse(
        threat_score=final_score,
        risk_label=risk_label,
        confidence=0.94 if detected_tactics else 0.70,
        detected_tactics=detected_tactics,
        coercion_type=coercion_type,
        safety_summary=safety_summary,
        immediate_defense_advice=immediate_defense_advice,
    )
