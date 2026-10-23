import logging
import os

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["explain"])
logger = logging.getLogger(__name__)


class ExplainRequest(BaseModel):
    label: str
    risk_score: int
    reasons: list[str]
    risk_breakdown: list[dict]


class ExplainResponse(BaseModel):
    explanation: str


def _clean_reason_for_humans(r: str) -> str:
    r = r.replace("possible typosquatting", "misspelled look-alike name")
    r = r.replace("Deceptive combosquatting:", "Fake replica:")
    r = r.replace("credential lure keywords", "asking for login or verification")
    r = r.replace("Domain has high character entropy", "scrambled random web address")
    r = r.replace("TLS certificate could not be validated", "unverified security certificate")
    return r


def _build_prompt(label: str, risk_score: int, reasons: list[str], risk_breakdown: list[dict]) -> str:
    reasons_text = "\n".join(f"- {_clean_reason_for_humans(r)}" for r in reasons) if reasons else "- No security red flags found"
    breakdown_text = "\n".join(
        f"- {item.get('category', '?')}: {item.get('score', 0)}/{item.get('max_score', 0)}"
        for item in risk_breakdown
    )
    return f"""You are a helpful internet safety assistant explaining website safety to everyday non-technical users.

Website Check Result:
- Safety Status: {label.upper()} (Risk: {risk_score}/100)
- Red flags found:
{reasons_text}

Write 2 simple, friendly sentences explaining what was found and what the user should do.
Use simple, everyday language (e.g. "fake website", "look-alike link", "do not enter passwords").
Do NOT use security jargon like "heuristics", "entropy", "RDAP", "TLS", "combosquatting", "SHA-256", or "subdomain depth".
Keep the explanation under 60 words."""


@router.post("/explain", response_model=ExplainResponse)
async def explain(payload: ExplainRequest) -> ExplainResponse:
    clean_reasons = [_clean_reason_for_humans(r) for r in payload.reasons]

    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        if payload.label == "dangerous":
            top_reasons = ", ".join(clean_reasons[:2]) if clean_reasons else "fake website patterns"
            return ExplainResponse(
                explanation=f"Warning: This looks like a dangerous fake site ({top_reasons}). Never enter your passwords, OTP, or credit card details here."
            )
        elif payload.label == "suspicious":
            top_reasons = ", ".join(clean_reasons[:2]) if clean_reasons else "unusual indicators"
            return ExplainResponse(
                explanation=f"Be careful: This link has warning signs ({top_reasons}). Double-check the website address before typing any personal details."
            )
        else:
            return ExplainResponse(
                explanation="All clear: This website appears legitimate and safe to use. No scam patterns were found."
            )

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash")
        prompt = _build_prompt(payload.label, payload.risk_score, payload.reasons, payload.risk_breakdown)
        response = model.generate_content(prompt)
        text = response.text.strip() if response and response.text else ""
        return ExplainResponse(explanation=text or "Safety check completed.")
    except Exception as e:
        logger.warning("gemini_explain_error", extra={"error": str(e)})
        top = ", ".join(clean_reasons[:2]) if clean_reasons else "warning signs"
        return ExplainResponse(
            explanation=f"Risk Score {payload.risk_score}/100: Flagged due to {top}. Be cautious before proceeding."
        )
