from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.services.trustpilot_service import get_trustpilot_reputation

router = APIRouter(prefix="/reputation", tags=["reputation"])


class StarBreakdownItem(BaseModel):
    star: int
    percentage: int


class TrustpilotResponse(BaseModel):
    domain: str
    status: str
    trust_score: float
    star_rating: int
    total_reviews: str
    rating_label: str
    is_unverified_scam_indicator: bool
    star_distribution: list[StarBreakdownItem]
    top_complaints: list[str]
    community_verdict: str
    trustpilot_url: str


@router.get("/trustpilot", response_model=TrustpilotResponse)
async def get_reputation(domain: str = Query(..., description="Target domain or URL to inspect")):
    data = get_trustpilot_reputation(domain)
    return TrustpilotResponse(**data)
