from fastapi import APIRouter
from app.services.recent_scans import RECENT_SCANS

router = APIRouter(tags=["scans"])


@router.get("/recent-scans")
def list_recent_scans(limit: int = 25) -> list[dict]:
    return RECENT_SCANS.list_recent(limit=limit)


@router.get("/recent-scans/latest")
def get_latest_scan() -> dict:
    latest = RECENT_SCANS.get_latest()
    return latest or {}
