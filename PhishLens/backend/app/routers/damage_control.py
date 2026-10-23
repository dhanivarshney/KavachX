"""Damage-Control Mode API endpoints."""

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from typing import Any

from app.services.damage_control_service import (
    create_incident,
    get_incident,
    toggle_action,
    close_incident,
    generate_dossier,
    INCIDENT_LABELS,
)

router = APIRouter(prefix="/api/damage-control", tags=["damage-control"])


class CreateIncidentRequest(BaseModel):
    incident_type: str
    channel: str | None = None
    details: dict[str, Any] | None = None


@router.get("/incident-types")
async def list_incident_types():
    """Return available incident types with labels."""
    return {
        "types": [
            {"key": k, "label": v}
            for k, v in INCIDENT_LABELS.items()
        ]
    }


@router.post("/incidents")
async def create_new_incident(req: CreateIncidentRequest):
    """Create a new incident with dynamic contextual rules."""
    try:
        result = create_incident(req.incident_type, req.channel, req.details)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/incidents/{incident_id}")
async def get_single_incident(incident_id: str):
    """Get a specific incident with its recovery checklist and dynamic metadata."""
    result = get_incident(incident_id)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.patch("/incidents/{incident_id}/actions/{action_id}")
async def toggle_incident_action(incident_id: str, action_id: str):
    """Toggle an action's completed status."""
    result = toggle_action(incident_id, action_id)
    if not result:
        raise HTTPException(status_code=404, detail="Incident or action not found")
    return result


@router.post("/incidents/{incident_id}/close")
async def close_single_incident(incident_id: str):
    """Close/resolve an incident."""
    result = close_incident(incident_id)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.get("/incidents/{incident_id}/dossier")
async def download_incident_dossier(incident_id: str):
    """Generate and return a plain text complaint dossier."""
    dossier = generate_dossier(incident_id)
    if not dossier:
        raise HTTPException(status_code=404, detail="Incident not found")
    return Response(
        content=dossier,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="PhishLens_Incident_{incident_id}.txt"'},
    )
