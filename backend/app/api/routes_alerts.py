from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas import AlertListResponse, AlertResponse
from app.services.runtime import runtime

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    limit: int = Query(default=100, ge=1, le=500, description="Max alerts to retrieve"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: medium, high"),
    acknowledged: Optional[bool] = Query(default=None, description="Filter by acknowledgement status"),
    rule_id: Optional[str] = Query(default=None, description="Filter by rule ID: PORT_SCAN, SYN_FLOOD, ARP_SPOOF")
) -> AlertListResponse:
    """Return filtered, newest-first in-memory alerts."""
    alerts_data = runtime.alert_store.get_alerts(
        limit=limit,
        severity=severity,
        acknowledged=acknowledged,
        rule_id=rule_id
    )
    return AlertListResponse(
        alerts=[AlertResponse(**a) for a in alerts_data["alerts"]],
        total=alerts_data["total"],
        unacknowledged_count=alerts_data["unacknowledged_count"],
    )


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(alert_id: str) -> AlertResponse:
    """Mark an alert as acknowledged."""
    updated = runtime.alert_store.acknowledge_alert(alert_id)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": {
                    "code": "ALERT_NOT_FOUND",
                    "message": f"Alert with ID '{alert_id}' was not found.",
                }
            },
        )
    return AlertResponse(**updated.to_dict())
