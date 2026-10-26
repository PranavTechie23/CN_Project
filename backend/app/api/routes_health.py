from fastapi import APIRouter
from app.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return liveness and service identifier."""
    return HealthResponse(status="ok", service="network-traffic-analyzer")
