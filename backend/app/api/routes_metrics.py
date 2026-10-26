from typing import Optional
from fastapi import APIRouter, Query

from app.schemas import MetricsSummaryResponse, TopHostsResponse
from app.services.runtime import runtime

router = APIRouter(prefix="/metrics", tags=["Metrics"])


@router.get("/summary", response_model=MetricsSummaryResponse)
async def get_metrics_summary(
    window_seconds: int = Query(default=60, ge=5, le=3600, description="Rolling time window in seconds"),
    window: Optional[int] = Query(default=None, ge=5, le=3600, description="Alias for window_seconds")
) -> MetricsSummaryResponse:
    """Return cumulative session statistics and rolling window rates."""
    eff_window = window if window is not None else window_seconds
    summary = runtime.metrics_store.get_summary(window_seconds=eff_window)
    return MetricsSummaryResponse(**summary)


@router.get("/hosts", response_model=TopHostsResponse)
async def get_top_hosts(
    window_seconds: int = Query(default=60, ge=5, le=3600, description="Rolling time window in seconds"),
    window: Optional[int] = Query(default=None, ge=5, le=3600, description="Alias for window_seconds"),
    limit: int = Query(default=10, ge=1, le=100, description="Max hosts to return"),
    sort_by: str = Query(default="total_bytes", description="Sort criterion: total_bytes, tx_bytes, rx_bytes")
) -> TopHostsResponse:
    """Return top observed hosts sorted by cumulative or rolling bandwidth."""
    eff_window = window if window is not None else window_seconds
    safe_sort = sort_by if sort_by in ("total_bytes", "tx_bytes", "rx_bytes") else "total_bytes"
    top_data = runtime.metrics_store.get_top_hosts(
        window_seconds=eff_window,
        limit=limit,
        sort_by=safe_sort
    )
    return TopHostsResponse(**top_data)
