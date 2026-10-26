from typing import Optional
from fastapi import APIRouter, Query

from app.schemas import PacketMetadataResponse, RecentPacketsResponse
from app.services.runtime import runtime

router = APIRouter(tags=["Packets"])


@router.get("/packets", response_model=RecentPacketsResponse)
async def get_recent_packets(
    limit: int = Query(default=50, ge=1, le=100, description="Max packets to retrieve"),
    protocol: Optional[str] = Query(default=None, description="Optional protocol filter (e.g. TCP, UDP, ARP, ICMP)")
) -> RecentPacketsResponse:
    """Return newest-first bounded list of recent packet metadata."""
    packets_data = runtime.metrics_store.get_recent_packets(limit=limit, protocol=protocol)
    parsed_packets = [PacketMetadataResponse(**p) for p in packets_data]
    return RecentPacketsResponse(packets=parsed_packets, total=len(parsed_packets))
