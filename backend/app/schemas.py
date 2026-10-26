from typing import Any
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = Field(default="ok", description="Service health status")
    service: str = Field(default="network-traffic-analyzer", description="Service identifier")


class ErrorDetail(BaseModel):
    """Structured error detail schema."""
    code: str
    message: str


class ErrorResponse(BaseModel):
    """Standard error response wrapper."""
    error: ErrorDetail


class PacketMetadataResponse(BaseModel):
    """Normalized metadata for a single observed packet."""
    packet_id: int
    timestamp: str
    interface: str
    protocol: str
    length_bytes: int
    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_flags: str | None = None
    arp_sender_ip: str | None = None
    arp_sender_mac: str | None = None
    arp_target_ip: str | None = None


class RecentPacketsResponse(BaseModel):
    """List of recent packet metadata."""
    packets: list[PacketMetadataResponse]
    total: int


class ProtocolMetric(BaseModel):
    """Cumulative counters for a single network protocol."""
    protocol: str
    packets: int
    bytes: int


class SessionSummary(BaseModel):
    """Cumulative totals for the entire capture session."""
    packets: int
    bytes: int


class WindowSummary(BaseModel):
    """Rolling window metrics and bandwidth rates."""
    packets: int
    bytes: int
    packets_per_second: float
    bytes_per_second: float


class MetricsSummaryResponse(BaseModel):
    """Response schema for GET /api/metrics/summary."""
    window_seconds: int
    session: SessionSummary
    window: WindowSummary
    protocols: list[ProtocolMetric]


class HostTraffic(BaseModel):
    """Traffic statistics and rolling bandwidth rates for an individual host."""
    host_ip: str
    tx_bytes: int
    rx_bytes: int
    tx_packets: int
    rx_packets: int
    tx_bytes_per_second: float
    rx_bytes_per_second: float
    last_seen: str


class TopHostsResponse(BaseModel):
    """Response schema for GET /api/metrics/hosts."""
    hosts: list[HostTraffic]
    window_seconds: int
    total_hosts: int


class AlertResponse(BaseModel):
    """Schema representing an anomaly detection alert."""
    id: str
    rule_id: str
    severity: str
    title: str
    description: str
    source_ip: str | None = None
    target_ip: str | None = None
    first_seen: str
    last_seen: str
    occurrence_count: int
    acknowledged: bool
    evidence: dict[str, Any]


class AlertListResponse(BaseModel):
    """Response schema for GET /api/alerts."""
    alerts: list[AlertResponse]
    total: int
    unacknowledged_count: int


class InterfaceInfo(BaseModel):
    """Network interface details."""
    name: str
    description: str | None = None
    is_up: bool
    is_loopback: bool
    addresses: list[str]


class InterfacesResponse(BaseModel):
    """Response schema for GET /api/interfaces."""
    interfaces: list[InterfaceInfo]


class CaptureStartRequest(BaseModel):
    """Request payload for starting capture on an interface."""
    interface: str


class CaptureStatusResponse(BaseModel):
    """Response schema for capture status and controls."""
    state: str = Field(description="Capture state: stopped, starting, running, stopping, error")
    interface: str | None = None
    started_at: str | None = None
    packets_seen: int = 0
    packets_processed: int = 0
    processing_errors: int = 0
    last_error: str | None = None


