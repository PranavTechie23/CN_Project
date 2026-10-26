from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """Application settings backed by environment variables."""

    HOST: str = Field(default="127.0.0.1", description="Host address to bind the API server")
    PORT: int = Field(default=8000, description="Port for the API server")
    FRONTEND_ORIGIN: str = Field(default="http://localhost:5173", description="Allowed CORS origin for frontend")

    # Metrics and limits
    METRICS_WINDOW_SECONDS: int = Field(default=60, ge=5, le=3600, description="Default rolling metrics window in seconds")
    RECENT_PACKETS_LIMIT: int = Field(default=100, ge=10, le=1000, description="Max stored recent packet metadata rows")
    MAX_ALERTS: int = Field(default=500, ge=10, le=5000, description="Max stored in-memory alerts")
    WS_UPDATE_INTERVAL_SECONDS: float = Field(default=1.0, ge=0.2, le=10.0, description="Cadence for live WebSocket broadcasts")
    ALERT_DEDUP_SECONDS: int = Field(default=30, ge=1, le=600, description="Cooldown window for alert deduplication")

    # Detector settings
    PORT_SCAN_WINDOW_SECONDS: int = Field(default=10, ge=1, le=120, description="Window in seconds for port scan heuristic")
    PORT_SCAN_UNIQUE_PORTS_THRESHOLD: int = Field(default=15, ge=2, le=500, description="Distinct ports threshold for port scan")

    SYN_FLOOD_WINDOW_SECONDS: int = Field(default=5, ge=1, le=60, description="Window in seconds for SYN flood heuristic")
    SYN_FLOOD_SYN_THRESHOLD: int = Field(default=100, ge=5, le=10000, description="Bare SYN packet count threshold for SYN flood")

    ARP_CONFLICT_WINDOW_SECONDS: int = Field(default=60, ge=5, le=600, description="Window in seconds for ARP conflict heuristic")

    ICMP_FLOOD_WINDOW_SECONDS: int = Field(default=5, ge=1, le=60, description="Window in seconds for ICMP flood heuristic")
    ICMP_FLOOD_THRESHOLD: int = Field(default=50, ge=5, le=10000, description="ICMP echo packet count threshold for ICMP flood")

    UDP_FLOOD_WINDOW_SECONDS: int = Field(default=5, ge=1, le=60, description="Window in seconds for UDP flood heuristic")
    UDP_FLOOD_THRESHOLD: int = Field(default=100, ge=5, le=10000, description="UDP packet count threshold for UDP flood")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
