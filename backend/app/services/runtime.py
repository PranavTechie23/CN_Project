from app.config import settings
from app.analysis.alert_store import AlertStore
from app.analysis.detection_engine import DetectionConfig, DetectionEngine
from app.analysis.metrics_store import MetricsStore
from app.analysis.packet_parser import PacketParser
from app.capture.interface_service import InterfaceService
from app.capture.capture_manager import CaptureManager


class RuntimeServices:
    """Dependency container wiring all shared services for the application."""

    def __init__(self) -> None:
        self.interface_service = InterfaceService()
        self.packet_parser = PacketParser()

        self.metrics_store = MetricsStore(
            default_window_seconds=settings.METRICS_WINDOW_SECONDS,
            recent_packets_limit=settings.RECENT_PACKETS_LIMIT,
        )

        self.alert_store = AlertStore(
            max_alerts=settings.MAX_ALERTS,
            dedup_cooldown_seconds=settings.ALERT_DEDUP_SECONDS,
        )

        detection_config = DetectionConfig(
            port_scan_window_seconds=settings.PORT_SCAN_WINDOW_SECONDS,
            port_scan_unique_ports_threshold=settings.PORT_SCAN_UNIQUE_PORTS_THRESHOLD,
            syn_flood_window_seconds=settings.SYN_FLOOD_WINDOW_SECONDS,
            syn_flood_syn_threshold=settings.SYN_FLOOD_SYN_THRESHOLD,
            arp_conflict_window_seconds=settings.ARP_CONFLICT_WINDOW_SECONDS,
            icmp_flood_window_seconds=settings.ICMP_FLOOD_WINDOW_SECONDS,
            icmp_flood_threshold=settings.ICMP_FLOOD_THRESHOLD,
            udp_flood_window_seconds=settings.UDP_FLOOD_WINDOW_SECONDS,
            udp_flood_threshold=settings.UDP_FLOOD_THRESHOLD,
        )

        self.detection_engine = DetectionEngine(
            alert_store=self.alert_store,
            config=detection_config,
        )

        self.capture_manager = CaptureManager(
            interface_service=self.interface_service,
            packet_parser=self.packet_parser,
            metrics_store=self.metrics_store,
            detection_engine=self.detection_engine,
            alert_store=self.alert_store,
        )

    def shutdown(self) -> None:
        """Gracefully terminate any active capture sessions."""
        self.capture_manager.stop()


# Shared singleton runtime container
runtime = RuntimeServices()
