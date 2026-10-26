from datetime import datetime, timezone
import logging
import threading
from typing import Any, Callable, Optional

from scapy.sendrecv import AsyncSniffer

from app.analysis.alert_store import AlertStore
from app.analysis.detection_engine import DetectionEngine
from app.analysis.metrics_store import MetricsStore
from app.analysis.packet_parser import PacketParser
from app.capture.interface_service import InterfaceService
from app.schemas import CaptureStatusResponse

logger = logging.getLogger("traffic_analyzer.capture")


class CaptureManager:
    """Manages the lifecycle of a single passive packet capture session."""

    def __init__(
        self,
        *,
        interface_service: InterfaceService,
        packet_parser: PacketParser,
        metrics_store: MetricsStore,
        detection_engine: DetectionEngine,
        alert_store: AlertStore,
        sniffer_factory: Optional[Callable[..., Any]] = None
    ) -> None:
        self.interface_service = interface_service
        self.packet_parser = packet_parser
        self.metrics_store = metrics_store
        self.detection_engine = detection_engine
        self.alert_store = alert_store
        self.sniffer_factory = sniffer_factory or self._default_sniffer_factory

        self._lock = threading.RLock()
        self._state: str = "stopped"  # stopped, starting, running, stopping, error
        self._interface: Optional[str] = None
        self._started_at: Optional[datetime] = None
        self._packets_seen: int = 0
        self._packets_processed: int = 0
        self._processing_errors: int = 0
        self._last_error: Optional[str] = None
        self._sniffer: Optional[Any] = None

    @staticmethod
    def _default_sniffer_factory(iface: str, prn: Callable[[Any], None]) -> Any:
        return AsyncSniffer(iface=iface, store=False, prn=prn)

    def get_status(self) -> CaptureStatusResponse:
        """Return the current capture state and diagnostic counters."""
        with self._lock:
            return CaptureStatusResponse(
                state=self._state,
                interface=self._interface,
                started_at=self._started_at.isoformat() if self._started_at else None,
                packets_seen=self._packets_seen,
                packets_processed=self._packets_processed,
                processing_errors=self._processing_errors + self.packet_parser.error_count,
                last_error=self._last_error,
            )

    def start(self, interface_name: str) -> CaptureStatusResponse:
        """Start packet capture on the selected network interface."""
        with self._lock:
            if self._state in ("running", "starting"):
                raise RuntimeError(
                    f"Capture is already active on interface '{self._interface}'."
                )

            if not self.interface_service.validate_interface(interface_name):
                raise ValueError(
                    f"Selected interface '{interface_name}' was not found among available interfaces."
                )

            self._state = "starting"
            self._last_error = None
            self._interface = interface_name

            # Reset session state across metrics, detection engine, and packet parser
            self.packet_parser.reset()
            self.metrics_store.reset()
            self.detection_engine.reset()
            self.alert_store.reset()

            self._packets_seen = 0
            self._packets_processed = 0
            self._processing_errors = 0
            self._started_at = datetime.now(timezone.utc)

            try:
                self._sniffer = self.sniffer_factory(
                    iface=interface_name,
                    prn=self._packet_callback
                )
                self._sniffer.start()
                self._state = "running"
                logger.info("Packet capture started on interface '%s'", interface_name)
            except PermissionError as e:
                self._state = "error"
                self._last_error = (
                    "Capture permission denied. Run the backend with appropriate capture permissions in your isolated lab."
                )
                logger.error("Permission denied starting capture on '%s': %s", interface_name, e)
                raise PermissionError(self._last_error) from e
            except Exception as e:
                self._state = "error"
                self._last_error = f"Failed to start packet sniffer: {str(e)}"
                logger.error("Error starting sniffer on '%s': %s", interface_name, e)
                raise RuntimeError(self._last_error) from e

            return self.get_status()

    def stop(self) -> CaptureStatusResponse:
        """Stop packet capture idempotently."""
        with self._lock:
            if self._state in ("stopped", "error") or self._sniffer is None:
                self._state = "stopped"
                return self.get_status()

            self._state = "stopping"
            sniffer = self._sniffer
            self._sniffer = None

        # Stop and join the sniffer outside of the lock
        try:
            sniffer.stop()
            logger.info("Packet capture stopped gracefully on interface '%s'", self._interface)
        except Exception as e:
            logger.warning("Error stopping sniffer: %s", e)

        with self._lock:
            self._state = "stopped"
            return self.get_status()

    def _packet_callback(self, packet: Any) -> None:
        """Callback invoked for each captured packet. Never raises exceptions."""
        try:
            with self._lock:
                self._packets_seen += 1

            obs = self.packet_parser.parse(packet, interface=self._interface or "")
            if obs is not None:
                with self._lock:
                    self._packets_processed += 1
                # Record metrics and evaluate rules
                self.metrics_store.record_observation(obs)
                self.detection_engine.process(obs)
            else:
                with self._lock:
                    self._processing_errors += 1
        except Exception as e:
            logger.debug("Exception in packet capture callback: %s", e)
            with self._lock:
                self._processing_errors += 1
