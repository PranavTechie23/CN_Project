from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional, Tuple

from app.analysis.packet_models import PacketObservation

SUPPORTED_PROTOCOLS: Tuple[str, ...] = (
    "TCP",
    "UDP",
    "ICMP",
    "ICMPv6",
    "ARP",
    "IPv6-OTHER",
    "OTHER",
)


@dataclass
class HostRecord:
    """Cumulative and rolling traffic state for an observed host IP."""
    host_ip: str
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_packets: int = 0
    rx_packets: int = 0
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tx_history: deque = field(default_factory=lambda: deque(maxlen=20000))  # (timestamp_sec, bytes)
    rx_history: deque = field(default_factory=lambda: deque(maxlen=20000))  # (timestamp_sec, bytes)


class MetricsStore:
    """Thread-safe in-memory store for session totals, rolling rates, per-host metrics,

    and bounded recent packet metadata.
    """

    def __init__(
        self,
        *,
        default_window_seconds: int = 60,
        recent_packets_limit: int = 100,
        max_hosts: int = 1000
    ) -> None:
        self.default_window_seconds = default_window_seconds
        self.recent_packets_limit = recent_packets_limit
        self.max_hosts = max_hosts

        self._lock = threading.RLock()
        self._session_start: Optional[datetime] = None

        # Cumulative totals
        self._session_packets: int = 0
        self._session_bytes: int = 0
        self._dropped_observations: int = 0

        # Protocol counters
        self._protocol_packets: Dict[str, int] = {p: 0 for p in SUPPORTED_PROTOCOLS}
        self._protocol_bytes: Dict[str, int] = {p: 0 for p in SUPPORTED_PROTOCOLS}

        # Rolling session traffic: deque of (timestamp_sec, bytes)
        self._rolling_traffic: deque = deque(maxlen=50000)

        # Hosts: host_ip -> HostRecord
        self._hosts: Dict[str, HostRecord] = {}

        # Recent packet metadata ring buffer (newest at right)
        self._recent_packets: deque = deque(maxlen=recent_packets_limit)

    def reset(self) -> None:
        """Reset all metrics, host stats, rolling histories, and recent packets."""
        with self._lock:
            self._session_start = None
            self._session_packets = 0
            self._session_bytes = 0
            self._dropped_observations = 0
            self._protocol_packets = {p: 0 for p in SUPPORTED_PROTOCOLS}
            self._protocol_bytes = {p: 0 for p in SUPPORTED_PROTOCOLS}
            self._rolling_traffic.clear()
            self._hosts.clear()
            self._recent_packets.clear()

    def record_observation(self, observation: PacketObservation) -> None:
        """Record a single normalized packet observation into metrics."""
        with self._lock:
            if self._session_start is None:
                self._session_start = observation.timestamp

            ts_sec = observation.timestamp.timestamp()
            pkt_bytes = observation.length_bytes

            # Update session totals
            self._session_packets += 1
            self._session_bytes += pkt_bytes

            # Update protocol totals
            proto = observation.protocol if observation.protocol in self._protocol_packets else "OTHER"
            self._protocol_packets[proto] += 1
            self._protocol_bytes[proto] += pkt_bytes

            # Update rolling traffic
            self._rolling_traffic.append((ts_sec, pkt_bytes))

            # Update recent packet ring buffer
            self._recent_packets.append(observation)

            # Update per-host statistics
            self._update_host_tx(observation.src_ip, pkt_bytes, observation.timestamp, ts_sec)
            self._update_host_rx(observation.dst_ip, pkt_bytes, observation.timestamp, ts_sec)

    def _update_host_tx(self, ip: Optional[str], pkt_bytes: int, ts: datetime, ts_sec: float) -> None:
        if not ip or ip == "0.0.0.0":
            return
        host = self._get_or_create_host(ip, ts)
        host.tx_bytes += pkt_bytes
        host.tx_packets += 1
        host.last_seen = ts
        host.tx_history.append((ts_sec, pkt_bytes))

    def _update_host_rx(self, ip: Optional[str], pkt_bytes: int, ts: datetime, ts_sec: float) -> None:
        if not ip or ip == "0.0.0.0":
            return
        host = self._get_or_create_host(ip, ts)
        host.rx_bytes += pkt_bytes
        host.rx_packets += 1
        host.last_seen = ts
        host.rx_history.append((ts_sec, pkt_bytes))

    def _get_or_create_host(self, ip: str, ts: datetime) -> HostRecord:
        if ip in self._hosts:
            return self._hosts[ip]

        # Enforce memory bounds on hosts table
        if len(self._hosts) >= self.max_hosts:
            # Evict the oldest seen host
            oldest_ip = min(self._hosts.keys(), key=lambda k: self._hosts[k].last_seen)
            del self._hosts[oldest_ip]

        record = HostRecord(host_ip=ip, last_seen=ts)
        self._hosts[ip] = record
        return record

    def get_summary(
        self,
        *,
        window_seconds: Optional[int] = None,
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Return cumulative session summary and rolling window rates."""
        win_sec = window_seconds if window_seconds and window_seconds > 0 else self.default_window_seconds
        ref_time = now if now is not None else datetime.now(timezone.utc)
        ref_ts = ref_time.timestamp()
        cutoff = ref_ts - win_sec

        with self._lock:
            # Clean up and compute rolling window traffic
            while self._rolling_traffic and self._rolling_traffic[0][0] < cutoff:
                self._rolling_traffic.popleft()

            window_packets = len(self._rolling_traffic)
            window_bytes = sum(b for _, b in self._rolling_traffic)

            # Determine divisor: use elapsed session duration if less than window, minimum 1.0s
            if self._session_start is not None:
                elapsed = max(1.0, ref_ts - self._session_start.timestamp())
                effective_window = min(float(win_sec), elapsed)
            else:
                effective_window = float(win_sec)

            pps = round(window_packets / effective_window, 2)
            bps = round(window_bytes / effective_window, 2)

            protocols = [
                {
                    "protocol": p,
                    "packets": self._protocol_packets[p],
                    "bytes": self._protocol_bytes[p],
                }
                for p in SUPPORTED_PROTOCOLS
            ]

            return {
                "window_seconds": win_sec,
                "session": {
                    "packets": self._session_packets,
                    "bytes": self._session_bytes,
                },
                "window": {
                    "packets": window_packets,
                    "bytes": window_bytes,
                    "packets_per_second": pps,
                    "bytes_per_second": bps,
                },
                "protocols": protocols,
            }

    def get_top_hosts(
        self,
        *,
        window_seconds: Optional[int] = None,
        limit: int = 10,
        sort_by: str = "total_bytes",
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Return top hosts sorted by cumulative or rolling traffic."""
        win_sec = window_seconds if window_seconds and window_seconds > 0 else self.default_window_seconds
        safe_limit = max(1, min(limit, 100))
        ref_time = now if now is not None else datetime.now(timezone.utc)
        ref_ts = ref_time.timestamp()
        cutoff = ref_ts - win_sec

        with self._lock:
            if self._session_start is not None:
                elapsed = max(1.0, ref_ts - self._session_start.timestamp())
                effective_window = min(float(win_sec), elapsed)
            else:
                effective_window = float(win_sec)

            host_list: List[Dict[str, Any]] = []

            for host in self._hosts.values():
                # Purge old history points
                while host.tx_history and host.tx_history[0][0] < cutoff:
                    host.tx_history.popleft()
                while host.rx_history and host.rx_history[0][0] < cutoff:
                    host.rx_history.popleft()

                tx_win_bytes = sum(b for _, b in host.tx_history)
                rx_win_bytes = sum(b for _, b in host.rx_history)

                host_list.append({
                    "host_ip": host.host_ip,
                    "tx_bytes": host.tx_bytes,
                    "rx_bytes": host.rx_bytes,
                    "tx_packets": host.tx_packets,
                    "rx_packets": host.rx_packets,
                    "tx_bytes_per_second": round(tx_win_bytes / effective_window, 2),
                    "rx_bytes_per_second": round(rx_win_bytes / effective_window, 2),
                    "last_seen": host.last_seen.isoformat(),
                    "_total_bytes": host.tx_bytes + host.rx_bytes,
                })

            # Sort
            if sort_by == "tx_bytes":
                host_list.sort(key=lambda h: h["tx_bytes"], reverse=True)
            elif sort_by == "rx_bytes":
                host_list.sort(key=lambda h: h["rx_bytes"], reverse=True)
            else:
                host_list.sort(key=lambda h: h["_total_bytes"], reverse=True)

            # Strip temporary sort keys
            top_hosts = []
            for h in host_list[:safe_limit]:
                clean_h = {k: v for k, v in h.items() if not k.startswith("_")}
                top_hosts.append(clean_h)

            return {
                "hosts": top_hosts,
                "window_seconds": win_sec,
                "total_hosts": len(self._hosts),
            }

    def get_recent_packets(self, limit: int = 50, protocol: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return newest-first recent packet metadata records, optionally filtered by protocol."""
        safe_limit = max(1, min(limit, self.recent_packets_limit))
        with self._lock:
            if protocol:
                clean_proto = protocol.strip().upper()
                filtered = [
                    obs.to_dict()
                    for obs in reversed(self._recent_packets)
                    if obs.protocol.upper() == clean_proto
                ]
                return filtered[:safe_limit]

            # deque stores oldest at left, newest at right; reversed provides newest first
            slice_packets = [obs.to_dict() for obs in reversed(list(self._recent_packets)[-safe_limit:])]
            return slice_packets
