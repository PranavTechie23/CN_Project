from collections import deque
from dataclasses import dataclass
import threading
from typing import Any, Dict, List, Optional, Tuple

from app.analysis.packet_models import PacketObservation
from app.analysis.alert_store import Alert, AlertStore


@dataclass
class DetectionConfig:
    """Configurable thresholds and time windows for heuristic detection rules."""
    port_scan_window_seconds: int = 10
    port_scan_unique_ports_threshold: int = 15
    syn_flood_window_seconds: int = 5
    syn_flood_syn_threshold: int = 100
    arp_conflict_window_seconds: int = 60
    icmp_flood_window_seconds: int = 5
    icmp_flood_threshold: int = 50
    udp_flood_window_seconds: int = 5
    udp_flood_threshold: int = 100


class DetectionEngine:
    """Deterministic, rule-based detection engine for network anomalies.

    Consumes PacketObservation instances and evaluates:
      - Rule A: TCP Port Scan (PORT_SCAN)
      - Rule B: TCP SYN Flood (SYN_FLOOD)
      - Rule C: ARP Spoofing (ARP_SPOOF)
      - Rule D: ICMP Ping Flood (ICMP_FLOOD)
      - Rule E: UDP Flood (UDP_FLOOD)
      - Rule F: TCP Flag Anomaly / Stealth Scan (TCP_FLAG_ANOMALY: NULL, XMAS, SYN-FIN)
      - Rule G: LAND Attack (LAND_ATTACK)
    """

    def __init__(self, alert_store: AlertStore, config: Optional[DetectionConfig] = None) -> None:
        self.alert_store = alert_store
        self.config = config if config is not None else DetectionConfig()

        self._lock = threading.RLock()
        # (src_ip, dst_ip) -> deque of (ts_sec, dst_port)
        self._port_scan_state: Dict[Tuple[str, str], deque] = {}
        # dst_ip -> deque of (ts_sec, src_ip)
        self._syn_flood_state: Dict[str, deque] = {}
        # sender_ip -> deque of (ts_sec, sender_mac)
        self._arp_state: Dict[str, deque] = {}
        # dst_ip -> deque of (ts_sec, src_ip)
        self._icmp_flood_state: Dict[str, deque] = {}
        # dst_ip -> deque of (ts_sec, src_ip)
        self._udp_flood_state: Dict[str, deque] = {}

    def reset(self) -> None:
        """Reset internal rolling state across all detection rules."""
        with self._lock:
            self._port_scan_state.clear()
            self._syn_flood_state.clear()
            self._arp_state.clear()
            self._icmp_flood_state.clear()
            self._udp_flood_state.clear()

    def process(self, obs: PacketObservation) -> List[Alert]:
        """Evaluate observation against all detection rules and return triggered alerts."""
        alerts: List[Alert] = []

        with self._lock:
            if obs.protocol == "TCP":
                # Rule G: LAND Attack
                alert_g = self._check_land_attack(obs)
                if alert_g:
                    alerts.append(alert_g)

                # Rule F: TCP Flag Anomaly (NULL, XMAS, SYN-FIN)
                alert_f = self._check_tcp_flag_anomaly(obs)
                if alert_f:
                    alerts.append(alert_f)

                # Rule A & Rule B for bare TCP SYNs
                if obs.tcp_syn and not obs.tcp_ack:
                    alert_a = self._check_port_scan(obs)
                    if alert_a:
                        alerts.append(alert_a)

                    alert_b = self._check_syn_flood(obs)
                    if alert_b:
                        alerts.append(alert_b)

            elif obs.protocol == "ARP":
                # Rule C for ARP
                alert_c = self._check_arp_spoof(obs)
                if alert_c:
                    alerts.append(alert_c)

            elif obs.protocol in ("ICMP", "ICMPv6"):
                # Rule D for ICMP Ping Flood
                alert_d = self._check_icmp_flood(obs)
                if alert_d:
                    alerts.append(alert_d)

            elif obs.protocol == "UDP":
                # Rule E for UDP Flood
                alert_e = self._check_udp_flood(obs)
                if alert_e:
                    alerts.append(alert_e)

        return alerts

    @staticmethod
    def _prune_expired_entries(state: Dict[Any, deque], cutoff: float, max_capacity: int = 1000) -> None:
        """Enforce memory bounds on state dictionaries by purging expired deques."""
        if len(state) <= max_capacity:
            return
        expired_keys = [
            k for k, h in state.items()
            if not h or h[-1][0] < cutoff
        ]
        for k in expired_keys:
            del state[k]

    def _check_port_scan(self, obs: PacketObservation) -> Optional[Alert]:
        """Rule A: Port Scan Detection."""
        if not obs.src_ip or not obs.dst_ip or obs.dst_port is None:
            return None

        key = (obs.src_ip, obs.dst_ip)
        ts_sec = obs.timestamp.timestamp()
        cutoff = ts_sec - self.config.port_scan_window_seconds

        # Periodically enforce capacity bound
        self._prune_expired_entries(self._port_scan_state, cutoff, max_capacity=1000)

        if key not in self._port_scan_state:
            self._port_scan_state[key] = deque(maxlen=2000)

        history = self._port_scan_state[key]
        history.append((ts_sec, obs.dst_port))

        # Expire old entries
        while history and history[0][0] < cutoff:
            history.popleft()

        distinct_ports = {port for _, port in history}

        if len(distinct_ports) >= self.config.port_scan_unique_ports_threshold:
            sample_ports = sorted(list(distinct_ports))[:10]
            evidence = {
                "unique_destination_ports": len(distinct_ports),
                "window_seconds": self.config.port_scan_window_seconds,
                "threshold": self.config.port_scan_unique_ports_threshold,
                "sample_ports": sample_ports,
            }
            fingerprint = f"PORT_SCAN:{obs.src_ip}:{obs.dst_ip}"
            return self.alert_store.add_or_update_alert(
                rule_id="PORT_SCAN",
                severity="medium",
                title="Possible TCP port scan",
                description=(
                    f"Possible TCP port scan: source {obs.src_ip} sent bare SYN packets "
                    f"to {len(distinct_ports)} distinct ports on {obs.dst_ip} within {self.config.port_scan_window_seconds}s."
                ),
                fingerprint=fingerprint,
                source_ip=obs.src_ip,
                target_ip=obs.dst_ip,
                evidence=evidence,
                timestamp=obs.timestamp,
            )
        return None

    def _check_syn_flood(self, obs: PacketObservation) -> Optional[Alert]:
        """Rule B: Possible SYN Flood Detection."""
        if not obs.dst_ip:
            return None

        key = obs.dst_ip
        ts_sec = obs.timestamp.timestamp()
        cutoff = ts_sec - self.config.syn_flood_window_seconds

        # Periodically enforce capacity bound
        self._prune_expired_entries(self._syn_flood_state, cutoff, max_capacity=1000)

        if key not in self._syn_flood_state:
            self._syn_flood_state[key] = deque(maxlen=20000)

        history = self._syn_flood_state[key]
        history.append((ts_sec, obs.src_ip))

        # Expire old entries
        while history and history[0][0] < cutoff:
            history.popleft()

        count = len(history)

        if count >= self.config.syn_flood_syn_threshold:
            distinct_sources = {src for _, src in history if src}
            evidence = {
                "observed_syn_count": count,
                "window_seconds": self.config.syn_flood_window_seconds,
                "threshold": self.config.syn_flood_syn_threshold,
                "distinct_sources_count": len(distinct_sources),
            }
            fingerprint = f"SYN_FLOOD:{obs.dst_ip}"
            return self.alert_store.add_or_update_alert(
                rule_id="SYN_FLOOD",
                severity="high",
                title="Possible SYN flood (rate heuristic)",
                description=(
                    f"Possible SYN flood: target {obs.dst_ip} received {count} bare SYN packets "
                    f"within {self.config.syn_flood_window_seconds}s."
                ),
                fingerprint=fingerprint,
                source_ip=None,
                target_ip=obs.dst_ip,
                evidence=evidence,
                timestamp=obs.timestamp,
            )
        return None

    def _check_arp_spoof(self, obs: PacketObservation) -> Optional[Alert]:
        """Rule C: Possible ARP Spoofing Detection."""
        sender_ip = obs.arp_sender_ip
        sender_mac = obs.arp_sender_mac

        if not sender_ip or sender_ip == "0.0.0.0" or not sender_mac or sender_mac == "ff:ff:ff:ff:ff:ff":
            return None

        sender_mac = sender_mac.lower()
        key = sender_ip
        ts_sec = obs.timestamp.timestamp()
        cutoff = ts_sec - self.config.arp_conflict_window_seconds

        # Periodically enforce capacity bound
        self._prune_expired_entries(self._arp_state, cutoff, max_capacity=1000)

        if key not in self._arp_state:
            self._arp_state[key] = deque(maxlen=100)

        history = self._arp_state[key]

        # Expire old mappings
        while history and history[0][0] < cutoff:
            history.popleft()

        alert: Optional[Alert] = None

        # Check for conflicting MAC inside the window
        conflicting_macs = [mac for _, mac in history if mac != sender_mac]
        if conflicting_macs:
            prior_mac = conflicting_macs[-1]
            evidence = {
                "claimed_ip": sender_ip,
                "prior_mac": prior_mac,
                "new_mac": sender_mac,
                "window_seconds": self.config.arp_conflict_window_seconds,
            }
            fingerprint = f"ARP_SPOOF:{sender_ip}"
            alert = self.alert_store.add_or_update_alert(
                rule_id="ARP_SPOOF",
                severity="high",
                title="Possible ARP spoofing",
                description=(
                    f"Possible ARP spoofing: {sender_ip} was observed with both "
                    f"{prior_mac} and {sender_mac} within {self.config.arp_conflict_window_seconds}s."
                ),
                fingerprint=fingerprint,
                source_ip=None,
                target_ip=sender_ip,
                evidence=evidence,
                timestamp=obs.timestamp,
            )

        # Record this claim
        history.append((ts_sec, sender_mac))
        return alert

    def _check_icmp_flood(self, obs: PacketObservation) -> Optional[Alert]:
        """Rule D: Possible ICMP Ping Flood Detection."""
        if not obs.dst_ip:
            return None

        key = obs.dst_ip
        ts_sec = obs.timestamp.timestamp()
        cutoff = ts_sec - self.config.icmp_flood_window_seconds

        self._prune_expired_entries(self._icmp_flood_state, cutoff, max_capacity=1000)

        if key not in self._icmp_flood_state:
            self._icmp_flood_state[key] = deque(maxlen=20000)

        history = self._icmp_flood_state[key]
        history.append((ts_sec, obs.src_ip))

        while history and history[0][0] < cutoff:
            history.popleft()

        count = len(history)
        if count >= self.config.icmp_flood_threshold:
            distinct_sources = {src for _, src in history if src}
            evidence = {
                "observed_icmp_count": count,
                "window_seconds": self.config.icmp_flood_window_seconds,
                "threshold": self.config.icmp_flood_threshold,
                "distinct_sources_count": len(distinct_sources),
            }
            fingerprint = f"ICMP_FLOOD:{obs.dst_ip}"
            return self.alert_store.add_or_update_alert(
                rule_id="ICMP_FLOOD",
                severity="high",
                title="Possible ICMP ping flood",
                description=(
                    f"Possible ICMP ping flood: target {obs.dst_ip} received {count} ICMP echo packets "
                    f"within {self.config.icmp_flood_window_seconds}s."
                ),
                fingerprint=fingerprint,
                source_ip=obs.src_ip if len(distinct_sources) == 1 else None,
                target_ip=obs.dst_ip,
                evidence=evidence,
                timestamp=obs.timestamp,
            )
        return None

    def _check_udp_flood(self, obs: PacketObservation) -> Optional[Alert]:
        """Rule E: Possible UDP Flood Detection."""
        if not obs.dst_ip:
            return None

        key = obs.dst_ip
        ts_sec = obs.timestamp.timestamp()
        cutoff = ts_sec - self.config.udp_flood_window_seconds

        self._prune_expired_entries(self._udp_flood_state, cutoff, max_capacity=1000)

        if key not in self._udp_flood_state:
            self._udp_flood_state[key] = deque(maxlen=20000)

        history = self._udp_flood_state[key]
        history.append((ts_sec, obs.src_ip))

        while history and history[0][0] < cutoff:
            history.popleft()

        count = len(history)
        if count >= self.config.udp_flood_threshold:
            distinct_sources = {src for _, src in history if src}
            evidence = {
                "observed_udp_count": count,
                "window_seconds": self.config.udp_flood_window_seconds,
                "threshold": self.config.udp_flood_threshold,
                "distinct_sources_count": len(distinct_sources),
            }
            fingerprint = f"UDP_FLOOD:{obs.dst_ip}"
            return self.alert_store.add_or_update_alert(
                rule_id="UDP_FLOOD",
                severity="high",
                title="Possible UDP flood",
                description=(
                    f"Possible UDP flood: target {obs.dst_ip} received {count} UDP datagrams "
                    f"within {self.config.udp_flood_window_seconds}s."
                ),
                fingerprint=fingerprint,
                source_ip=obs.src_ip if len(distinct_sources) == 1 else None,
                target_ip=obs.dst_ip,
                evidence=evidence,
                timestamp=obs.timestamp,
            )
        return None

    def _check_tcp_flag_anomaly(self, obs: PacketObservation) -> Optional[Alert]:
        """Rule F: TCP Flag Anomaly / Stealth Scan Detection (NULL, XMAS, SYN-FIN)."""
        if obs.protocol != "TCP" or obs.tcp_flags_int is None or not obs.dst_ip:
            return None

        flags = obs.tcp_flags_int
        anomaly_type: Optional[str] = None

        # 1. NULL Scan: All control flags unset (0)
        if flags == 0:
            anomaly_type = "NULL scan (no flags set)"
        # 2. XMAS Scan: FIN (0x01) + PSH (0x08) + URG (0x20) == 0x29
        elif (flags & 0x29) == 0x29:
            anomaly_type = "XMAS scan (FIN+PSH+URG set)"
        # 3. SYN-FIN Scan: Illegal simultaneous SYN (0x02) and FIN (0x01) == 0x03
        elif (flags & 0x03) == 0x03:
            anomaly_type = "SYN-FIN scan (illegal simultaneous SYN+FIN)"

        if anomaly_type is not None:
            evidence = {
                "anomaly_type": anomaly_type,
                "tcp_flags": obs.tcp_flags or "",
                "tcp_flags_int": obs.tcp_flags_int,
                "src_port": obs.src_port,
                "dst_port": obs.dst_port,
            }
            fingerprint = f"TCP_FLAG_ANOMALY:{obs.src_ip}:{obs.dst_ip}:{anomaly_type}"
            return self.alert_store.add_or_update_alert(
                rule_id="TCP_FLAG_ANOMALY",
                severity="medium",
                title=f"TCP flag anomaly: {anomaly_type}",
                description=(
                    f"TCP flag anomaly detected: {anomaly_type} from {obs.src_ip or 'unknown'} "
                    f"to {obs.dst_ip}:{obs.dst_port} (flags: '{obs.tcp_flags or ''}')."
                ),
                fingerprint=fingerprint,
                source_ip=obs.src_ip,
                target_ip=obs.dst_ip,
                evidence=evidence,
                timestamp=obs.timestamp,
            )
        return None

    def _check_land_attack(self, obs: PacketObservation) -> Optional[Alert]:
        """Rule G: LAND Attack Detection (identical source/destination IP & Port)."""
        if (
            obs.protocol == "TCP"
            and obs.src_ip
            and obs.dst_ip
            and obs.src_ip == obs.dst_ip
            and obs.src_port is not None
            and obs.dst_port is not None
            and obs.src_port == obs.dst_port
        ):
            evidence = {
                "spoofed_ip": obs.src_ip,
                "spoofed_port": obs.src_port,
                "tcp_flags": obs.tcp_flags,
            }
            fingerprint = f"LAND_ATTACK:{obs.src_ip}:{obs.src_port}"
            return self.alert_store.add_or_update_alert(
                rule_id="LAND_ATTACK",
                severity="high",
                title="LAND attack detected",
                description=(
                    f"LAND attack detected: packet has identical source and destination "
                    f"({obs.src_ip}:{obs.src_port})."
                ),
                fingerprint=fingerprint,
                source_ip=obs.src_ip,
                target_ip=obs.dst_ip,
                evidence=evidence,
                timestamp=obs.timestamp,
            )
        return None

