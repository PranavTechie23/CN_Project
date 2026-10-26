from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(frozen=True, slots=True)
class PacketObservation:
    """Normalized, metadata-only packet observation.

    Strictly immutable and excludes any packet payloads or raw byte references.
    """
    packet_id: int
    timestamp: datetime             # Timezone-aware UTC
    interface: str
    protocol: str                   # TCP, UDP, ICMP, ICMPv6, ARP, IPv6-OTHER, OTHER
    length_bytes: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_fin: bool = False
    tcp_rst: bool = False
    tcp_psh: bool = False
    tcp_urg: bool = False
    tcp_flags_int: Optional[int] = None
    tcp_flags: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert observation to a JSON-serializable dictionary with ISO timestamp."""
        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp.isoformat(),
            "interface": self.interface,
            "protocol": self.protocol,
            "length_bytes": self.length_bytes,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_syn": self.tcp_syn,
            "tcp_ack": self.tcp_ack,
            "tcp_fin": self.tcp_fin,
            "tcp_rst": self.tcp_rst,
            "tcp_psh": self.tcp_psh,
            "tcp_urg": self.tcp_urg,
            "tcp_flags_int": self.tcp_flags_int,
            "tcp_flags": self.tcp_flags,
            "arp_sender_ip": self.arp_sender_ip,
            "arp_sender_mac": self.arp_sender_mac,
            "arp_target_ip": self.arp_target_ip,
        }

