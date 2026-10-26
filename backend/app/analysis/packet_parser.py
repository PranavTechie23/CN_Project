from datetime import datetime, timezone
import logging
import threading
from typing import Any, Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
try:
    from scapy.layers.inet6 import _ICMPv6
except ImportError:
    _ICMPv6 = None
from scapy.layers.l2 import ARP, Ether

from app.analysis.packet_models import PacketObservation

logger = logging.getLogger("traffic_analyzer.parser")


def _is_icmpv6(packet: Any) -> bool:
    """Check if the packet contains an ICMPv6 layer."""
    try:
        if not hasattr(packet, "layers"):
            return False
        layers = packet.layers()
        if _ICMPv6 is not None and any(issubclass(l, _ICMPv6) for l in layers if isinstance(l, type)):
            return True
        return any(hasattr(l, "__name__") and l.__name__.startswith("ICMPv6") for l in layers)
    except Exception:
        return False


def parse_packet(
    packet: Any,
    *,
    packet_id: int,
    interface: str,
    timestamp: Optional[datetime] = None
) -> Optional[PacketObservation]:
    """Parse a raw Scapy packet into a normalized, metadata-only PacketObservation.

    Safely handles malformed packets without throwing exceptions out of the capture callback.
    Guarantees that raw packet payloads, payload bytes (Raw.load), and the Scapy packet
    instance itself are never retained or included in the returned object.
    """
    try:
        ts = timestamp if timestamp is not None else datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        # Wire frame length captured
        try:
            length_bytes = len(packet)
        except Exception:
            length_bytes = 0

        src_mac: Optional[str] = None
        dst_mac: Optional[str] = None

        if hasattr(packet, "haslayer") and packet.haslayer(Ether):
            try:
                eth = packet[Ether]
                src_mac = str(eth.src).lower() if getattr(eth, "src", None) else None
                dst_mac = str(eth.dst).lower() if getattr(eth, "dst", None) else None
            except Exception as e:
                logger.debug("Failed to extract Ethernet layer metadata: %s", e)

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
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

        if hasattr(packet, "haslayer") and packet.haslayer(ARP):
            protocol = "ARP"
            try:
                arp = packet[ARP]
                arp_sender_ip = str(arp.psrc) if getattr(arp, "psrc", None) else None
                arp_sender_mac = str(arp.hwsrc).lower() if getattr(arp, "hwsrc", None) else None
                arp_target_ip = str(arp.pdst) if getattr(arp, "pdst", None) else None
                src_ip = arp_sender_ip
                dst_ip = arp_target_ip
                if arp_sender_mac:
                    src_mac = arp_sender_mac
            except Exception as e:
                logger.debug("Failed to extract ARP metadata: %s", e)
        else:
            # IP Layer
            if hasattr(packet, "haslayer") and packet.haslayer(IP):
                try:
                    ip = packet[IP]
                    src_ip = str(ip.src) if getattr(ip, "src", None) else None
                    dst_ip = str(ip.dst) if getattr(ip, "dst", None) else None
                except Exception as e:
                    logger.debug("Failed to extract IPv4 metadata: %s", e)
            elif hasattr(packet, "haslayer") and packet.haslayer(IPv6):
                try:
                    ip6 = packet[IPv6]
                    src_ip = str(ip6.src) if getattr(ip6, "src", None) else None
                    dst_ip = str(ip6.dst) if getattr(ip6, "dst", None) else None
                except Exception as e:
                    logger.debug("Failed to extract IPv6 metadata: %s", e)

            # Transport / Protocol Layer
            if hasattr(packet, "haslayer") and packet.haslayer(TCP):
                protocol = "TCP"
                try:
                    tcp = packet[TCP]
                    src_port = int(tcp.sport) if getattr(tcp, "sport", None) is not None else None
                    dst_port = int(tcp.dport) if getattr(tcp, "dport", None) is not None else None
                    if getattr(tcp, "flags", None) is not None:
                        flags_int = int(tcp.flags)
                        tcp_flags_int = flags_int
                        tcp_fin = bool(flags_int & 0x01)
                        tcp_syn = bool(flags_int & 0x02)
                        tcp_rst = bool(flags_int & 0x04)
                        tcp_psh = bool(flags_int & 0x08)
                        tcp_ack = bool(flags_int & 0x10)
                        tcp_urg = bool(flags_int & 0x20)
                        tcp_flags = str(tcp.flags)
                except Exception as e:
                    logger.debug("Failed to extract TCP metadata: %s", e)
            elif hasattr(packet, "haslayer") and packet.haslayer(UDP):
                protocol = "UDP"
                try:
                    udp = packet[UDP]
                    src_port = int(udp.sport) if getattr(udp, "sport", None) is not None else None
                    dst_port = int(udp.dport) if getattr(udp, "dport", None) is not None else None
                except Exception as e:
                    logger.debug("Failed to extract UDP metadata: %s", e)
            elif hasattr(packet, "haslayer") and packet.haslayer(ICMP):
                protocol = "ICMP"
            elif _is_icmpv6(packet):
                protocol = "ICMPv6"
            elif hasattr(packet, "haslayer") and packet.haslayer(IPv6):
                protocol = "IPv6-OTHER"
            else:
                protocol = "OTHER"

        return PacketObservation(
            packet_id=packet_id,
            timestamp=ts,
            interface=interface,
            protocol=protocol,
            length_bytes=length_bytes,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_port=src_port,
            dst_port=dst_port,
            tcp_syn=tcp_syn,
            tcp_ack=tcp_ack,
            tcp_fin=tcp_fin,
            tcp_rst=tcp_rst,
            tcp_psh=tcp_psh,
            tcp_urg=tcp_urg,
            tcp_flags_int=tcp_flags_int,
            tcp_flags=tcp_flags,
            arp_sender_ip=arp_sender_ip,
            arp_sender_mac=arp_sender_mac,
            arp_target_ip=arp_target_ip,
        )

    except Exception as e:
        logger.warning("Unexpected error parsing packet %d: %s", packet_id, e)
        return None


class PacketParser:
    """Thread-safe parser maintaining monotonic packet IDs."""

    def __init__(self, start_id: int = 1) -> None:
        self._next_id: int = start_id
        self._lock = threading.Lock()
        self._error_count: int = 0

    @property
    def error_count(self) -> int:
        """Total number of packets that failed parsing."""
        with self._lock:
            return self._error_count

    def reset(self, start_id: int = 1) -> None:
        """Reset the packet ID counter and error count for a new capture session."""
        with self._lock:
            self._next_id = start_id
            self._error_count = 0

    def parse(
        self,
        packet: Any,
        *,
        interface: str = "",
        timestamp: Optional[datetime] = None
    ) -> Optional[PacketObservation]:
        """Parse packet with an automatically assigned monotonic packet ID."""
        with self._lock:
            current_id = self._next_id
            self._next_id += 1

        obs = parse_packet(
            packet,
            packet_id=current_id,
            interface=interface,
            timestamp=timestamp
        )

        if obs is None:
            with self._lock:
                self._error_count += 1

        return obs
