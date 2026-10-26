import logging
import socket
from typing import List, Optional

import psutil
try:
    from scapy.all import get_if_list
except Exception:
    get_if_list = None

from app.schemas import InterfaceInfo

logger = logging.getLogger("traffic_analyzer.interfaces")


class InterfaceService:
    """Service to discover and validate network interfaces on the host system."""

    def get_interfaces(self) -> List[InterfaceInfo]:
        """Enumerate system network interfaces with address and status details."""
        interfaces: List[InterfaceInfo] = []

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception as e:
            logger.error("Failed to query system interfaces: %s", e)
            addrs = {}
            stats = {}

        # Discover all interface names seen by psutil and scapy
        scapy_ifaces = set(get_if_list()) if get_if_list is not None else set()
        all_names = sorted(list(set(addrs.keys()) | scapy_ifaces))

        for name in all_names:
            if_addrs = addrs.get(name, [])
            if_stat = stats.get(name)

            # Filter IPv4 and IPv6 addresses
            ip_addresses: List[str] = []
            for addr in if_addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    # Strip interface zone indices like %eth0 or %lo0
                    ip_str = addr.address.split("%")[0]
                    ip_addresses.append(ip_str)

            is_loopback = (
                name.lower().startswith("lo")
                or any(ip.startswith("127.") or ip == "::1" for ip in ip_addresses)
            )

            is_up = if_stat.isup if if_stat is not None else True

            # Generate concise descriptive label
            if is_loopback:
                description = "Loopback interface"
            elif name.startswith("eth") or name.startswith("en") or name.startswith("wlan") or name.startswith("wl"):
                description = "Ethernet / Wireless interface"
            elif name.startswith("s1-") or name.startswith("s2-") or name.startswith("h"):
                description = "Virtual / Mininet lab interface"
            else:
                description = "Network interface"

            interfaces.append(
                InterfaceInfo(
                    name=name,
                    description=description,
                    is_up=is_up,
                    is_loopback=is_loopback,
                    addresses=ip_addresses,
                )
            )

        return interfaces

    def validate_interface(self, name: str) -> bool:
        """Check whether the provided interface name exists on the host."""
        clean_name = name.strip() if name else ""
        available = {i.name for i in self.get_interfaces()}
        return clean_name in available
