#!/usr/bin/env python3
"""Standalone, opt-in lab traffic generation utility for the Network Traffic Analyzer.

SAFETY NOTICE:
- This script is strictly a separate lab testing tool.
- It is NEVER executed or imported by the production backend or frontend.
- It enforces strict destination IP validation and will refuse to send packets
  to public, non-private, or unverified network addresses.
- Only run this on isolated test networks (e.g. Mininet or private host-only VMs)
  that you own and control.
"""

import argparse
import ipaddress
import sys
import time

try:
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, send, sendp
except ImportError:
    print("Error: Scapy is required to run the lab traffic generator.")
    print("Install it via: pip install scapy")
    sys.exit(1)


def is_safe_lab_address(ip_str: str) -> bool:
    """Validate that the target address is loopback or an RFC1918 private network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def run_normal_traffic(target: str, count: int = 5, iface: str | None = None) -> None:
    """Generate benign ICMP ping and UDP traffic that should never trigger anomaly alerts."""
    print(f"[*] Generating {count} normal ICMP and UDP packets toward {target}...")
    for i in range(count):
        # Benign ICMP Echo Request
        if iface:
            sendp(Ether() / IP(dst=target) / ICMP(), iface=iface, verbose=False)
            sendp(Ether() / IP(dst=target) / UDP(sport=53000 + i, dport=53), iface=iface, verbose=False)
        else:
            send(IP(dst=target) / ICMP(), verbose=False)
            send(IP(dst=target) / UDP(sport=53000 + i, dport=53), verbose=False)
        time.sleep(0.1)
    print("[+] Normal baseline traffic completed. (Expected: Counters increment, 0 alerts)")


def run_port_scan(target: str, port_count: int = 20, start_port: int = 1, iface: str | None = None) -> None:
    """Generate a bounded sequence of bare TCP SYN packets across distinct ports."""
    print(f"[*] Sending bare TCP SYN probes to ports {start_port}-{start_port + port_count - 1} on target {target}...")
    for port in range(start_port, start_port + port_count):
        if iface:
            pkt = Ether() / IP(dst=target) / TCP(sport=40000 + (port % 10000), dport=port, flags="S")
            sendp(pkt, iface=iface, verbose=False)
        else:
            pkt = IP(dst=target) / TCP(sport=40000 + (port % 10000), dport=port, flags="S")
            send(pkt, verbose=False)
        time.sleep(0.05)
    print(f"[+] Sent {port_count} bare SYN probes. (Expected: PORT_SCAN alert if threshold reached)")


def run_syn_flood(target: str, count: int = 120, port: int = 80, rate: float = 100.0, iface: str | None = None) -> None:
    """Generate a rate-limited burst of bare TCP SYN packets to a single destination port."""
    print(f"[*] Sending burst of {count} bare TCP SYN packets to {target}:{port} (~{rate} pkts/s)...")
    delay = 1.0 / max(1.0, rate)
    for i in range(count):
        if iface:
            pkt = Ether() / IP(dst=target) / TCP(sport=30000 + (i % 5000), dport=port, flags="S")
            sendp(pkt, iface=iface, verbose=False)
        else:
            pkt = IP(dst=target) / TCP(sport=30000 + (i % 5000), dport=port, flags="S")
            send(pkt, verbose=False)
        time.sleep(delay)
    print(f"[+] Sent {count} SYN packets. (Expected: SYN_FLOOD alert if threshold reached)")


def run_arp_conflict(target_ip: str, iface: str | None = None, count: int = 2) -> None:
    """Send conflicting ARP announcements claiming the target IP with different MACs."""
    mac_a = "02:00:00:aa:bb:01"
    mac_b = "02:00:00:aa:bb:02"

    print(f"[*] Generating conflicting ARP claims for IP {target_ip}...")
    print(f"    Claim 1: {target_ip} is at {mac_a}")
    pkt1 = Ether(src=mac_a, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=mac_a, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip
    )
    sendp(pkt1, iface=iface, verbose=False)
    time.sleep(1.0)

    print(f"    Claim 2: {target_ip} is at {mac_b}")
    pkt2 = Ether(src=mac_b, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=mac_b, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip
    )
    sendp(pkt2, iface=iface, verbose=False)
    print("[+] Conflicting ARP claims sent. (Expected: ARP_SPOOF alert)")


def run_icmp_flood(target: str, count: int = 60, rate: float = 60.0, iface: str | None = None) -> None:
    """Generate a rapid burst of ICMP Echo Request packets (Ping Flood)."""
    print(f"[*] Sending burst of {count} ICMP Echo Requests to {target} (~{rate} pkts/s)...")
    delay = 1.0 / max(1.0, rate)
    for _ in range(count):
        if iface:
            sendp(Ether() / IP(dst=target) / ICMP(), iface=iface, verbose=False)
        else:
            send(IP(dst=target) / ICMP(), verbose=False)
        time.sleep(delay)
    print(f"[+] Sent {count} ICMP Echo Requests. (Expected: ICMP_FLOOD alert)")


def run_udp_flood(target: str, count: int = 120, port: int = 53, rate: float = 100.0, iface: str | None = None) -> None:
    """Generate a high-rate burst of UDP datagrams targeting a port."""
    print(f"[*] Sending burst of {count} UDP datagrams to {target}:{port} (~{rate} pkts/s)...")
    delay = 1.0 / max(1.0, rate)
    for i in range(count):
        if iface:
            pkt = Ether() / IP(dst=target) / UDP(sport=30000 + (i % 5000), dport=port)
            sendp(pkt, iface=iface, verbose=False)
        else:
            pkt = IP(dst=target) / UDP(sport=30000 + (i % 5000), dport=port)
            send(pkt, verbose=False)
        time.sleep(delay)
    print(f"[+] Sent {count} UDP datagrams. (Expected: UDP_FLOOD alert)")


def run_xmas_scan(target: str, port: int = 80, count: int = 5, iface: str | None = None) -> None:
    """Generate TCP packets with FIN, PSH, and URG flags set simultaneously (XMAS Scan)."""
    print(f"[*] Sending {count} XMAS scan packets (FIN+PSH+URG) to {target}:{port}...")
    for i in range(count):
        if iface:
            pkt = Ether() / IP(dst=target) / TCP(sport=54320 + i, dport=port, flags="FPU")
            sendp(pkt, iface=iface, verbose=False)
        else:
            pkt = IP(dst=target) / TCP(sport=54320 + i, dport=port, flags="FPU")
            send(pkt, verbose=False)
        time.sleep(0.08)
    print(f"[+] Sent {count} XMAS scan packets. (Expected: TCP_FLAG_ANOMALY alert)")


def run_null_scan(target: str, port: int = 80, count: int = 5, iface: str | None = None) -> None:
    """Generate TCP packets with NO flags set at all (NULL Scan)."""
    print(f"[*] Sending {count} NULL scan packets (0 flags) to {target}:{port}...")
    for i in range(count):
        if iface:
            pkt = Ether() / IP(dst=target) / TCP(sport=54320 + i, dport=port, flags="")
            sendp(pkt, iface=iface, verbose=False)
        else:
            pkt = IP(dst=target) / TCP(sport=54320 + i, dport=port, flags="")
            send(pkt, verbose=False)
        time.sleep(0.08)
    print(f"[+] Sent {count} NULL scan packets. (Expected: TCP_FLAG_ANOMALY alert)")


def run_syn_fin_scan(target: str, port: int = 80, count: int = 5, iface: str | None = None) -> None:
    """Generate TCP packets with illegal simultaneous SYN and FIN flags set (SYN-FIN Scan)."""
    print(f"[*] Sending {count} SYN-FIN scan packets (SYN+FIN) to {target}:{port}...")
    for i in range(count):
        if iface:
            pkt = Ether() / IP(dst=target) / TCP(sport=54320 + i, dport=port, flags="SF")
            sendp(pkt, iface=iface, verbose=False)
        else:
            pkt = IP(dst=target) / TCP(sport=54320 + i, dport=port, flags="SF")
            send(pkt, verbose=False)
        time.sleep(0.08)
    print(f"[+] Sent {count} SYN-FIN scan packets. (Expected: TCP_FLAG_ANOMALY alert)")


def run_land_attack(target: str, port: int = 80, count: int = 3, iface: str | None = None) -> None:
    """Generate LAND attack packets with identical source and destination IP and port."""
    print(f"[*] Sending {count} LAND attack packets (src={target}:{port}, dst={target}:{port})...")
    for _ in range(count):
        if iface:
            pkt = Ether() / IP(src=target, dst=target) / TCP(sport=port, dport=port, flags="S")
            sendp(pkt, iface=iface, verbose=False)
        else:
            pkt = IP(src=target, dst=target) / TCP(sport=port, dport=port, flags="S")
            send(pkt, verbose=False)
        time.sleep(0.1)
    print(f"[+] Sent {count} LAND attack packets. (Expected: LAND_ATTACK alert)")


def main():
    parser = argparse.ArgumentParser(
        description="Safe Lab Traffic Generator for Network Traffic Analyzer (Mini IDS)"
    )
    # Support positional command or --mode flag
    attack_choices = [
        "normal", "benign",
        "port_scan", "port-scan",
        "syn_flood", "syn-flood",
        "arp", "arp_spoof",
        "icmp_flood", "icmp-flood",
        "udp_flood", "udp-flood",
        "xmas", "xmas-scan",
        "null", "null-scan",
        "syn-fin", "syn_fin",
        "land", "land-attack",
    ]
    parser.add_argument(
        "subcommand",
        nargs="?",
        choices=attack_choices,
        help="Test scenario mode (e.g. benign, port-scan, syn-flood, icmp-flood, udp-flood, xmas, null, syn-fin, land, arp)",
    )
    parser.add_argument(
        "--mode",
        choices=attack_choices,
        default=None,
        help="Optional flag for test scenario mode",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address in your private lab (e.g. 10.0.0.2 or 127.0.0.1)",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Optional network interface to bind packet sending (e.g. s1-eth1 or lo)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Packet count for the scenario",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=80,
        help="Target destination port (default 80)",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Port range for scan (e.g. 1-20 or 20)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=100.0,
        help="Target packets per second rate for burst floods (default 100)",
    )

    args = parser.parse_args()

    # Resolve active mode from positional subcommand or --mode flag
    mode = args.subcommand or args.mode
    if not mode:
        parser.error("Scenario mode is required as a positional command (e.g. 'benign') or via '--mode'.")

    # Normalize mode names
    mode_normalized = mode.replace("-", "_")
    if mode_normalized == "benign":
        mode_normalized = "normal"
    elif mode_normalized == "arp":
        mode_normalized = "arp_spoof"
    elif mode_normalized == "xmas_scan":
        mode_normalized = "xmas"
    elif mode_normalized == "null_scan":
        mode_normalized = "null"
    elif mode_normalized == "land_attack":
        mode_normalized = "land"

    # Safety validation: Refuse public networks
    if not is_safe_lab_address(args.target):
        print(f"[ERROR] Target address '{args.target}' is NOT a private lab or loopback address!")
        print("For safety, this lab tool will only send traffic to RFC1918/loopback addresses.")
        sys.exit(1)

    print(f"=== Lab Traffic Generator ===")
    print(f"Mode:   {mode_normalized} (invoked as '{mode}')")
    print(f"Target: {args.target}")
    if args.iface:
        print(f"Iface:  {args.iface}")
    print("=============================")

    # Parse port range if provided
    port_count = args.count or 20
    start_port = 1
    if args.ports:
        if "-" in args.ports:
            parts = args.ports.split("-")
            try:
                start_port = int(parts[0])
                end_port = int(parts[1])
                port_count = max(1, end_port - start_port + 1)
            except ValueError:
                port_count = 20
        else:
            try:
                port_count = int(args.ports)
            except ValueError:
                port_count = 20

    if mode_normalized == "normal":
        run_normal_traffic(args.target, count=args.count or 6, iface=args.iface)
    elif mode_normalized == "port_scan":
        run_port_scan(args.target, port_count=port_count, start_port=start_port, iface=args.iface)
    elif mode_normalized == "syn_flood":
        run_syn_flood(args.target, count=args.count or 120, port=args.port, rate=args.rate, iface=args.iface)
    elif mode_normalized == "arp_spoof":
        run_arp_conflict(args.target, iface=args.iface, count=args.count or 2)
    elif mode_normalized == "icmp_flood":
        run_icmp_flood(args.target, count=args.count or 60, rate=args.rate, iface=args.iface)
    elif mode_normalized == "udp_flood":
        run_udp_flood(args.target, count=args.count or 120, port=args.port if args.port != 80 else 53, rate=args.rate, iface=args.iface)
    elif mode_normalized == "xmas":
        run_xmas_scan(args.target, port=args.port, count=args.count or 5, iface=args.iface)
    elif mode_normalized == "null":
        run_null_scan(args.target, port=args.port, count=args.count or 5, iface=args.iface)
    elif mode_normalized == "syn_fin":
        run_syn_fin_scan(args.target, port=args.port, count=args.count or 5, iface=args.iface)
    elif mode_normalized == "land":
        run_land_attack(args.target, port=args.port, count=args.count or 3, iface=args.iface)


if __name__ == "__main__":
    main()

