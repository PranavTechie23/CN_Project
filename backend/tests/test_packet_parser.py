from datetime import datetime, timezone
import concurrent.futures
import json
import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.analysis.packet_parser import PacketParser, parse_packet
from app.analysis.packet_models import PacketObservation


def test_parse_ipv4_tcp_bare_syn():
    """Test parsing of an IPv4 TCP bare SYN packet."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=54321, dport=80, flags="S")
    )
    obs = parse_packet(pkt, packet_id=1, interface="eth0")

    assert obs is not None
    assert obs.packet_id == 1
    assert obs.interface == "eth0"
    assert obs.protocol == "TCP"
    assert obs.src_ip == "192.168.1.10"
    assert obs.dst_ip == "192.168.1.20"
    assert obs.src_mac == "00:11:22:33:44:55"
    assert obs.dst_mac == "66:77:88:99:aa:bb"
    assert obs.src_port == 54321
    assert obs.dst_port == 80
    assert obs.tcp_syn is True
    assert obs.tcp_ack is False
    assert "S" in (obs.tcp_flags or "")
    assert obs.length_bytes == len(pkt)
    assert obs.timestamp.tzinfo is not None


def test_parse_ipv4_tcp_syn_ack():
    """Test parsing of an IPv4 TCP SYN+ACK handshake packet."""
    pkt = (
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=80, dport=54321, flags="SA")
    )
    obs = parse_packet(pkt, packet_id=2, interface="eth0")

    assert obs is not None
    assert obs.protocol == "TCP"
    assert obs.tcp_syn is True
    assert obs.tcp_ack is True
    assert "S" in (obs.tcp_flags or "")
    assert "A" in (obs.tcp_flags or "")


def test_parse_ipv4_udp():
    """Test parsing of an IPv4 UDP packet."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=53, dport=12345)
    )
    obs = parse_packet(pkt, packet_id=3, interface="eth0")

    assert obs is not None
    assert obs.protocol == "UDP"
    assert obs.src_ip == "10.0.0.1"
    assert obs.dst_ip == "10.0.0.2"
    assert obs.src_port == 53
    assert obs.dst_port == 12345
    assert obs.tcp_syn is False
    assert obs.tcp_ack is False


def test_parse_ipv4_icmp():
    """Test parsing of an ICMP echo request packet."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.5", dst="192.168.1.1")
        / ICMP()
    )
    obs = parse_packet(pkt, packet_id=4, interface="eth0")

    assert obs is not None
    assert obs.protocol == "ICMP"
    assert obs.src_ip == "192.168.1.5"
    assert obs.dst_ip == "192.168.1.1"
    assert obs.src_port is None
    assert obs.dst_port is None


def test_parse_ipv6_tcp():
    """Test parsing of an IPv6 TCP packet."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=443, dport=55555, flags="A")
    )
    obs = parse_packet(pkt, packet_id=5, interface="eth0")

    assert obs is not None
    assert obs.protocol == "TCP"
    assert obs.src_ip == "2001:db8::1"
    assert obs.dst_ip == "2001:db8::2"
    assert obs.src_port == 443
    assert obs.dst_port == 55555
    assert obs.tcp_syn is False
    assert obs.tcp_ack is True


def test_parse_ipv6_icmpv6():
    """Test parsing of an ICMPv6 echo request packet."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IPv6(src="fe80::1", dst="fe80::2")
        / ICMPv6EchoRequest()
    )
    obs = parse_packet(pkt, packet_id=6, interface="eth0")

    assert obs is not None
    assert obs.protocol == "ICMPv6"
    assert obs.src_ip == "fe80::1"
    assert obs.dst_ip == "fe80::2"


def test_parse_arp_request_and_reply():
    """Test parsing of ARP request and reply packets."""
    arp_req = (
        Ether(src="00:aa:bb:cc:dd:ee", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc="00:aa:bb:cc:dd:ee", psrc="192.168.1.50", hwdst="00:00:00:00:00:00", pdst="192.168.1.1")
    )
    obs_req = parse_packet(arp_req, packet_id=7, interface="eth0")

    assert obs_req is not None
    assert obs_req.protocol == "ARP"
    assert obs_req.src_ip == "192.168.1.50"
    assert obs_req.dst_ip == "192.168.1.1"
    assert obs_req.arp_sender_ip == "192.168.1.50"
    assert obs_req.arp_sender_mac == "00:aa:bb:cc:dd:ee"
    assert obs_req.arp_target_ip == "192.168.1.1"

    arp_rep = (
        Ether(src="00:11:22:33:44:99", dst="00:aa:bb:cc:dd:ee")
        / ARP(op=2, hwsrc="00:11:22:33:44:99", psrc="192.168.1.1", hwdst="00:aa:bb:cc:dd:ee", pdst="192.168.1.50")
    )
    obs_rep = parse_packet(arp_rep, packet_id=8, interface="eth0")

    assert obs_rep is not None
    assert obs_rep.protocol == "ARP"
    assert obs_rep.arp_sender_ip == "192.168.1.1"
    assert obs_rep.arp_sender_mac == "00:11:22:33:44:99"


def test_parse_without_ethernet_header():
    """Test parsing a raw IP packet where Ethernet header is absent."""
    pkt = IP(src="172.16.0.1", dst="172.16.0.2") / UDP(sport=1000, dport=2000)
    obs = parse_packet(pkt, packet_id=9, interface="lo")

    assert obs is not None
    assert obs.protocol == "UDP"
    assert obs.src_mac is None
    assert obs.dst_mac is None
    assert obs.src_ip == "172.16.0.1"
    assert obs.dst_ip == "172.16.0.2"


def test_parse_unsupported_protocol_fallback():
    """Test classification fallback to OTHER for unrecognized non-IP packet."""
    pkt = Ether() / Raw(b"\x00\x01\x02\x03")
    obs = parse_packet(pkt, packet_id=10, interface="eth0")

    assert obs is not None
    assert obs.protocol == "OTHER"
    assert obs.src_ip is None
    assert obs.dst_ip is None


def test_parse_malformed_object_safety():
    """Test that malformed or non-packet inputs return None without raising exceptions."""
    class BrokenPacket:
        def __len__(self):
            raise RuntimeError("Corrupted packet length")

    obs = parse_packet(BrokenPacket(), packet_id=11, interface="eth0")
    # Should safely return None or safe observation, never crash
    assert obs is None or isinstance(obs, PacketObservation)


def test_strict_zero_payload_guarantee():
    """Verify that packet payloads are never stored, exposed, or serialized."""
    secret_payload = b"SUPER_SECRET_CREDENTIALS_PASSWORD123!"
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.10.10.10", dst="20.20.20.20")
        / TCP(sport=1234, dport=80, flags="PA")
        / Raw(load=secret_payload)
    )

    obs = parse_packet(pkt, packet_id=12, interface="eth0")
    assert obs is not None

    # Verify no attribute on PacketObservation holds the payload
    for attr in obs.__slots__:
        val = getattr(obs, attr)
        assert secret_payload not in str(val).encode(), f"Payload leaked into attribute {attr}"

    # Verify JSON serialization does not contain payload
    serialized = json.dumps(obs.to_dict())
    assert "SUPER_SECRET" not in serialized
    assert "Raw" not in serialized


def test_packet_parser_monotonic_ids_and_reset():
    """Test PacketParser sequential ID generation, error counting, and reset."""
    parser = PacketParser(start_id=100)

    pkt1 = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
    pkt2 = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()

    obs1 = parser.parse(pkt1, interface="eth0")
    obs2 = parser.parse(pkt2, interface="eth0")

    assert obs1.packet_id == 100
    assert obs2.packet_id == 101

    parser.reset(start_id=1)
    obs3 = parser.parse(pkt1, interface="eth0")
    assert obs3.packet_id == 1


def test_packet_parser_thread_safety():
    """Test PacketParser thread safety when parsing concurrently."""
    parser = PacketParser(start_id=1)
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()

    def worker():
        return parser.parse(pkt, interface="eth0")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: worker(), range(100)))

    ids = [r.packet_id for r in results if r is not None]
    assert len(ids) == 100
    assert len(set(ids)) == 100
    assert min(ids) == 1
    assert max(ids) == 100
