from datetime import datetime, timedelta, timezone
import pytest

from app.analysis.packet_models import PacketObservation
from app.analysis.alert_store import AlertStore
from app.analysis.detection_engine import DetectionConfig, DetectionEngine


def make_obs(
    protocol: str,
    src_ip: str,
    dst_ip: str,
    ts: datetime,
    *,
    src_port: int | None = None,
    dst_port: int | None = None,
    tcp_syn: bool = False,
    tcp_ack: bool = False,
    tcp_flags_int: int | None = None,
    tcp_flags: str | None = None,
) -> PacketObservation:
    return PacketObservation(
        packet_id=1,
        timestamp=ts,
        interface="en0",
        protocol=protocol,
        length_bytes=60,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
        tcp_flags_int=tcp_flags_int,
        tcp_flags=tcp_flags,
    )


# ==============================================================================
# Rule D: ICMP Flood Tests
# ==============================================================================

def test_icmp_flood_positive_trigger():
    alert_store = AlertStore()
    config = DetectionConfig(icmp_flood_window_seconds=5, icmp_flood_threshold=50)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)

    alerts = []
    for i in range(50):
        obs = make_obs("ICMP", "192.168.1.50", "192.168.1.100", t0 + timedelta(milliseconds=i * 20))
        alerts = engine.process(obs)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "ICMP_FLOOD"
    assert alert.severity == "high"
    assert alert.target_ip == "192.168.1.100"
    assert alert.evidence["observed_icmp_count"] == 50


def test_icmp_flood_negative_below_threshold():
    alert_store = AlertStore()
    config = DetectionConfig(icmp_flood_window_seconds=5, icmp_flood_threshold=50)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)

    # Send 10 packets (normal ping)
    for i in range(10):
        obs = make_obs("ICMP", "192.168.1.50", "192.168.1.100", t0 + timedelta(milliseconds=i * 100))
        alerts = engine.process(obs)
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


# ==============================================================================
# Rule E: UDP Flood Tests
# ==============================================================================

def test_udp_flood_positive_trigger():
    alert_store = AlertStore()
    config = DetectionConfig(udp_flood_window_seconds=5, udp_flood_threshold=100)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)

    alerts = []
    for i in range(100):
        obs = make_obs("UDP", "192.168.1.50", "192.168.1.100", t0 + timedelta(milliseconds=i * 10), src_port=50000 + i, dst_port=53)
        alerts = engine.process(obs)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "UDP_FLOOD"
    assert alert.severity == "high"
    assert alert.target_ip == "192.168.1.100"
    assert alert.evidence["observed_udp_count"] == 100


def test_udp_flood_negative_below_threshold():
    alert_store = AlertStore()
    config = DetectionConfig(udp_flood_window_seconds=5, udp_flood_threshold=100)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(20):
        obs = make_obs("UDP", "192.168.1.50", "192.168.1.100", t0 + timedelta(milliseconds=i * 50), src_port=50000, dst_port=53)
        alerts = engine.process(obs)
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


# ==============================================================================
# Rule F: TCP Flag Anomaly Tests (NULL, XMAS, SYN-FIN)
# ==============================================================================

def test_tcp_flag_anomaly_null_scan():
    alert_store = AlertStore()
    engine = DetectionEngine(alert_store=alert_store)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    obs = make_obs("TCP", "10.0.0.5", "10.0.0.1", t0, src_port=54321, dst_port=80, tcp_flags_int=0, tcp_flags="")

    alerts = engine.process(obs)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "TCP_FLAG_ANOMALY"
    assert "NULL scan" in alert.title
    assert alert.severity == "medium"
    assert alert.target_ip == "10.0.0.1"


def test_tcp_flag_anomaly_xmas_scan():
    alert_store = AlertStore()
    engine = DetectionEngine(alert_store=alert_store)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    # XMAS bitmask: 0x29 (FIN=0x01, PSH=0x08, URG=0x20)
    obs = make_obs("TCP", "10.0.0.5", "10.0.0.1", t0, src_port=54321, dst_port=80, tcp_flags_int=0x29, tcp_flags="FPU")

    alerts = engine.process(obs)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "TCP_FLAG_ANOMALY"
    assert "XMAS scan" in alert.title
    assert alert.target_ip == "10.0.0.1"


def test_tcp_flag_anomaly_syn_fin_scan():
    alert_store = AlertStore()
    engine = DetectionEngine(alert_store=alert_store)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    # SYN+FIN bitmask: 0x03
    obs = make_obs("TCP", "10.0.0.5", "10.0.0.1", t0, src_port=54321, dst_port=80, tcp_flags_int=0x03, tcp_flags="SF")

    alerts = engine.process(obs)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "TCP_FLAG_ANOMALY"
    assert "SYN-FIN scan" in alert.title


def test_tcp_flag_anomaly_negative_normal_flags():
    alert_store = AlertStore()
    engine = DetectionEngine(alert_store=alert_store)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    # Normal SYN
    obs1 = make_obs("TCP", "10.0.0.5", "10.0.0.1", t0, src_port=54321, dst_port=80, tcp_flags_int=0x02, tcp_flags="S", tcp_syn=True)
    alerts1 = engine.process(obs1)
    # Shouldn't trigger flag anomaly (may be port scan if threshold reached, but 1 packet won't)
    flag_alerts = [a for a in alerts1 if a.rule_id == "TCP_FLAG_ANOMALY"]
    assert len(flag_alerts) == 0

    # Normal ACK
    obs2 = make_obs("TCP", "10.0.0.5", "10.0.0.1", t0, src_port=54321, dst_port=80, tcp_flags_int=0x10, tcp_flags="A", tcp_ack=True)
    alerts2 = engine.process(obs2)
    assert len(alerts2) == 0


# ==============================================================================
# Rule G: LAND Attack Tests
# ==============================================================================

def test_land_attack_positive():
    alert_store = AlertStore()
    engine = DetectionEngine(alert_store=alert_store)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    # LAND attack: src_ip == dst_ip and src_port == dst_port
    obs = make_obs("TCP", "10.0.0.1", "10.0.0.1", t0, src_port=80, dst_port=80, tcp_syn=True, tcp_flags_int=0x02, tcp_flags="S")

    alerts = engine.process(obs)
    land_alerts = [a for a in alerts if a.rule_id == "LAND_ATTACK"]
    assert len(land_alerts) == 1
    alert = land_alerts[0]
    assert alert.rule_id == "LAND_ATTACK"
    assert alert.severity == "high"
    assert alert.source_ip == "10.0.0.1"
    assert alert.target_ip == "10.0.0.1"


def test_land_attack_negative_different_ports():
    alert_store = AlertStore()
    engine = DetectionEngine(alert_store=alert_store)

    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    # Local loopback client connecting to server (same IP, different ports)
    obs = make_obs("TCP", "127.0.0.1", "127.0.0.1", t0, src_port=54321, dst_port=8000, tcp_syn=True, tcp_flags_int=0x02, tcp_flags="S")

    alerts = engine.process(obs)
    land_alerts = [a for a in alerts if a.rule_id == "LAND_ATTACK"]
    assert len(land_alerts) == 0
