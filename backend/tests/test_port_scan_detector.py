from datetime import datetime, timedelta, timezone
import pytest

from app.analysis.packet_models import PacketObservation
from app.analysis.alert_store import AlertStore
from app.analysis.detection_engine import DetectionConfig, DetectionEngine


def make_syn_obs(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    ts: datetime,
    *,
    tcp_ack: bool = False
) -> PacketObservation:
    """Helper to create TCP SYN packet observation."""
    return PacketObservation(
        packet_id=1,
        timestamp=ts,
        interface="eth0",
        protocol="TCP",
        length_bytes=60,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        tcp_syn=True,
        tcp_ack=tcp_ack,
    )


def test_port_scan_positive_trigger():
    """Verify that reaching threshold of distinct bare SYN ports emits an alert."""
    alert_store = AlertStore()
    config = DetectionConfig(port_scan_window_seconds=10, port_scan_unique_ports_threshold=15)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Send 15 bare SYNs to 15 distinct ports on target
    last_alerts = []
    for port in range(1, 16):
        obs = make_syn_obs("10.0.0.3", "10.0.0.2", port, t0 + timedelta(seconds=port * 0.1))
        last_alerts = engine.process(obs)

    # 15th port should trigger the alert
    assert len(last_alerts) == 1
    alert = last_alerts[0]
    assert alert.rule_id == "PORT_SCAN"
    assert alert.source_ip == "10.0.0.3"
    assert alert.target_ip == "10.0.0.2"
    assert alert.evidence["unique_destination_ports"] == 15
    assert len(alert.evidence["sample_ports"]) == 10
    assert alert.evidence["threshold"] == 15


def test_port_scan_negative_repeated_same_port():
    """Verify repeated probes to the SAME destination port do NOT trigger port scan."""
    alert_store = AlertStore()
    config = DetectionConfig(port_scan_window_seconds=10, port_scan_unique_ports_threshold=15)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Send 50 bare SYNs to port 80 only
    for _ in range(50):
        obs = make_syn_obs("10.0.0.3", "10.0.0.2", 80, t0)
        alerts = engine.process(obs)
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


def test_port_scan_negative_syn_ack_ignored():
    """Verify that SYN+ACK packets are ignored and do not count toward port scan."""
    alert_store = AlertStore()
    config = DetectionConfig(port_scan_window_seconds=10, port_scan_unique_ports_threshold=5)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Send SYN+ACK packets (tcp_ack=True)
    for port in range(1, 20):
        obs = make_syn_obs("10.0.0.3", "10.0.0.2", port, t0, tcp_ack=True)
        alerts = engine.process(obs)
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


def test_port_scan_negative_window_expiry():
    """Verify that probes outside the rolling window expire and do not meet threshold."""
    alert_store = AlertStore()
    config = DetectionConfig(port_scan_window_seconds=5, port_scan_unique_ports_threshold=10)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Send 5 distinct ports at t0
    for port in range(1, 6):
        obs = make_syn_obs("10.0.0.3", "10.0.0.2", port, t0)
        engine.process(obs)

    # Send 5 distinct ports at t0 + 10s (first 5 have expired from 5s window)
    t1 = t0 + timedelta(seconds=10)
    for port in range(6, 11):
        obs = make_syn_obs("10.0.0.3", "10.0.0.2", port, t1)
        alerts = engine.process(obs)
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


def test_port_scan_negative_different_sources_not_combined():
    """Verify that two separate source IPs scanning different ports are not combined."""
    alert_store = AlertStore()
    config = DetectionConfig(port_scan_window_seconds=10, port_scan_unique_ports_threshold=10)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Source A probes 6 ports
    for port in range(1, 7):
        obs = make_syn_obs("10.0.0.3", "10.0.0.2", port, t0)
        assert len(engine.process(obs)) == 0

    # Source B probes 6 different ports
    for port in range(7, 13):
        obs = make_syn_obs("10.0.0.4", "10.0.0.2", port, t0)
        assert len(engine.process(obs)) == 0

    assert alert_store.get_alerts()["total"] == 0
