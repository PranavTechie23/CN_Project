from datetime import datetime, timedelta, timezone
import pytest

from app.analysis.packet_models import PacketObservation
from app.analysis.alert_store import AlertStore
from app.analysis.detection_engine import DetectionConfig, DetectionEngine


def make_syn_obs(
    src_ip: str,
    dst_ip: str,
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
        dst_port=80,
        tcp_syn=True,
        tcp_ack=tcp_ack,
    )


def test_syn_flood_positive_trigger():
    """Verify that reaching threshold of bare SYNs to a target within window triggers SYN_FLOOD alert."""
    alert_store = AlertStore()
    config = DetectionConfig(syn_flood_window_seconds=5, syn_flood_syn_threshold=100)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    last_alerts = []
    # Send 100 bare SYNs to 10.0.0.2 within 3 seconds
    for i in range(100):
        obs = make_syn_obs(f"192.168.1.{i % 10}", "10.0.0.2", t0 + timedelta(milliseconds=i * 20))
        last_alerts = engine.process(obs)

    assert len(last_alerts) == 1
    alert = last_alerts[0]
    assert alert.rule_id == "SYN_FLOOD"
    assert alert.severity == "high"
    assert alert.target_ip == "10.0.0.2"
    assert alert.evidence["observed_syn_count"] == 100
    assert alert.evidence["threshold"] == 100
    assert alert.evidence["window_seconds"] == 5


def test_syn_flood_negative_syn_ack_ignored():
    """Verify that SYN+ACK packets are ignored and do not count toward SYN flood."""
    alert_store = AlertStore()
    config = DetectionConfig(syn_flood_window_seconds=5, syn_flood_syn_threshold=10)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(50):
        obs = make_syn_obs("10.0.0.1", "10.0.0.2", t0, tcp_ack=True)
        alerts = engine.process(obs)
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


def test_syn_flood_negative_sub_threshold():
    """Verify that fewer than threshold bare SYNs do not alert."""
    alert_store = AlertStore()
    config = DetectionConfig(syn_flood_window_seconds=5, syn_flood_syn_threshold=100)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(99):  # 1 short of 100
        obs = make_syn_obs("10.0.0.1", "10.0.0.2", t0)
        alerts = engine.process(obs)
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


def test_syn_flood_negative_window_expiry():
    """Verify that SYN packets outside the window expire and do not accumulate."""
    alert_store = AlertStore()
    config = DetectionConfig(syn_flood_window_seconds=2, syn_flood_syn_threshold=10)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # 8 packets at t0
    for _ in range(8):
        engine.process(make_syn_obs("10.0.0.1", "10.0.0.2", t0))

    # 4 packets at t0 + 5s (first 8 expired from 2s window)
    t1 = t0 + timedelta(seconds=5)
    for _ in range(4):
        alerts = engine.process(make_syn_obs("10.0.0.1", "10.0.0.2", t1))
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


def test_syn_flood_negative_different_destinations_not_combined():
    """Verify traffic to different destination IPs is not combined."""
    alert_store = AlertStore()
    config = DetectionConfig(syn_flood_window_seconds=5, syn_flood_syn_threshold=10)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # 6 packets to target 1
    for _ in range(6):
        assert len(engine.process(make_syn_obs("10.0.0.1", "10.0.0.2", t0))) == 0

    # 6 packets to target 2
    for _ in range(6):
        assert len(engine.process(make_syn_obs("10.0.0.1", "10.0.0.3", t0))) == 0

    assert alert_store.get_alerts()["total"] == 0
