from datetime import datetime, timedelta, timezone
import pytest

from app.analysis.packet_models import PacketObservation
from app.analysis.alert_store import AlertStore
from app.analysis.detection_engine import DetectionConfig, DetectionEngine


def make_arp_obs(
    sender_ip: str,
    sender_mac: str,
    ts: datetime,
    target_ip: str = "192.168.1.1"
) -> PacketObservation:
    """Helper to create ARP packet observation."""
    return PacketObservation(
        packet_id=1,
        timestamp=ts,
        interface="eth0",
        protocol="ARP",
        length_bytes=42,
        src_ip=sender_ip,
        dst_ip=target_ip,
        arp_sender_ip=sender_ip,
        arp_sender_mac=sender_mac,
        arp_target_ip=target_ip,
    )


def test_arp_spoof_positive_conflict():
    """Verify that different MAC claiming the same IPv4 within window emits ARP_SPOOF alert."""
    alert_store = AlertStore()
    config = DetectionConfig(arp_conflict_window_seconds=60)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Legitimate claim: 192.168.1.1 is at aa:bb:cc:dd:ee:01
    obs1 = make_arp_obs("192.168.1.1", "aa:bb:cc:dd:ee:01", t0)
    alerts1 = engine.process(obs1)
    assert len(alerts1) == 0

    # Conflicting claim 5s later: 192.168.1.1 is at aa:bb:cc:dd:ee:99
    t1 = t0 + timedelta(seconds=5)
    obs2 = make_arp_obs("192.168.1.1", "aa:bb:cc:dd:ee:99", t1)
    alerts2 = engine.process(obs2)

    assert len(alerts2) == 1
    alert = alerts2[0]
    assert alert.rule_id == "ARP_SPOOF"
    assert alert.severity == "high"
    assert alert.target_ip == "192.168.1.1"
    assert alert.evidence["claimed_ip"] == "192.168.1.1"
    assert alert.evidence["prior_mac"] == "aa:bb:cc:dd:ee:01"
    assert alert.evidence["new_mac"] == "aa:bb:cc:dd:ee:99"
    assert alert.evidence["window_seconds"] == 60


def test_arp_spoof_negative_same_mac_repeated():
    """Verify that repeated ARP announcements with the SAME MAC do NOT alert."""
    alert_store = AlertStore()
    config = DetectionConfig(arp_conflict_window_seconds=60)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(20):
        obs = make_arp_obs("192.168.1.1", "aa:bb:cc:dd:ee:01", t0 + timedelta(seconds=i))
        alerts = engine.process(obs)
        assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


def test_arp_spoof_negative_expired_mapping():
    """Verify that mapping conflict outside the window does NOT trigger when prior mapping expired."""
    alert_store = AlertStore()
    config = DetectionConfig(arp_conflict_window_seconds=10)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Claim at t0
    obs1 = make_arp_obs("192.168.1.1", "aa:bb:cc:dd:ee:01", t0)
    engine.process(obs1)

    # Claim 20s later (prior mapping expired from 10s window)
    t1 = t0 + timedelta(seconds=20)
    obs2 = make_arp_obs("192.168.1.1", "aa:bb:cc:dd:ee:99", t1)
    alerts = engine.process(obs2)
    assert len(alerts) == 0

    assert alert_store.get_alerts()["total"] == 0


def test_arp_spoof_negative_invalid_addresses_ignored():
    """Verify that 0.0.0.0 or broadcast sender MACs do not trigger false alerts."""
    alert_store = AlertStore()
    config = DetectionConfig(arp_conflict_window_seconds=60)
    engine = DetectionEngine(alert_store=alert_store, config=config)

    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # ARP probe with 0.0.0.0
    obs1 = make_arp_obs("0.0.0.0", "aa:bb:cc:dd:ee:01", t0)
    obs2 = make_arp_obs("0.0.0.0", "aa:bb:cc:dd:ee:99", t0)
    assert len(engine.process(obs1)) == 0
    assert len(engine.process(obs2)) == 0

    # Broadcast MAC
    obs3 = make_arp_obs("192.168.1.1", "ff:ff:ff:ff:ff:ff", t0)
    assert len(engine.process(obs3)) == 0

    assert alert_store.get_alerts()["total"] == 0
