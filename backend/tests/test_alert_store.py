from datetime import datetime, timedelta, timezone
import pytest

from app.analysis.alert_store import AlertStore


def test_alert_store_add_and_deduplication_cooldown():
    """Verify alert creation and deduplication within cooldown."""
    store = AlertStore(max_alerts=10, dedup_cooldown_seconds=30)
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # First event
    a1 = store.add_or_update_alert(
        rule_id="PORT_SCAN",
        severity="medium",
        title="Port Scan",
        description="Scanning ports",
        fingerprint="PORT_SCAN:10.0.0.1:10.0.0.2",
        source_ip="10.0.0.1",
        target_ip="10.0.0.2",
        evidence={"ports": [1, 2, 3]},
        timestamp=t0,
    )

    assert a1.id == "alert_000001"
    assert a1.occurrence_count == 1
    assert a1.first_seen == t0
    assert a1.last_seen == t0

    # Recurring event 10s later (within 30s cooldown)
    t1 = t0 + timedelta(seconds=10)
    a2 = store.add_or_update_alert(
        rule_id="PORT_SCAN",
        severity="medium",
        title="Port Scan",
        description="Scanning ports",
        fingerprint="PORT_SCAN:10.0.0.1:10.0.0.2",
        source_ip="10.0.0.1",
        target_ip="10.0.0.2",
        evidence={"ports": [1, 2, 3, 4]},
        timestamp=t1,
    )

    assert a2.id == "alert_000001"  # Same ID
    assert a2.occurrence_count == 2
    assert a2.first_seen == t0
    assert a2.last_seen == t1
    assert a2.evidence["ports"] == [1, 2, 3, 4]

    # After cooldown (35s after t1 = 45s after t0)
    t2 = t1 + timedelta(seconds=35)
    a3 = store.add_or_update_alert(
        rule_id="PORT_SCAN",
        severity="medium",
        title="Port Scan",
        description="Scanning ports",
        fingerprint="PORT_SCAN:10.0.0.1:10.0.0.2",
        source_ip="10.0.0.1",
        target_ip="10.0.0.2",
        evidence={"ports": [10, 20]},
        timestamp=t2,
    )

    assert a3.id == "alert_000002"  # New alert generated
    assert a3.occurrence_count == 1
    assert a3.first_seen == t2


def test_alert_acknowledgement():
    """Verify alert acknowledgement marks status and preserves alert."""
    store = AlertStore()
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    alert = store.add_or_update_alert(
        rule_id="SYN_FLOOD",
        severity="high",
        title="SYN Flood",
        description="Flooding",
        fingerprint="SYN_FLOOD:10.0.0.2",
        source_ip=None,
        target_ip="10.0.0.2",
        evidence={},
        timestamp=t0,
    )

    assert alert.acknowledged is False
    res = store.get_alerts()
    assert res["unacknowledged_count"] == 1

    updated = store.acknowledge_alert(alert.id)
    assert updated is not None
    assert updated.acknowledged is True

    res2 = store.get_alerts()
    assert res2["total"] == 1
    assert res2["unacknowledged_count"] == 0
    assert res2["alerts"][0]["acknowledged"] is True

    # Unknown ID returns None
    assert store.acknowledge_alert("alert_999999") is None


def test_alert_store_capacity_eviction():
    """Verify AlertStore evicts oldest alert when max_alerts is reached."""
    max_cap = 3
    store = AlertStore(max_alerts=max_cap)
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(5):
        store.add_or_update_alert(
            rule_id=f"RULE_{i}",
            severity="medium",
            title=f"Alert {i}",
            description="Test",
            fingerprint=f"FP_{i}",
            source_ip=None,
            target_ip=None,
            evidence={},
            timestamp=t0 + timedelta(seconds=i),
        )

    res = store.get_alerts(limit=10)
    assert res["total"] == 3
    # Newest first: alert_000005, alert_000004, alert_000003
    ids = [a["id"] for a in res["alerts"]]
    assert ids == ["alert_000005", "alert_000004", "alert_000003"]


def test_alert_filtering():
    """Verify filtering by severity, rule_id, and acknowledged status."""
    store = AlertStore()
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    a1 = store.add_or_update_alert(
        rule_id="PORT_SCAN",
        severity="medium",
        title="Port Scan",
        description="",
        fingerprint="FP_1",
        source_ip=None,
        target_ip=None,
        evidence={},
        timestamp=t0,
    )
    store.add_or_update_alert(
        rule_id="SYN_FLOOD",
        severity="high",
        title="SYN Flood",
        description="",
        fingerprint="FP_2",
        source_ip=None,
        target_ip=None,
        evidence={},
        timestamp=t0,
    )

    # Acknowledge first alert
    store.acknowledge_alert(a1.id)

    # Filter by severity
    high_alerts = store.get_alerts(severity="high")["alerts"]
    assert len(high_alerts) == 1
    assert high_alerts[0]["rule_id"] == "SYN_FLOOD"

    # Filter by acknowledged=False
    unack_alerts = store.get_alerts(acknowledged=False)["alerts"]
    assert len(unack_alerts) == 1
    assert unack_alerts[0]["rule_id"] == "SYN_FLOOD"

    # Filter by rule_id
    scan_alerts = store.get_alerts(rule_id="PORT_SCAN")["alerts"]
    assert len(scan_alerts) == 1
    assert scan_alerts[0]["id"] == a1.id
