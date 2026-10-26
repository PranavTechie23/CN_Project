from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.runtime import runtime


@pytest.fixture(autouse=True)
def cleanup_alerts():
    """Reset alert store before each test."""
    runtime.alert_store.reset()
    yield
    runtime.alert_store.reset()


def test_list_alerts_and_acknowledgement(client: TestClient):
    """Test GET /api/alerts and POST /api/alerts/{id}/acknowledge."""
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Seed alert store
    alert1 = runtime.alert_store.add_or_update_alert(
        rule_id="PORT_SCAN",
        severity="medium",
        title="Port Scan",
        description="Scanning ports",
        fingerprint="FP_1",
        source_ip="10.0.0.1",
        target_ip="10.0.0.2",
        evidence={"ports": [1, 2, 3]},
        timestamp=t0,
    )
    alert2 = runtime.alert_store.add_or_update_alert(
        rule_id="SYN_FLOOD",
        severity="high",
        title="SYN Flood",
        description="Flood",
        fingerprint="FP_2",
        source_ip=None,
        target_ip="10.0.0.2",
        evidence={"observed_syn_count": 105},
        timestamp=t0,
    )

    # List alerts
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert data["unacknowledged_count"] == 2
    assert len(data["alerts"]) == 2

    # Acknowledge first alert
    ack_res = client.post(f"/api/alerts/{alert1.id}/acknowledge")
    assert ack_res.status_code == 200
    ack_data = ack_res.json()
    assert ack_data["id"] == alert1.id
    assert ack_data["acknowledged"] is True

    # Check that unacknowledged_count decreased to 1
    res2 = client.get("/api/alerts")
    assert res2.json()["unacknowledged_count"] == 1

    # Filter by acknowledged=False
    unack_res = client.get("/api/alerts?acknowledged=false")
    assert len(unack_res.json()["alerts"]) == 1
    assert unack_res.json()["alerts"][0]["id"] == alert2.id

    # Filter by severity
    high_res = client.get("/api/alerts?severity=high")
    assert len(high_res.json()["alerts"]) == 1
    assert high_res.json()["alerts"][0]["rule_id"] == "SYN_FLOOD"

    # Acknowledge non-existent alert returns 404
    not_found_res = client.post("/api/alerts/alert_non_existent/acknowledge")
    assert not_found_res.status_code == 404
    assert not_found_res.json()["detail"]["error"]["code"] == "ALERT_NOT_FOUND"
