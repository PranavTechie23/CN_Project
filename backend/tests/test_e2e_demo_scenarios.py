from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether

from app.main import app
from app.services.runtime import runtime


@pytest.fixture(autouse=True)
def cleanup():
    """Reset capture and stores before and after test."""
    runtime.capture_manager.stop()
    runtime.packet_parser.reset()
    runtime.metrics_store.reset()
    runtime.detection_engine.reset()
    runtime.alert_store.reset()
    yield
    runtime.capture_manager.stop()


def test_full_demo_matrix_e2e(client: TestClient):
    """End-to-End verification of the full demo matrix (PRD Section 15.8):

    - Scenario 1: Initial state is stopped with 0 packets and 0 alerts.
    - Scenario 2: Normal traffic increments counters without raising alerts.
    - Scenario 3: Bounded TCP port scan produces a single PORT_SCAN alert.
    - Scenario 4: High-rate SYN burst produces a SYN_FLOOD alert.
    - Scenario 5: Conflicting ARP claims produce an ARP_SPOOF alert.
    - Scenario 6: Stopping capture preserves final session metrics.
    - Scenario 7: Starting a new session resets session-scoped state.
    """
    # Use mock sniffer so tests execute synchronously and deterministically
    mock_sniffer = MagicMock()
    runtime.capture_manager.sniffer_factory = lambda iface, prn: mock_sniffer
    original_validate = runtime.interface_service.validate_interface
    runtime.interface_service.validate_interface = lambda name: True

    try:
        # --- SCENARIO 1: Initial State ---
        status = client.get("/api/capture/status").json()
        assert status["state"] == "stopped"
        assert status["packets_seen"] == 0
        alerts = client.get("/api/alerts").json()
        assert alerts["total"] == 0

        # Start capture
        start_res = client.post("/api/capture/start", json={"interface": "eth0"})
        assert start_res.status_code == 200
        assert start_res.json()["state"] == "running"

        # --- SCENARIO 2: Normal Lab Traffic (Zero Alerts Expected) ---
        t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

        # Send benign ICMP ping and UDP DNS packet
        ping_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        dns_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=54321, dport=53)

        runtime.capture_manager._packet_callback(ping_pkt)
        runtime.capture_manager._packet_callback(dns_pkt)

        metrics = client.get("/api/metrics/summary").json()
        assert metrics["session"]["packets"] == 2
        proto_counts = {p["protocol"]: p["packets"] for p in metrics["protocols"]}
        assert proto_counts["ICMP"] == 1
        assert proto_counts["UDP"] == 1

        alerts = client.get("/api/alerts").json()
        assert alerts["total"] == 0, "Normal traffic must not trigger any alerts"

        # --- SCENARIO 3: Port Scan Detection ---
        for port in range(1, 21):
            scan_pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src="10.0.0.3", dst="10.0.0.2")
                / TCP(sport=50000 + port, dport=port, flags="S")
            )
            runtime.capture_manager._packet_callback(scan_pkt)

        alerts = client.get("/api/alerts?rule_id=PORT_SCAN").json()
        assert len(alerts["alerts"]) == 1
        port_scan_alert = alerts["alerts"][0]
        assert port_scan_alert["rule_id"] == "PORT_SCAN"
        assert port_scan_alert["source_ip"] == "10.0.0.3"
        assert port_scan_alert["target_ip"] == "10.0.0.2"
        assert port_scan_alert["evidence"]["unique_destination_ports"] >= 15

        # --- SCENARIO 4: SYN Flood Detection ---
        for i in range(110):
            flood_pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src=f"192.168.1.{i % 10}", dst="10.0.0.9")
                / TCP(sport=30000 + i, dport=80, flags="S")
            )
            runtime.capture_manager._packet_callback(flood_pkt)

        alerts = client.get("/api/alerts?rule_id=SYN_FLOOD").json()
        assert len(alerts["alerts"]) == 1
        syn_flood_alert = alerts["alerts"][0]
        assert syn_flood_alert["rule_id"] == "SYN_FLOOD"
        assert syn_flood_alert["target_ip"] == "10.0.0.9"
        assert syn_flood_alert["evidence"]["observed_syn_count"] >= 100

        # --- SCENARIO 5: Conflicting ARP Mapping Detection ---
        arp1 = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.1"
        )
        arp2 = Ether(src="aa:bb:cc:dd:ee:99", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc="aa:bb:cc:dd:ee:99", psrc="10.0.0.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.1"
        )
        runtime.capture_manager._packet_callback(arp1)
        runtime.capture_manager._packet_callback(arp2)

        alerts = client.get("/api/alerts?rule_id=ARP_SPOOF").json()
        assert len(alerts["alerts"]) == 1
        arp_alert = alerts["alerts"][0]
        assert arp_alert["rule_id"] == "ARP_SPOOF"
        assert arp_alert["target_ip"] == "10.0.0.1"
        assert arp_alert["evidence"]["claimed_ip"] == "10.0.0.1"
        assert arp_alert["evidence"]["prior_mac"] == "aa:bb:cc:dd:ee:01"
        assert arp_alert["evidence"]["new_mac"] == "aa:bb:cc:dd:ee:99"

        # --- SCENARIO 6: Stop Capture Preserves Summary ---
        stop_res = client.post("/api/capture/stop")
        assert stop_res.status_code == 200
        stopped_status = client.get("/api/capture/status").json()
        assert stopped_status["state"] == "stopped"
        assert stopped_status["packets_seen"] > 0

        # --- SCENARIO 7: Start New Session Resets State ---
        client.post("/api/capture/start", json={"interface": "eth0"})
        new_status = client.get("/api/capture/status").json()
        assert new_status["state"] == "running"
        assert new_status["packets_seen"] == 0

        new_metrics = client.get("/api/metrics/summary").json()
        assert new_metrics["session"]["packets"] == 0

        new_alerts = client.get("/api/alerts").json()
        assert new_alerts["total"] == 0

    finally:
        runtime.interface_service.validate_interface = original_validate
        runtime.capture_manager.sniffer_factory = runtime.capture_manager._default_sniffer_factory


def test_traffic_generator_cli_safety_and_subcommands():
    """Verify traffic_generator.py safe lab address filter and argument parsing."""
    import subprocess
    import sys
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent.parent

    # Test safety guard rejects public IP 8.8.8.8
    res_unsafe = subprocess.run(
        [sys.executable, "scripts/lab/traffic_generator.py", "benign", "--target", "8.8.8.8"],
        capture_output=True,
        text=True,
        cwd=str(project_root)
    )
    assert res_unsafe.returncode != 0
    assert "NOT a private lab or loopback address" in res_unsafe.stdout or "NOT a private lab or loopback address" in res_unsafe.stderr

    # Test --help works cleanly
    res_help = subprocess.run(
        [sys.executable, "scripts/lab/traffic_generator.py", "--help"],
        capture_output=True,
        text=True,
        cwd=str(project_root)
    )
    assert res_help.returncode == 0
    assert "Safe Lab Traffic Generator" in res_help.stdout
