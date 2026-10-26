from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.analysis.packet_models import PacketObservation
from app.main import app
from app.services.runtime import runtime


@pytest.fixture(autouse=True)
def cleanup_metrics():
    """Reset metrics store before each test."""
    runtime.metrics_store.reset()
    yield
    runtime.metrics_store.reset()


def test_metrics_summary_and_hosts_endpoints(client: TestClient):
    """Test GET /api/metrics/summary and GET /api/metrics/hosts."""
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Ingest test packets
    obs1 = PacketObservation(
        packet_id=1,
        timestamp=t0,
        interface="eth0",
        protocol="TCP",
        length_bytes=1000,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
    )
    obs2 = PacketObservation(
        packet_id=2,
        timestamp=t0,
        interface="eth0",
        protocol="UDP",
        length_bytes=500,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=53,
        dst_port=4321,
    )
    runtime.metrics_store.record_observation(obs1)
    runtime.metrics_store.record_observation(obs2)

    # Test summary with window_seconds and window alias
    sum_res = client.get("/api/metrics/summary?window_seconds=30")
    assert sum_res.status_code == 200
    sum_data = sum_res.json()
    assert sum_data["session"]["packets"] == 2
    assert sum_data["session"]["bytes"] == 1500
    assert sum_data["window_seconds"] == 30
    assert len(sum_data["protocols"]) == 7  # All standard protocols present

    sum_res_alias = client.get("/api/metrics/summary?window=15")
    assert sum_res_alias.status_code == 200
    assert sum_res_alias.json()["window_seconds"] == 15

    # Test top hosts with window alias
    hosts_res = client.get("/api/metrics/hosts?limit=5&window=20")
    assert hosts_res.status_code == 200
    hosts_data = hosts_res.json()
    assert hosts_data["total_hosts"] == 2
    assert hosts_data["window_seconds"] == 20
    assert len(hosts_data["hosts"]) == 2
    assert hosts_data["hosts"][0]["host_ip"] in ("10.0.0.1", "10.0.0.2")

    # Test recent packets
    pkts_res = client.get("/api/packets?limit=10")
    assert pkts_res.status_code == 200
    pkts_data = pkts_res.json()
    assert pkts_data["total"] == 2
    assert len(pkts_data["packets"]) == 2
    assert pkts_data["packets"][0]["packet_id"] == 2  # Newest first

    # Test protocol filtering
    tcp_pkts = client.get("/api/packets?protocol=TCP")
    assert tcp_pkts.status_code == 200
    tcp_data = tcp_pkts.json()
    assert tcp_data["total"] == 1
    assert tcp_data["packets"][0]["protocol"] == "TCP"

    udp_pkts = client.get("/api/packets?protocol=UDP")
    assert udp_pkts.status_code == 200
    udp_data = udp_pkts.json()
    assert udp_data["total"] == 1
    assert udp_data["packets"][0]["protocol"] == "UDP"
