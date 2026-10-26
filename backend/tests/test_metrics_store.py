from datetime import datetime, timedelta, timezone
import concurrent.futures
import pytest

from app.analysis.packet_models import PacketObservation
from app.analysis.metrics_store import MetricsStore


def create_mock_obs(
    packet_id: int,
    *,
    protocol: str = "TCP",
    length_bytes: int = 100,
    src_ip: str | None = "192.168.1.10",
    dst_ip: str | None = "192.168.1.20",
    timestamp: datetime | None = None
) -> PacketObservation:
    """Helper to construct synthetic PacketObservation instances."""
    ts = timestamp if timestamp is not None else datetime.now(timezone.utc)
    return PacketObservation(
        packet_id=packet_id,
        timestamp=ts,
        interface="eth0",
        protocol=protocol,
        length_bytes=length_bytes,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )


def test_session_totals_and_protocols():
    """Verify cumulative packet and byte totals and per-protocol buckets."""
    store = MetricsStore(default_window_seconds=60)
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    store.record_observation(create_mock_obs(1, protocol="TCP", length_bytes=200, timestamp=t0))
    store.record_observation(create_mock_obs(2, protocol="UDP", length_bytes=100, timestamp=t0))
    store.record_observation(create_mock_obs(3, protocol="ICMP", length_bytes=50, timestamp=t0))
    store.record_observation(create_mock_obs(4, protocol="CUSTOM_PROTO", length_bytes=75, timestamp=t0))  # -> OTHER

    summary = store.get_summary(now=t0)

    assert summary["session"]["packets"] == 4
    assert summary["session"]["bytes"] == 425

    proto_dict = {p["protocol"]: p for p in summary["protocols"]}
    assert proto_dict["TCP"]["packets"] == 1
    assert proto_dict["TCP"]["bytes"] == 200
    assert proto_dict["UDP"]["packets"] == 1
    assert proto_dict["UDP"]["bytes"] == 100
    assert proto_dict["ICMP"]["packets"] == 1
    assert proto_dict["ICMP"]["bytes"] == 50
    assert proto_dict["OTHER"]["packets"] == 1
    assert proto_dict["OTHER"]["bytes"] == 75
    assert proto_dict["ARP"]["packets"] == 0
    assert proto_dict["ARP"]["bytes"] == 0


def test_host_directionality_tx_rx():
    """Verify that source IP increments TX and destination IP increments RX."""
    store = MetricsStore(default_window_seconds=60)
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Host A sends 500 bytes to Host B
    store.record_observation(create_mock_obs(
        1,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        length_bytes=500,
        timestamp=t0
    ))

    # Host B replies with 200 bytes to Host A
    store.record_observation(create_mock_obs(
        2,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        length_bytes=200,
        timestamp=t0
    ))

    top = store.get_top_hosts(now=t0)
    hosts_by_ip = {h["host_ip"]: h for h in top["hosts"]}

    assert len(hosts_by_ip) == 2

    # Host A (10.0.0.1): TX=500, RX=200
    assert hosts_by_ip["10.0.0.1"]["tx_bytes"] == 500
    assert hosts_by_ip["10.0.0.1"]["rx_bytes"] == 200
    assert hosts_by_ip["10.0.0.1"]["tx_packets"] == 1
    assert hosts_by_ip["10.0.0.1"]["rx_packets"] == 1

    # Host B (10.0.0.2): TX=200, RX=500
    assert hosts_by_ip["10.0.0.2"]["tx_bytes"] == 200
    assert hosts_by_ip["10.0.0.2"]["rx_bytes"] == 500
    assert hosts_by_ip["10.0.0.2"]["tx_packets"] == 1
    assert hosts_by_ip["10.0.0.2"]["rx_packets"] == 1


def test_missing_and_zero_ip_ignored():
    """Verify that None, empty, or 0.0.0.0 IP does not create host rows."""
    store = MetricsStore(default_window_seconds=60)
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Observation with None IPs
    store.record_observation(create_mock_obs(1, src_ip=None, dst_ip=None, length_bytes=60, timestamp=t0))
    # Observation with 0.0.0.0
    store.record_observation(create_mock_obs(2, src_ip="0.0.0.0", dst_ip=None, length_bytes=60, timestamp=t0))

    top = store.get_top_hosts(now=t0)
    assert len(top["hosts"]) == 0
    assert top["total_hosts"] == 0

    # But session totals should still record them
    summary = store.get_summary(now=t0)
    assert summary["session"]["packets"] == 2
    assert summary["session"]["bytes"] == 120


def test_rolling_window_expiry_and_rates():
    """Verify deterministic expiry of old observations outside the rolling window."""
    store = MetricsStore(default_window_seconds=10)
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # 10 packets of 100 bytes at t0 (1000 bytes)
    for i in range(10):
        store.record_observation(create_mock_obs(
            i + 1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            length_bytes=100,
            timestamp=t0
        ))

    # At t0 + 2s, all 10 packets are inside the 10s window
    t1 = t0 + timedelta(seconds=2)
    summary1 = store.get_summary(window_seconds=10, now=t1)
    assert summary1["window"]["packets"] == 10
    assert summary1["window"]["bytes"] == 1000

    # At t0 + 15s (beyond 10s window), those packets have expired from the rolling window
    t2 = t0 + timedelta(seconds=15)
    summary2 = store.get_summary(window_seconds=10, now=t2)
    assert summary2["window"]["packets"] == 0
    assert summary2["window"]["bytes"] == 0
    assert summary2["window"]["packets_per_second"] == 0.0
    assert summary2["window"]["bytes_per_second"] == 0.0

    # But cumulative session totals remain intact
    assert summary2["session"]["packets"] == 10
    assert summary2["session"]["bytes"] == 1000


def test_top_hosts_sorting():
    """Verify top hosts sort correctly by total bytes or individual TX/RX bytes."""
    store = MetricsStore(default_window_seconds=60)
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    # Host 1 (10.0.0.1) transmits 10,000 bytes to Host 2 (192.168.1.1)
    store.record_observation(create_mock_obs(1, src_ip="10.0.0.1", dst_ip="192.168.1.1", length_bytes=10000, timestamp=t0))

    # Host 3 (192.168.1.2) transmits 5,000 bytes to Host 1 (10.0.0.1)
    store.record_observation(create_mock_obs(2, src_ip="192.168.1.2", dst_ip="10.0.0.1", length_bytes=5000, timestamp=t0))

    # Sort by total_bytes descending: Host 1 (15,000 total) is 1st
    top_total = store.get_top_hosts(sort_by="total_bytes", now=t0)["hosts"]
    assert top_total[0]["host_ip"] == "10.0.0.1"
    assert top_total[1]["host_ip"] == "192.168.1.1"
    assert top_total[2]["host_ip"] == "192.168.1.2"

    # Sort by tx_bytes descending: Host 1 (10,000 TX) is 1st, Host 3 (5,000 TX) is 2nd
    top_tx = store.get_top_hosts(sort_by="tx_bytes", now=t0)["hosts"]
    assert top_tx[0]["host_ip"] == "10.0.0.1"
    assert top_tx[1]["host_ip"] == "192.168.1.2"
    assert top_tx[2]["host_ip"] == "192.168.1.1"

    # Sort by rx_bytes descending: Host 2 (10,000 RX) is 1st, Host 1 (5,000 RX) is 2nd
    top_rx = store.get_top_hosts(sort_by="rx_bytes", now=t0)["hosts"]
    assert top_rx[0]["host_ip"] == "192.168.1.1"
    assert top_rx[1]["host_ip"] == "10.0.0.1"
    assert top_rx[2]["host_ip"] == "192.168.1.2"


def test_recent_packets_ring_buffer_bounded():
    """Verify recent packets ring buffer stays capped at configured limit and returns newest first."""
    limit = 5
    store = MetricsStore(recent_packets_limit=limit)

    for i in range(10):
        store.record_observation(create_mock_obs(i + 1, length_bytes=i * 10))

    recent = store.get_recent_packets(limit=10)
    assert len(recent) == limit
    # Newest first: packet IDs 10, 9, 8, 7, 6
    assert recent[0]["packet_id"] == 10
    assert recent[-1]["packet_id"] == 6


def test_reset_clears_session():
    """Verify reset() clears session totals, hosts, rolling histories, and packet buffer."""
    store = MetricsStore()
    t0 = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    store.record_observation(create_mock_obs(1, src_ip="10.0.0.1", dst_ip="10.0.0.2", length_bytes=500, timestamp=t0))
    assert store.get_summary(now=t0)["session"]["packets"] == 1
    assert len(store.get_top_hosts(now=t0)["hosts"]) == 2
    assert len(store.get_recent_packets()) == 1

    store.reset()

    assert store.get_summary(now=t0)["session"]["packets"] == 0
    assert store.get_summary(now=t0)["session"]["bytes"] == 0
    assert len(store.get_top_hosts(now=t0)["hosts"]) == 0
    assert len(store.get_recent_packets()) == 0


def test_concurrent_recording_thread_safety():
    """Verify that MetricsStore handles concurrent record_observation calls cleanly."""
    store = MetricsStore(recent_packets_limit=100)
    t0 = datetime.now(timezone.utc)

    def worker(i: int):
        obs = create_mock_obs(
            i,
            src_ip=f"10.0.0.{i % 10}",
            dst_ip="10.0.0.99",
            length_bytes=100,
            timestamp=t0
        )
        store.record_observation(obs)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(worker, range(200)))

    summary = store.get_summary(now=t0)
    assert summary["session"]["packets"] == 200
    assert summary["session"]["bytes"] == 200 * 100
    assert len(store.get_recent_packets(limit=100)) == 100
