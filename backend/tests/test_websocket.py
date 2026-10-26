from fastapi.testclient import TestClient

from app.main import app


def test_websocket_initial_snapshot(client: TestClient):
    """Test connecting to /ws/live and receiving the initial snapshot."""
    with client.websocket_connect("/ws/live") as websocket:
        data = websocket.receive_json()

        assert data["type"] == "snapshot"
        assert "timestamp" in data
        assert "capture" in data
        assert data["capture"]["state"] == "stopped"

        assert "metrics" in data
        assert data["metrics"]["window_seconds"] == 60
        assert "session_packets" in data["metrics"]
        assert "bytes_per_second" in data["metrics"]

        assert "protocols" in data
        assert len(data["protocols"]) == 7

        assert "top_hosts" in data
        assert isinstance(data["top_hosts"], list)

        assert "recent_packets" in data
        assert isinstance(data["recent_packets"], list)

        assert "recent_alerts" in data
        assert isinstance(data["recent_alerts"], list)
