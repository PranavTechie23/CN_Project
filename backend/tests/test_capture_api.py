from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.runtime import runtime
from app.schemas import InterfaceInfo


@pytest.fixture(autouse=True)
def cleanup_capture():
    """Ensure capture is stopped and reset before and after each test."""
    runtime.capture_manager.stop()
    yield
    runtime.capture_manager.stop()


def test_interfaces_endpoint(client: TestClient):
    """Test GET /api/interfaces and alias /api/capture/interfaces return valid interfaces."""
    response = client.get("/api/interfaces")
    assert response.status_code == 200
    data = response.json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)
    if data["interfaces"]:
        iface = data["interfaces"][0]
        assert "name" in iface
        assert "is_up" in iface
        assert "is_loopback" in iface
        assert "addresses" in iface

    # Verify alias endpoint /api/capture/interfaces returns the same
    alias_res = client.get("/api/capture/interfaces")
    assert alias_res.status_code == 200
    assert alias_res.json() == data


def test_initial_capture_status(client: TestClient):
    """Test that capture is stopped on application boot."""
    response = client.get("/api/capture/status")
    assert response.status_code == 200
    data = response.json()
    assert data["state"] == "stopped"
    assert data["interface"] is None
    assert data["packets_seen"] == 0


def test_capture_start_invalid_interface(client: TestClient):
    """Test starting capture on a non-existent interface returns 400 Bad Request."""
    response = client.post("/api/capture/start", json={"interface": "non_existent_iface_999"})
    assert response.status_code == 400
    data = response.json()
    assert "error" in data["detail"]
    assert data["detail"]["error"]["code"] == "INVALID_INTERFACE"


def test_capture_start_stop_lifecycle_with_mock_sniffer(client: TestClient):
    """Test starting and stopping capture lifecycle using a mock sniffer."""
    # Mock sniffer
    mock_sniffer = MagicMock()
    runtime.capture_manager.sniffer_factory = lambda iface, prn: mock_sniffer

    # Mock interface service validation
    original_validate = runtime.interface_service.validate_interface
    runtime.interface_service.validate_interface = lambda name: name == "test-eth0"

    try:
        # Start capture
        start_res = client.post("/api/capture/start", json={"interface": "test-eth0"})
        assert start_res.status_code == 200
        start_data = start_res.json()
        assert start_data["state"] == "running"
        assert start_data["interface"] == "test-eth0"
        mock_sniffer.start.assert_called_once()

        # Second start while running returns 409 Conflict
        conflict_res = client.post("/api/capture/start", json={"interface": "test-eth0"})
        assert conflict_res.status_code == 409
        conflict_data = conflict_res.json()
        assert conflict_data["detail"]["error"]["code"] == "CAPTURE_ALREADY_ACTIVE"

        # Stop capture
        stop_res = client.post("/api/capture/stop")
        assert stop_res.status_code == 200
        stop_data = stop_res.json()
        assert stop_data["state"] == "stopped"
        mock_sniffer.stop.assert_called_once()

        # Idempotent second stop
        stop_res2 = client.post("/api/capture/stop")
        assert stop_res2.status_code == 200
        assert stop_res2.json()["state"] == "stopped"

    finally:
        runtime.interface_service.validate_interface = original_validate
        runtime.capture_manager.sniffer_factory = runtime.capture_manager._default_sniffer_factory


def test_capture_permission_denied_handling(client: TestClient):
    """Test that permission errors during sniffer start return 403 Forbidden."""
    def permission_denied_factory(iface, prn):
        mock = MagicMock()
        mock.start.side_effect = PermissionError("Operation not permitted")
        return mock

    runtime.capture_manager.sniffer_factory = permission_denied_factory
    original_validate = runtime.interface_service.validate_interface
    runtime.interface_service.validate_interface = lambda name: True

    try:
        res = client.post("/api/capture/start", json={"interface": "eth0"})
        assert res.status_code == 403
        data = res.json()
        assert data["detail"]["error"]["code"] == "CAPTURE_PERMISSION_DENIED"

        # Status should now be error
        status_res = client.get("/api/capture/status")
        assert status_res.json()["state"] == "error"
    finally:
        runtime.interface_service.validate_interface = original_validate
        runtime.capture_manager.sniffer_factory = runtime.capture_manager._default_sniffer_factory
