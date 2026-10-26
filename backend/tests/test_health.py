def test_health_check(client):
    """Test that GET /api/health returns 200 with expected schema."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "network-traffic-analyzer"
