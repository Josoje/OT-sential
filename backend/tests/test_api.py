import os
from uuid import uuid4

os.environ["OT_SENTINEL_DB"] = os.path.join(os.path.dirname(__file__), "testdata", f"api-{uuid4()}.db")

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_and_dashboard_are_data_backed():
    assert client.get("/api/health").json()["status"] == "ok"
    dashboard = client.get("/api/dashboard?hours=1").json()
    assert dashboard["metrics"]["total_events"] >= 7
    assert dashboard["metrics"]["assets"] >= 8
    assert len(dashboard["timeline"]) == 13
    assert dashboard["events"][0]["timestamp"].endswith("Z")


def test_event_investigation_status_and_notes():
    event = client.get("/api/events").json()["items"][0]
    response = client.patch(f"/api/events/{event['id']}/status", json={"status": "Under undersøgelse"})
    assert response.status_code == 200
    note = client.post(f"/api/events/{event['id']}/notes", json={"body": "Analytikernote"})
    assert note.status_code == 201
    assert client.get(f"/api/events/{event['id']}").json()["notes"][0]["body"] == "Analytikernote"


def test_simulation_and_import_preview():
    result = client.post("/api/simulation", json={"scenario": "correlated"})
    assert result.status_code == 200
    assert result.json()["created"] == 3
    sample = b'{"events":[{"timestamp":"2026-10-28T12:00:00Z","event_type":"auth_failure","source_asset":"demo-host","severity":"Middel"}]}'
    preview = client.post("/api/import/preview?filename=sample.json", content=sample)
    assert preview.status_code == 200
    assert preview.json()["valid"] == 1
    committed = client.post("/api/import/commit", json=preview.json()["records"])
    assert committed.status_code == 200
    assert committed.json()["created"] == 1


def test_csv_export_and_invalid_filters():
    assert client.get("/api/reports/events.csv").text.startswith("timestamp,severity")
    assert client.get("/api/events?sort=not-a-sort").status_code == 400
