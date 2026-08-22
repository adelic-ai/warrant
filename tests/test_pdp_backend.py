from warrant.pdp import PDP_BACKEND


def test_cedar_backend_is_active():
    # cedarpy ships a prebuilt wheel for this platform (verified during Phase 2) — if this
    # ever falls back to python-fallback, that's a real regression worth seeing in CI, not a
    # silently accepted substitution.
    assert PDP_BACKEND == "cedar"


def test_health_reports_backend(client):
    resp = client.get("/health")
    assert resp.json()["pdp_backend"] == "cedar"
