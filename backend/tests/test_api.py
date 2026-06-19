import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core import auth as auth_module
from app.main import app
from app.models.entities import Organization
from app.services.dashboard.labels import SCANNER_LABELS
from app.services.system.capabilities import (
    build_platform_info,
    build_scanner_modules,
    is_demo_organization,
)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    get_settings.cache_clear()
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_enabled", False)
    monkeypatch.setattr(auth_module.settings, "auth_enabled", False)
    yield TestClient(app)
    get_settings.cache_clear()


class TestHealthEndpoints:
    def test_health_json(self, client):
        res = client.get("/health", headers={"Accept": "application/json"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["service"] == "KurSal"

    def test_health_html(self, client):
        res = client.get("/health", headers={"Accept": "text/html"})
        assert res.status_code == 200
        assert "Sistem çalışıyor" in res.text

    def test_root(self, client):
        res = client.get("/")
        assert res.status_code == 200
        assert res.json()["service"] == "KurSal"


class TestSystemInfo:
    def test_system_info(self, client):
        res = client.get("/api/v1/system/info")
        assert res.status_code == 200
        data = res.json()
        assert data["app_name"] == "KurSal"
        assert "capabilities" in data
        assert "roadmap" in data
        assert data["scanner_modes"]["cloud"] == "configured_inventory"


class TestCapabilities:
    def test_demo_org_detection(self):
        org = Organization(name="Demo", slug="demo-company", root_domains=["example.com"])
        assert is_demo_organization(org) is True

    def test_real_org_not_demo(self):
        org = Organization(name="Acme", slug="acme", root_domains=["acme.com"])
        assert is_demo_organization(org) is False

    def test_scanner_modules_from_metadata(self):
        metadata = {
            "scanner_results": {
                "dns": {"status": "ok", "count": 5},
                "port": {"status": "ok", "count": 8},
                "ssl": {"status": "ok", "count": 2},
                "cloud": {"status": "ok", "count": 1},
            }
        }
        modules = build_scanner_modules(metadata)
        assert len(modules) == len(SCANNER_LABELS)
        assert modules[0]["status"] == "ok"
        assert modules[3]["mode"] == "configured_inventory"

    def test_platform_info_has_demo_notice_for_demo_org(self):
        org = Organization(name="Demo", slug="demo-company", root_domains=["example.com"])
        info = build_platform_info(org)
        assert info["deployment_mode"] == "demo"
        assert info["demo_notice"] is not None
