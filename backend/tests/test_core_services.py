import pytest

from app.models.entities import AssetType, ChangeType, RiskLevel
from app.services.ai.threat_engine import ThreatScenarioEngine
from app.services.diff.engine import DiffEngine, SnapshotRecord
from app.services.risk.calculator import RiskCalculator
from app.services.scanners.base import DiscoveredAsset


def _snap(asset_type: AssetType, identifier: str, payload: dict | None = None, risk: float = 5.0) -> SnapshotRecord:
    from app.services.diff.engine import to_snapshot_record

    asset = DiscoveredAsset(
        asset_type=asset_type,
        identifier=identifier,
        payload=payload or {},
        risk_score=risk,
    )
    return to_snapshot_record(asset)


class TestDiffEngine:
    def test_detects_added_subdomain(self):
        engine = DiffEngine()
        current = [_snap(AssetType.SUBDOMAIN, "api.example.com")]
        diffs = engine.compare([], current)
        assert len(diffs) == 1
        assert diffs[0].change_type == ChangeType.ADDED
        assert "api.example.com" in diffs[0].summary

    def test_detects_removed_port(self):
        engine = DiffEngine()
        previous = [_snap(AssetType.PORT, "1.2.3.4:3306", {"port": 3306}, risk=8.0)]
        diffs = engine.compare(previous, [])
        assert len(diffs) == 1
        assert diffs[0].change_type == ChangeType.REMOVED

    def test_detects_ssl_expiry_change(self):
        engine = DiffEngine()
        previous = [_snap(AssetType.SSL_CERT, "example.com", {"host": "example.com", "days_until_expiry": 60})]
        current = [_snap(AssetType.SSL_CERT, "example.com", {"host": "example.com", "days_until_expiry": 15})]
        diffs = engine.compare(previous, current)
        assert len(diffs) == 1
        assert diffs[0].change_type == ChangeType.MODIFIED


class TestRiskCalculator:
    def test_empty_snapshots(self):
        calc = RiskCalculator()
        result = calc.assess([], [], None)
        assert result.total_score == 0.0

    def test_risk_increases_with_critical_port(self):
        calc = RiskCalculator()
        snapshots = [_snap(AssetType.PORT, "10.0.0.1:3306", {"port": 3306}, risk=9.0)]
        engine = DiffEngine()
        diffs = engine.compare([], snapshots)
        result = calc.assess(snapshots, diffs, previous_score=3.0)
        assert result.total_score > 3.0
        assert result.delta_percent is not None

    def test_critical_findings_from_high_risk_changes(self):
        calc = RiskCalculator()
        from app.services.diff.engine import DiffResult

        diffs = [
            DiffResult(
                change_type=ChangeType.ADDED,
                asset_type=AssetType.PORT,
                identifier="1.2.3.4:3306",
                previous_value=None,
                current_value={"port": 3306},
                risk_level=RiskLevel.CRITICAL,
                risk_score=9.5,
                summary="+ 1.2.3.4:3306 açık port",
            )
        ]
        result = calc.assess([_snap(AssetType.PORT, "1.2.3.4:3306", {"port": 3306}, 9.0)], diffs, None)
        assert len(result.critical_findings) >= 1


class TestThreatEngine:
    def test_mysql_port_generates_scenario(self):
        engine = ThreatScenarioEngine()
        snapshots = [_snap(AssetType.PORT, "203.0.113.1:3306", {"port": 3306, "host": "203.0.113.1"}, 8.0)]
        scenarios, actions = engine.analyze([], snapshots)
        assert any("MySQL" in s.title for s in scenarios)
        assert len(actions) >= 1

    def test_nuclei_vulnerability_generates_scenario(self):
        engine = ThreatScenarioEngine()
        snapshots = [
            _snap(
                AssetType.VULNERABILITY,
                "vuln:CVE-2024-0001:https://app.example.com",
                {
                    "template_id": "CVE-2024-0001",
                    "name": "Remote Code Execution",
                    "severity": "critical",
                    "host": "app.example.com",
                    "cve_ids": ["CVE-2024-0001"],
                    "source": "nuclei",
                },
                10.0,
            )
        ]
        scenarios, actions = engine.analyze([], snapshots)
        assert any("Nuclei" in s.title for s in scenarios)
        assert any(a.priority == "critical" for a in actions)

    def test_public_s3_generates_scenario(self):
        engine = ThreatScenarioEngine()
        from app.services.diff.engine import DiffResult

        diffs = [
            DiffResult(
                change_type=ChangeType.ADDED,
                asset_type=AssetType.CLOUD_RESOURCE,
                identifier="demo-bucket",
                previous_value=None,
                current_value={"public": True, "resource_type": "s3_bucket"},
                risk_level=RiskLevel.CRITICAL,
                risk_score=9.0,
                summary="+ Cloud: demo-bucket",
            )
        ]
        scenarios, actions = engine.analyze(diffs, [])
        assert any("Public Cloud" in s.title for s in scenarios)
        assert any(a.priority == "critical" for a in actions)
