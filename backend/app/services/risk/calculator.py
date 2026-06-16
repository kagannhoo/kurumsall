from dataclasses import dataclass

from app.models.entities import AssetType, RiskLevel
from app.services.diff.engine import DiffResult, SnapshotRecord


@dataclass
class RiskBreakdown:
    total_score: float
    delta_percent: float | None
    by_type: dict[str, float]
    by_level: dict[str, int]
    critical_findings: list[str]


class RiskCalculator:
    WEIGHTS = {
        AssetType.VULNERABILITY: 1.5,
        AssetType.CLOUD_RESOURCE: 1.3,
        AssetType.PORT: 1.2,
        AssetType.SSL_CERT: 1.0,
        AssetType.SUBDOMAIN: 0.8,
        AssetType.DOMAIN: 0.5,
    }

    CRITICAL_PORTS = {3306, 5432, 6379, 27017, 9200, 8443}

    def assess(
        self,
        snapshots: list[SnapshotRecord],
        changes: list[DiffResult],
        previous_score: float | None = None,
    ) -> RiskBreakdown:
        if not snapshots:
            return RiskBreakdown(0.0, None, {}, {}, [])

        weighted_scores = [
            s.risk_score * self.WEIGHTS.get(s.asset_type, 1.0) for s in snapshots
        ]
        base_score = min(10.0, sum(weighted_scores) / max(len(snapshots), 1) * 2)

        change_boost = sum(c.risk_score * 0.15 for c in changes if c.change_type.value == "added")
        total_score = min(10.0, base_score + change_boost)

        by_type: dict[str, float] = {}
        by_level: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        for snap in snapshots:
            key = snap.asset_type.value
            by_type[key] = by_type.get(key, 0.0) + snap.risk_score
            level = self._score_to_level(snap.risk_score)
            by_level[level.value] += 1

        critical_findings = self._critical_findings(changes)

        delta = None
        if previous_score is not None and previous_score > 0:
            delta = round(((total_score - previous_score) / previous_score) * 100, 1)

        return RiskBreakdown(
            total_score=round(total_score, 2),
            delta_percent=delta,
            by_type={k: round(v, 2) for k, v in by_type.items()},
            by_level=by_level,
            critical_findings=critical_findings,
        )

    def _critical_findings(self, changes: list[DiffResult]) -> list[str]:
        findings: list[str] = []
        for change in changes:
            if change.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                findings.append(change.summary)
        return findings[:10]

    @staticmethod
    def _score_to_level(score: float) -> RiskLevel:
        if score >= 9.0:
            return RiskLevel.CRITICAL
        if score >= 7.0:
            return RiskLevel.HIGH
        if score >= 4.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
