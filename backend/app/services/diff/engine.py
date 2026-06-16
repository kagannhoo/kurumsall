import hashlib
import json
from dataclasses import dataclass

from app.models.entities import AssetType, ChangeType, RiskLevel
from app.services.scanners.base import DiscoveredAsset


@dataclass
class SnapshotRecord:
    asset_type: AssetType
    identifier: str
    fingerprint: str
    payload: dict
    risk_score: float


@dataclass
class DiffResult:
    change_type: ChangeType
    asset_type: AssetType
    identifier: str
    previous_value: dict | None
    current_value: dict | None
    risk_level: RiskLevel
    risk_score: float
    summary: str


def fingerprint_asset(asset: DiscoveredAsset) -> str:
    canonical = {
        "type": asset.asset_type.value,
        "identifier": asset.identifier.lower(),
        "payload": asset.payload,
    }
    raw = json.dumps(canonical, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def to_snapshot_record(asset: DiscoveredAsset) -> SnapshotRecord:
    return SnapshotRecord(
        asset_type=asset.asset_type,
        identifier=asset.identifier.lower(),
        fingerprint=fingerprint_asset(asset),
        payload=asset.payload,
        risk_score=asset.risk_score,
    )


def score_to_level(score: float) -> RiskLevel:
    if score >= 9.0:
        return RiskLevel.CRITICAL
    if score >= 7.0:
        return RiskLevel.HIGH
    if score >= 4.0:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


class DiffEngine:
    def compare(
        self,
        previous: list[SnapshotRecord],
        current: list[SnapshotRecord],
    ) -> list[DiffResult]:
        prev_map = {r.identifier: r for r in previous}
        curr_map = {r.identifier: r for r in current}
        results: list[DiffResult] = []

        for identifier, curr in curr_map.items():
            prev = prev_map.get(identifier)
            if prev is None:
                results.append(self._build_added(curr))
            elif prev.fingerprint != curr.fingerprint:
                results.append(self._build_modified(prev, curr))

        for identifier, prev in prev_map.items():
            if identifier not in curr_map:
                results.append(self._build_removed(prev))

        return sorted(results, key=lambda r: r.risk_score, reverse=True)

    def _build_added(self, curr: SnapshotRecord) -> DiffResult:
        score = max(curr.risk_score, self._type_baseline(curr.asset_type))
        risk_level = score_to_level(score)
        summary = self._summarize(ChangeType.ADDED, curr)
        return DiffResult(
            change_type=ChangeType.ADDED,
            asset_type=curr.asset_type,
            identifier=curr.identifier,
            previous_value=None,
            current_value=curr.payload,
            risk_level=risk_level,
            risk_score=score,
            summary=summary,
        )

    def _build_removed(self, prev: SnapshotRecord) -> DiffResult:
        return DiffResult(
            change_type=ChangeType.REMOVED,
            asset_type=prev.asset_type,
            identifier=prev.identifier,
            previous_value=prev.payload,
            current_value=None,
            risk_level=RiskLevel.LOW,
            risk_score=1.0,
            summary=self._summarize(ChangeType.REMOVED, prev),
        )

    def _build_modified(self, prev: SnapshotRecord, curr: SnapshotRecord) -> DiffResult:
        risk_score = max(curr.risk_score, prev.risk_score)
        if curr.asset_type == AssetType.SSL_CERT:
            days = curr.payload.get("days_until_expiry")
            if days is not None and days <= 30:
                risk_score = max(risk_score, 8.0)
        return DiffResult(
            change_type=ChangeType.MODIFIED,
            asset_type=curr.asset_type,
            identifier=curr.identifier,
            previous_value=prev.payload,
            current_value=curr.payload,
            risk_level=self._score_to_level(risk_score),
            risk_score=risk_score,
            summary=self._summarize_modified(prev, curr),
        )

    @staticmethod
    def _score_to_level(score: float) -> RiskLevel:
        if score >= 9.0:
            return RiskLevel.CRITICAL
        if score >= 7.0:
            return RiskLevel.HIGH
        if score >= 4.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _type_baseline(asset_type: AssetType) -> float:
        return {
            AssetType.PORT: 5.0,
            AssetType.SUBDOMAIN: 4.0,
            AssetType.SSL_CERT: 3.0,
            AssetType.CLOUD_RESOURCE: 6.0,
            AssetType.VULNERABILITY: 8.0,
            AssetType.DOMAIN: 2.0,
        }.get(asset_type, 3.0)

    @staticmethod
    def _summarize(change_type: ChangeType, record: SnapshotRecord) -> str:
        prefix = {"added": "+", "removed": "-", "modified": "~"}[change_type.value]
        if record.asset_type == AssetType.SUBDOMAIN:
            return f"{prefix} {record.identifier}"
        if record.asset_type == AssetType.PORT:
            return f"{prefix} {record.identifier} açık port"
        if record.asset_type == AssetType.SSL_CERT:
            days = record.payload.get("days_until_expiry")
            if days is not None:
                return f"{prefix} SSL: {record.payload.get('host')} — {days} gün kaldı"
            return f"{prefix} SSL: {record.payload.get('host')}"
        if record.asset_type == AssetType.CLOUD_RESOURCE:
            return f"{prefix} Cloud: {record.identifier}"
        return f"{prefix} {record.identifier}"

    @staticmethod
    def _summarize_modified(prev: SnapshotRecord, curr: SnapshotRecord) -> str:
        if curr.asset_type == AssetType.SSL_CERT:
            prev_days = prev.payload.get("days_until_expiry")
            curr_days = curr.payload.get("days_until_expiry")
            return f"~ SSL {curr.payload.get('host')}: {prev_days} → {curr_days} gün"
        return f"~ {curr.identifier} değişti"
