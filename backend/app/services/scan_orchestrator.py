import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.metrics import SCAN_DURATION, SCAN_TOTAL
from app.models.entities import (
    AIInsight,
    Asset,
    AssetSnapshot,
    AssetType,
    ChangeEvent,
    Organization,
    RiskAssessment,
    RiskLevel,
    ScanRun,
    ScanStatus,
)
from app.services.ai.analysis import AIAnalysisService
from app.services.alerts.notifier import AlertService
from app.services.diff.engine import DiffEngine, SnapshotRecord, score_to_level, to_snapshot_record
from app.services.domain.verification import DomainVerificationService
from app.services.organizations.helpers import get_cloud_accounts
from app.services.risk.calculator import RiskCalculator
from app.services.scanners.base import ScanContext
from app.services.scanners.collectors import CloudScanner, DNSScanner, NucleiScanner, PortScanner, SSLScanner

logger = structlog.get_logger(__name__)


class ScanOrchestrator:
    def __init__(self) -> None:
        self.scanners = [DNSScanner(), PortScanner(), SSLScanner(), CloudScanner(), NucleiScanner()]
        self.diff_engine = DiffEngine()
        self.risk_calculator = RiskCalculator()
        self.ai_service = AIAnalysisService()
        self.alert_service = AlertService()
        self.domain_service = DomainVerificationService()

    async def run_scan(
        self, session: AsyncSession, organization_id: uuid.UUID, scan_run_id: uuid.UUID | None = None
    ) -> ScanRun:
        org = await session.get(Organization, organization_id)
        if not org:
            raise ValueError(f"Organization not found: {organization_id}")

        if not await self.domain_service.all_verified(session, organization_id):
            unverified = await self.domain_service.unverified_domains(session, organization_id)
            raise ValueError(f"Doğrulanmamış domainler: {', '.join(unverified)}")

        if scan_run_id:
            scan_run = await session.get(ScanRun, scan_run_id)
            if not scan_run or scan_run.organization_id != organization_id:
                raise ValueError(f"Scan run not found: {scan_run_id}")
            scan_run.status = ScanStatus.RUNNING
            scan_run.started_at = datetime.now(timezone.utc)
        else:
            scan_run = ScanRun(
                organization_id=organization_id,
                status=ScanStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
            session.add(scan_run)
        await session.flush()

        scan_start = datetime.now(timezone.utc)
        scanner_results: dict[str, dict] = {}

        try:
            context = ScanContext(
                organization_id=str(organization_id),
                root_domains=org.root_domains,
                cloud_accounts=get_cloud_accounts(org),
            )

            discovered = []
            for scanner in self.scanners:
                try:
                    results = await scanner.scan(context)
                    discovered.extend(results)
                    scanner_results[scanner.kind.value] = {"status": "ok", "count": len(results)}
                    logger.info("scanner_complete", kind=scanner.kind.value, count=len(results))
                except Exception as exc:
                    scanner_results[scanner.kind.value] = {"status": "failed", "error": str(exc)}
                    logger.exception("scanner_failed", kind=scanner.kind.value)

            if not discovered and all(r.get("status") == "failed" for r in scanner_results.values()):
                raise RuntimeError("Tüm tarayıcı modülleri başarısız oldu")

            current_records = [to_snapshot_record(a) for a in discovered]
            previous_records = await self._load_previous_snapshots(session, organization_id)

            await self._persist_assets_and_snapshots(session, org, scan_run, discovered, current_records)

            diffs = self.diff_engine.compare(previous_records, current_records)
            await self._persist_changes(session, scan_run, diffs)

            prev_assessment = await self._latest_assessment(session, organization_id)
            previous_score = prev_assessment.risk_score if prev_assessment else None
            previous_total = prev_assessment.total_assets if prev_assessment else None

            risk = self.risk_calculator.assess(current_records, diffs, previous_score)
            assessment = RiskAssessment(
                scan_run_id=scan_run.id,
                total_assets=len(current_records),
                previous_total_assets=previous_total,
                risk_score=risk.total_score,
                previous_risk_score=previous_score,
                risk_delta_percent=risk.delta_percent,
                breakdown={
                    "by_type": risk.by_type,
                    "by_level": risk.by_level,
                    "critical_findings": risk.critical_findings,
                },
            )
            session.add(assessment)

            ai_result = await self.ai_service.generate_insight(
                org.name,
                len(current_records),
                previous_total,
                risk,
                diffs,
                snapshots=current_records,
            )
            if ai_result:
                session.add(
                    AIInsight(
                        scan_run_id=scan_run.id,
                        summary=ai_result["summary"],
                        risk_commentary=ai_result["risk_commentary"],
                        recommendations=ai_result["recommendations"],
                        attack_scenarios=ai_result.get("attack_scenarios", []),
                        action_items=ai_result.get("action_items", []),
                        ollama_connected=ai_result.get("ollama_connected", False),
                        model_name=ai_result["model_name"],
                    )
                )

            scan_run.status = ScanStatus.COMPLETED
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.asset_count = len(current_records)
            scan_run.scan_metadata = {
                "scanners": [s.kind.value for s in self.scanners],
                "scanner_results": scanner_results,
                "changes_detected": len(diffs),
            }

            await session.flush()
            await self.alert_service.notify_scan_complete(
                org.name,
                len(current_records),
                risk.total_score,
                risk.delta_percent,
                diffs,
            )

            duration = (datetime.now(timezone.utc) - scan_start).total_seconds()
            SCAN_TOTAL.labels("completed").inc()
            SCAN_DURATION.observe(duration)

            logger.info(
                "scan_complete",
                organization=org.slug,
                assets=len(current_records),
                changes=len(diffs),
                risk=risk.total_score,
            )
            return scan_run

        except Exception as exc:
            scan_run.status = ScanStatus.FAILED
            scan_run.error_message = str(exc)
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.scan_metadata = {"scanner_results": scanner_results}
            SCAN_TOTAL.labels("failed").inc()
            logger.exception("scan_failed", organization_id=str(organization_id))
            raise

    async def _load_previous_snapshots(
        self, session: AsyncSession, organization_id: uuid.UUID
    ) -> list[SnapshotRecord]:
        stmt = (
            select(ScanRun)
            .where(
                ScanRun.organization_id == organization_id,
                ScanRun.status == ScanStatus.COMPLETED,
            )
            .order_by(ScanRun.completed_at.desc())
            .limit(1)
            .options(selectinload(ScanRun.snapshots))
        )
        result = await session.execute(stmt)
        prev_run = result.scalar_one_or_none()
        if not prev_run:
            return []

        return [
            SnapshotRecord(
                asset_type=s.asset_type,
                identifier=s.identifier,
                fingerprint=s.fingerprint,
                payload=s.payload,
                risk_score=s.risk_score,
            )
            for s in prev_run.snapshots
        ]

    async def _persist_assets_and_snapshots(
        self,
        session: AsyncSession,
        org: Organization,
        scan_run: ScanRun,
        discovered: list,
        records: list[SnapshotRecord],
    ) -> None:
        asset_map: dict[tuple[AssetType, str], Asset] = {}

        stmt = select(Asset).where(Asset.organization_id == org.id)
        existing = await session.execute(stmt)
        for asset in existing.scalars():
            asset_map[(asset.asset_type, asset.identifier)] = asset

        now = datetime.now(timezone.utc)
        for disc, record in zip(discovered, records, strict=True):
            key = (disc.asset_type, record.identifier)
            asset = asset_map.get(key)
            if asset is None:
                asset = Asset(
                    organization_id=org.id,
                    asset_type=disc.asset_type,
                    identifier=record.identifier,
                    display_name=disc.display_name,
                    metadata_=disc.payload,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                session.add(asset)
                await session.flush()
                asset_map[key] = asset
            else:
                asset.last_seen_at = now
                asset.metadata_ = disc.payload
                asset.is_active = True

            session.add(
                AssetSnapshot(
                    scan_run_id=scan_run.id,
                    asset_id=asset.id,
                    asset_type=record.asset_type,
                    identifier=record.identifier,
                    fingerprint=record.fingerprint,
                    payload=record.payload,
                    risk_score=record.risk_score,
                    risk_level=score_to_level(record.risk_score),
                )
            )

    async def _persist_changes(self, session: AsyncSession, scan_run: ScanRun, diffs: list) -> None:
        for diff in diffs:
            session.add(
                ChangeEvent(
                    scan_run_id=scan_run.id,
                    change_type=diff.change_type,
                    asset_type=diff.asset_type,
                    identifier=diff.identifier,
                    previous_value=diff.previous_value,
                    current_value=diff.current_value,
                    risk_level=diff.risk_level,
                    risk_score=diff.risk_score,
                    summary=diff.summary,
                )
            )

    async def _latest_assessment(
        self, session: AsyncSession, organization_id: uuid.UUID
    ) -> RiskAssessment | None:
        stmt = (
            select(RiskAssessment)
            .join(ScanRun, RiskAssessment.scan_run_id == ScanRun.id)
            .where(
                ScanRun.organization_id == organization_id,
                ScanRun.status == ScanStatus.COMPLETED,
            )
            .order_by(RiskAssessment.assessed_at.desc())
            .limit(1)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
