import uuid

import structlog
from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.entities import Organization
from app.services.scan_orchestrator import ScanOrchestrator
from app.workers.async_runner import run_async
from app.workers.celery_app import celery_app

logger = structlog.get_logger(__name__)


@celery_app.task(name="app.workers.tasks.run_organization_scan", bind=True, max_retries=2)
def run_organization_scan(self, organization_id: str, scan_run_id: str | None = None) -> dict:
    org_uuid = uuid.UUID(organization_id)
    scan_uuid = uuid.UUID(scan_run_id) if scan_run_id else None
    orchestrator = ScanOrchestrator()

    async def _execute() -> dict:
        async with AsyncSessionLocal() as session:
            scan_run = await orchestrator.run_scan(session, org_uuid, scan_uuid)
            await session.commit()
            return {
                "scan_run_id": str(scan_run.id),
                "status": scan_run.status.value,
                "asset_count": scan_run.asset_count,
            }

    try:
        result = run_async(_execute())
        logger.info("celery_scan_complete", organization_id=organization_id, **result)
        return result
    except Exception as exc:
        if scan_uuid:
            async def _mark_failed() -> None:
                async with AsyncSessionLocal() as session:
                    from app.models.entities import ScanRun, ScanStatus
                    from datetime import datetime, timezone

                    scan = await session.get(ScanRun, scan_uuid)
                    if scan and scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(exc)
                        scan.completed_at = datetime.now(timezone.utc)
                        await session.commit()

            run_async(_mark_failed())
        logger.exception("celery_scan_failed", organization_id=organization_id)
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.workers.tasks.run_all_organization_scans")
def run_all_organization_scans() -> dict:
    async def _fetch_org_ids() -> list[str]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Organization).where(Organization.is_active.is_(True))
            )
            return [str(o.id) for o in result.scalars().all()]

    org_ids = run_async(_fetch_org_ids())

    for org_id in org_ids:
        run_organization_scan.delay(org_id)

    logger.info("scheduled_scans_enqueued", count=len(org_ids))
    return {"enqueued": len(org_ids)}
