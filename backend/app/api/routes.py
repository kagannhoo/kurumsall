import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import AuthUser, get_current_user, require_admin
from app.db.session import get_db
from app.models.entities import (
    AIInsight,
    AssetSnapshot,
    AssetType,
    Organization,
    RiskAssessment,
    RiskLevel,
    ScanRun,
    ScanStatus,
)
from app.schemas.api import (
    AIInsightResponse,
    AssetInventoryItem,
    ChangeEventResponse,
    DashboardSummary,
    DomainVerificationResponse,
    OrganizationCreate,
    OrganizationResponse,
    PerimeterInfo,
    ScanRunResponse,
    SystemStatusResponse,
    TimelinePoint,
    TimelineResponse,
)
from app.config import get_settings
from app.services.ai.analysis import AIAnalysisService
from app.services.dashboard.labels import (
    ASSET_TYPE_LABELS,
    SCANNER_LABELS,
    build_executive_summary,
)
from app.services.domain.verification import DomainVerificationService
from app.services.export.report import export_dashboard_csv, export_dashboard_pdf
from app.services.organizations.helpers import get_cloud_accounts, set_cloud_accounts
from app.services.scan_orchestrator import ScanOrchestrator

settings = get_settings()
ai_service = AIAnalysisService()
domain_service = DomainVerificationService()

router = APIRouter()


@router.get("/system/status", response_model=SystemStatusResponse)
async def system_status(_user: AuthUser = Depends(get_current_user)):
    ollama = await ai_service.check_ollama()
    return SystemStatusResponse(ollama=ollama, ai_enabled=settings.ai_enabled)


def _perimeter(org: Organization) -> PerimeterInfo:
    cloud = get_cloud_accounts(org) or {}
    cloud_providers = list(cloud.keys()) if cloud else []
    surface = ["Dış ağ portları", "DNS / subdomain yüzeyi", "SSL sertifikaları"]
    if cloud_providers:
        surface.append("Cloud altyapı kaynakları")
    return PerimeterInfo(
        root_domains=org.root_domains,
        cloud_providers=[p.upper() for p in cloud_providers],
        monitored_surface=surface,
    )


async def _asset_inventory(db: AsyncSession, scan_run_id: UUID) -> list[AssetInventoryItem]:
    stmt = (
        select(AssetSnapshot.asset_type, func.count())
        .where(AssetSnapshot.scan_run_id == scan_run_id)
        .group_by(AssetSnapshot.asset_type)
    )
    result = await db.execute(stmt)
    items: list[AssetInventoryItem] = []
    for asset_type, count in result.all():
        label, desc = ASSET_TYPE_LABELS.get(asset_type, (asset_type.value, ""))
        items.append(
            AssetInventoryItem(
                asset_type=asset_type.value,
                label=label,
                count=int(count),
                description=desc,
            )
        )
    return sorted(items, key=lambda i: i.count, reverse=True)


def _scan_coverage(scan: ScanRun | None) -> list[str]:
    if not scan or not scan.scan_metadata:
        return list(SCANNER_LABELS.values())
    scanners = scan.scan_metadata.get("scanners", [])
    return [SCANNER_LABELS.get(s, s) for s in scanners] or list(SCANNER_LABELS.values())


async def _build_dashboard(org: Organization, db: AsyncSession) -> DashboardSummary:
    scan_stmt = (
        select(ScanRun)
        .where(ScanRun.organization_id == org.id, ScanRun.status == ScanStatus.COMPLETED)
        .order_by(ScanRun.completed_at.desc())
        .limit(1)
        .options(
            selectinload(ScanRun.changes),
            selectinload(ScanRun.risk_assessments),
            selectinload(ScanRun.ai_insights),
        )
    )
    scan_result = await db.execute(scan_stmt)
    latest_scan = scan_result.scalar_one_or_none()
    perimeter = _perimeter(org)
    ollama_status = await ai_service.check_ollama()

    if not latest_scan:
        return DashboardSummary(
            organization_id=org.id,
            organization_name=org.name,
            latest_scan=None,
            total_assets=0,
            previous_total_assets=None,
            risk_score=0.0,
            previous_risk_score=None,
            risk_delta_percent=None,
            recent_changes=[],
            ai_insight=None,
            asset_inventory=[],
            risk_breakdown=None,
            critical_findings=[],
            perimeter=perimeter,
            scan_coverage=list(SCANNER_LABELS.values()),
            executive_summary=(
                f"{org.name} için izleme tanımlandı ancak henüz tam tarama yapılmadı. "
                f"Kapsam: {', '.join(perimeter.root_domains)}. "
                "İlk tarama sonrası port, domain, SSL ve cloud envanteri burada görünecek."
            ),
            ollama_status=ollama_status,
        )

    assessment = latest_scan.risk_assessments[0] if latest_scan.risk_assessments else None
    ai = latest_scan.ai_insights[0] if latest_scan.ai_insights else None
    changes = sorted(latest_scan.changes, key=lambda c: c.risk_score, reverse=True)[:20]
    breakdown = assessment.breakdown if assessment else None
    critical = (breakdown or {}).get("critical_findings", [])
    critical_count = len([c for c in changes if c.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)])

    inventory = await _asset_inventory(db, latest_scan.id)
    risk_score = assessment.risk_score if assessment else 0.0
    prev_total = assessment.previous_total_assets if assessment else None
    risk_delta = assessment.risk_delta_percent if assessment else None

    return DashboardSummary(
        organization_id=org.id,
        organization_name=org.name,
        latest_scan=ScanRunResponse.model_validate(latest_scan),
        total_assets=assessment.total_assets if assessment else latest_scan.asset_count,
        previous_total_assets=prev_total,
        risk_score=risk_score,
        previous_risk_score=assessment.previous_risk_score if assessment else None,
        risk_delta_percent=risk_delta,
        recent_changes=[ChangeEventResponse.model_validate(c) for c in changes],
        ai_insight=AIInsightResponse.model_validate(ai) if ai else None,
        asset_inventory=inventory,
        risk_breakdown=breakdown,
        critical_findings=critical,
        perimeter=perimeter,
        scan_coverage=_scan_coverage(latest_scan),
        executive_summary=build_executive_summary(
            org.name,
            assessment.total_assets if assessment else latest_scan.asset_count,
            prev_total,
            risk_score,
            risk_delta,
            critical_count,
            len(changes),
        ),
        ollama_status=ollama_status,
    )


@router.post("/organizations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
):
    existing = await db.execute(select(Organization).where(Organization.slug == payload.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Organization slug already exists")

    org = Organization(
        name=payload.name,
        slug=payload.slug,
        root_domains=[d.lower().strip() for d in payload.root_domains],
    )
    set_cloud_accounts(org, payload.cloud_accounts)
    db.add(org)
    await db.flush()
    await domain_service.ensure_records(db, org)
    await db.refresh(org)
    return OrganizationResponse.model_validate(org)


@router.get("/organizations", response_model=list[OrganizationResponse])
async def list_organizations(
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    result = await db.execute(select(Organization).order_by(Organization.created_at.desc()))
    return result.scalars().all()


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return OrganizationResponse.model_validate(org)


@router.get("/organizations/{org_id}/domains/verification", response_model=list[DomainVerificationResponse])
async def list_domain_verifications(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    records = await domain_service.ensure_records(db, org)
    return [
        DomainVerificationResponse(
            domain=r.domain,
            verified=r.verified_at is not None,
            verified_at=r.verified_at,
            txt_record_name=domain_service.txt_record_name(r.domain),
            txt_record_value=domain_service.txt_record_value(r.verification_token),
        )
        for r in records
    ]


@router.post("/organizations/{org_id}/domains/{domain}/verify", response_model=DomainVerificationResponse)
async def verify_domain(
    org_id: UUID,
    domain: str,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    try:
        record = await domain_service.verify_dns(db, org_id, domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DomainVerificationResponse(
        domain=record.domain,
        verified=True,
        verified_at=record.verified_at,
        txt_record_name=domain_service.txt_record_name(record.domain),
        txt_record_value=domain_service.txt_record_value(record.verification_token),
    )


@router.post("/organizations/{org_id}/domains/{domain}/mark-verified", response_model=DomainVerificationResponse)
async def mark_domain_verified(
    org_id: UUID,
    domain: str,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    try:
        record = await domain_service.mark_verified(db, org_id, domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DomainVerificationResponse(
        domain=record.domain,
        verified=True,
        verified_at=record.verified_at,
        txt_record_name=domain_service.txt_record_name(record.domain),
        txt_record_value=domain_service.txt_record_value(record.verification_token),
    )


@router.post("/organizations/{org_id}/scans", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(require_admin),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if not await domain_service.all_verified(db, org_id):
        unverified = await domain_service.unverified_domains(db, org_id)
        raise HTTPException(
            status_code=400,
            detail=f"Tarama için domain doğrulaması gerekli: {', '.join(unverified)}",
        )

    scan_run = ScanRun(organization_id=org_id, status=ScanStatus.PENDING)
    db.add(scan_run)
    await db.flush()
    await db.commit()

    from app.workers.tasks import run_organization_scan

    run_organization_scan.delay(str(org_id), str(scan_run.id))
    return {"message": "Scan queued", "organization_id": str(org_id), "scan_run_id": str(scan_run.id)}


@router.post("/organizations/{org_id}/scans/sync", response_model=ScanRunResponse)
async def trigger_scan_sync(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if not await domain_service.all_verified(db, org_id):
        unverified = await domain_service.unverified_domains(db, org_id)
        raise HTTPException(
            status_code=400,
            detail=f"Tarama için domain doğrulaması gerekli: {', '.join(unverified)}",
        )

    orchestrator = ScanOrchestrator()
    scan_run = await orchestrator.run_scan(db, org_id)
    await db.refresh(scan_run)
    return scan_run


@router.get("/organizations/{org_id}/scans", response_model=list[ScanRunResponse])
async def list_scans(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanRun)
        .where(ScanRun.organization_id == org_id)
        .order_by(ScanRun.started_at.desc().nulls_last())
        .limit(50)
    )
    return result.scalars().all()


@router.get("/organizations/{org_id}/scans/{scan_id}", response_model=ScanRunResponse)
async def get_scan(
    org_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    scan = await db.get(ScanRun, scan_id)
    if not scan or scan.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/organizations/{org_id}/scans/{scan_id}/events")
async def scan_events(
    org_id: UUID,
    scan_id: UUID,
    _user: AuthUser = Depends(get_current_user),
):
    from app.db.session import AsyncSessionLocal

    async def event_stream():
        while True:
            async with AsyncSessionLocal() as session:
                scan = await session.get(ScanRun, scan_id)
                if not scan or scan.organization_id != org_id:
                    payload = {"status": "not_found"}
                    yield f"data: {json.dumps(payload)}\n\n"
                    return
                payload = {
                    "id": str(scan.id),
                    "status": scan.status.value,
                    "asset_count": scan.asset_count,
                    "error_message": scan.error_message,
                }
                yield f"data: {json.dumps(payload)}\n\n"
                if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                    return
            await asyncio.sleep(2)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/organizations/{org_id}/dashboard", response_model=DashboardSummary)
async def get_dashboard(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return await _build_dashboard(org, db)


@router.get("/organizations/{org_id}/export/csv")
async def export_csv(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    dashboard = await _build_dashboard(org, db)
    content = export_dashboard_csv(dashboard)
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="asm-report-{org.slug}.csv"'},
    )


@router.get("/organizations/{org_id}/export/pdf")
async def export_pdf(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    dashboard = await _build_dashboard(org, db)
    content = export_dashboard_pdf(dashboard)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="asm-report-{org.slug}.pdf"'},
    )


@router.get("/organizations/{org_id}/timeline", response_model=TimelineResponse)
async def get_timeline(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    stmt = (
        select(ScanRun, RiskAssessment)
        .join(RiskAssessment, RiskAssessment.scan_run_id == ScanRun.id, isouter=True)
        .where(ScanRun.organization_id == org_id, ScanRun.status == ScanStatus.COMPLETED)
        .order_by(ScanRun.completed_at.asc())
        .limit(90)
    )
    result = await db.execute(stmt)
    points: list[TimelinePoint] = []
    for scan_run, assessment in result.all():
        if scan_run.completed_at:
            points.append(
                TimelinePoint(
                    date=scan_run.completed_at,
                    asset_count=assessment.total_assets if assessment else scan_run.asset_count,
                    risk_score=assessment.risk_score if assessment else 0.0,
                )
            )

    return TimelineResponse(organization_id=org_id, points=points)


@router.get("/organizations/{org_id}/changes", response_model=list[ChangeEventResponse])
async def get_changes(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(get_current_user),
):
    from app.models.entities import ChangeEvent

    stmt = (
        select(ChangeEvent)
        .join(ScanRun, ChangeEvent.scan_run_id == ScanRun.id)
        .where(ScanRun.organization_id == org_id)
        .order_by(ChangeEvent.detected_at.desc())
        .limit(100)
    )
    result = await db.execute(stmt)
    return result.scalars().all()
