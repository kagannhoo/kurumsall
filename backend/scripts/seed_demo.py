"""Seed demo organization and run initial scan."""

import asyncio
import uuid

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.entities import Organization
from app.services.domain.verification import DomainVerificationService
from app.services.organizations.helpers import set_cloud_accounts
from app.services.scan_orchestrator import ScanOrchestrator

CLOUD_DEMO = {
    "aws": {
        "resources": [
            {
                "type": "s3_bucket",
                "id": "demo-public-bucket",
                "name": "demo-public-bucket",
                "region": "eu-west-1",
                "public": True,
            },
            {
                "type": "rds_instance",
                "id": "prod-db-01",
                "name": "prod-db-01",
                "region": "eu-west-1",
                "public": False,
            },
        ],
    },
}


async def main() -> None:
    domain_service = DomainVerificationService()
    async with AsyncSessionLocal() as session:
        existing = await session.execute(select(Organization).where(Organization.slug == "demo-company"))
        org = existing.scalar_one_or_none()

        if org is None:
            org = Organization(
                id=uuid.uuid4(),
                name="Demo Şirket A.Ş.",
                slug="demo-company",
                root_domains=["example.com"],
            )
            set_cloud_accounts(org, CLOUD_DEMO)
            session.add(org)
            await session.flush()
            print(f"Created organization: {org.name} ({org.id})")
        else:
            print(f"Using existing organization: {org.name} ({org.id})")

        await domain_service.ensure_records(session, org)
        for domain in org.root_domains:
            await domain_service.mark_verified(session, org.id, domain)
            print(f"Domain verified (demo): {domain}")

        orchestrator = ScanOrchestrator()
        scan = await orchestrator.run_scan(session, org.id)
        await session.commit()
        print(f"Scan completed: {scan.asset_count} assets, status={scan.status.value}")


if __name__ == "__main__":
    asyncio.run(main())
