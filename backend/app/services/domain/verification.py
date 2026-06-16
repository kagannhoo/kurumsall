import secrets
import uuid
from datetime import datetime, timezone

import dns.resolver
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.entities import DomainVerification, Organization

settings = get_settings()
TXT_PREFIX = "_asm-verify"


class DomainVerificationService:
    async def ensure_records(self, session: AsyncSession, org: Organization) -> list[DomainVerification]:
        existing = await session.execute(
            select(DomainVerification).where(DomainVerification.organization_id == org.id)
        )
        by_domain = {v.domain: v for v in existing.scalars()}
        records: list[DomainVerification] = []
        for domain in org.root_domains:
            domain = domain.lower().strip()
            if domain in by_domain:
                records.append(by_domain[domain])
                continue
            record = DomainVerification(
                organization_id=org.id,
                domain=domain,
                verification_token=f"asm-verify-{secrets.token_hex(16)}",
            )
            session.add(record)
            records.append(record)
        await session.flush()
        return records

    async def all_verified(self, session: AsyncSession, org_id: uuid.UUID) -> bool:
        if not settings.require_domain_verification:
            return True
        result = await session.execute(
            select(DomainVerification).where(DomainVerification.organization_id == org_id)
        )
        records = list(result.scalars())
        if not records:
            return False
        return all(r.verified_at is not None for r in records)

    async def unverified_domains(self, session: AsyncSession, org_id: uuid.UUID) -> list[str]:
        result = await session.execute(
            select(DomainVerification).where(
                DomainVerification.organization_id == org_id,
                DomainVerification.verified_at.is_(None),
            )
        )
        return [r.domain for r in result.scalars()]

    def txt_record_name(self, domain: str) -> str:
        return f"{TXT_PREFIX}.{domain}"

    def txt_record_value(self, token: str) -> str:
        return token

    async def verify_dns(self, session: AsyncSession, org_id: uuid.UUID, domain: str) -> DomainVerification:
        domain = domain.lower().strip()
        result = await session.execute(
            select(DomainVerification).where(
                DomainVerification.organization_id == org_id,
                DomainVerification.domain == domain,
            )
        )
        record = result.scalar_one_or_none()
        if not record:
            raise ValueError(f"Domain kaydı bulunamadı: {domain}")

        if record.verified_at:
            return record

        host = self.txt_record_name(domain)
        expected = self.txt_record_value(record.verification_token)
        try:
            answers = dns.resolver.resolve(host, "TXT")
            found = any(expected in b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            found = False
        except Exception:
            found = False

        if not found:
            raise ValueError(
                f"DNS TXT kaydı doğrulanamadı. {host} için '{expected}' değerini ekleyin."
            )

        record.verified_at = datetime.now(timezone.utc)
        await session.flush()
        return record

    async def mark_verified(self, session: AsyncSession, org_id: uuid.UUID, domain: str) -> DomainVerification:
        domain = domain.lower().strip()
        result = await session.execute(
            select(DomainVerification).where(
                DomainVerification.organization_id == org_id,
                DomainVerification.domain == domain,
            )
        )
        record = result.scalar_one_or_none()
        if not record:
            raise ValueError(f"Domain kaydı bulunamadı: {domain}")
        record.verified_at = datetime.now(timezone.utc)
        await session.flush()
        return record
