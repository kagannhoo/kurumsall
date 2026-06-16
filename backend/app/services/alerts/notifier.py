import httpx
import structlog

from app.config import get_settings
from app.models.entities import RiskLevel
from app.services.diff.engine import DiffResult

logger = structlog.get_logger(__name__)
settings = get_settings()


class AlertService:
    async def notify_scan_complete(
        self,
        organization_name: str,
        asset_count: int,
        risk_score: float,
        risk_delta: float | None,
        changes: list[DiffResult],
    ) -> None:
        critical = [c for c in changes if c.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        if not critical and risk_delta is not None and risk_delta < 10:
            return

        message = self._format_message(organization_name, asset_count, risk_score, risk_delta, critical)
        await self._send_slack(message)
        logger.info("alert_sent", organization=organization_name, critical_count=len(critical))

    def _format_message(
        self,
        org: str,
        asset_count: int,
        risk_score: float,
        risk_delta: float | None,
        critical: list[DiffResult],
    ) -> str:
        lines = [
            f"*[{org}] Attack Surface Tarama Tamamlandı*",
            f"Toplam asset: {asset_count} | Risk skoru: {risk_score}/10",
        ]
        if risk_delta is not None:
            lines.append(f"Risk değişimi: {risk_delta:+.1f}%")
        if critical:
            lines.append("\n*Kritik/Yüksek Bulgular:*")
            for c in critical[:8]:
                lines.append(f"• {c.summary}")
        return "\n".join(lines)

    async def _send_slack(self, message: str) -> None:
        if not settings.alert_slack_webhook:
            logger.debug("slack_webhook_not_configured")
            return
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                await client.post(settings.alert_slack_webhook, json={"text": message})
        except Exception as exc:
            logger.error("slack_alert_failed", error=str(exc))
