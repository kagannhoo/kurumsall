"""Platform yetenekleri ve deployment modu bilgisi."""

from __future__ import annotations

from app.config import Settings, get_settings
from app.models.entities import Organization
from app.services.dashboard.labels import SCANNER_LABELS

DEMO_ORG_SLUGS = {"demo-company"}
DEMO_DOMAINS = {"example.com", "example.org", "example.net"}

SCANNER_NOTES: dict[str, str] = {
    "dns": "Yerleşik: yaygın subdomain brute-force. Subfinder açıksa pasif keşif eklenir.",
    "port": "Yerleşik: TCP connect taraması. Naabu açıksa top-100 port modu kullanılır.",
    "ssl": "Canlı TLS handshake ile sertifika süresi ve SAN analizi.",
    "cloud": "Şu an yapılandırılmış envanter modu — AWS/Azure API entegrasyonu yol haritasında.",
    "vulnerability": "Nuclei CVE şablonları. Kurulu değilse veya kapalıysa modül atlanır.",
}


def is_demo_organization(org: Organization) -> bool:
    settings = get_settings()
    if org.slug in DEMO_ORG_SLUGS:
        return True
    if settings.demo_mode and all(d in DEMO_DOMAINS for d in org.root_domains):
        return True
    return False


def deployment_mode(org: Organization | None = None) -> str:
    settings = get_settings()
    if org and is_demo_organization(org):
        return "demo"
    if settings.demo_mode:
        return "demo-capable"
    return "production"


def build_scanner_modules(scan_metadata: dict | None, settings: Settings | None = None) -> list[dict]:
    settings = settings or get_settings()
    results = (scan_metadata or {}).get("scanner_results", {})
    modules: list[dict] = []

    for key, label in SCANNER_LABELS.items():
        result = results.get(key, {})
        status = result.get("status", "pending")
        mode = "external" if settings.scanner_use_external_tools and key in ("dns", "port", "vulnerability") else "builtin"
        if key == "cloud":
            mode = "configured_inventory"
        if key == "vulnerability" and not settings.scanner_use_external_tools:
            mode = "disabled"

        modules.append(
            {
                "module": key,
                "label": label,
                "status": status,
                "asset_count": int(result.get("count", 0)),
                "mode": mode,
                "note": SCANNER_NOTES.get(key, ""),
                "error": result.get("error"),
            }
        )
    return modules


def build_platform_info(org: Organization | None = None) -> dict:
    settings = get_settings()
    return {
        "app_name": settings.app_name,
        "version": settings.app_version,
        "deployment_mode": deployment_mode(org),
        "demo_mode_enabled": settings.demo_mode,
        "capabilities": {
            "auth": settings.auth_enabled,
            "domain_verification": settings.require_domain_verification,
            "ai_analysis": settings.ai_enabled,
            "external_scanners": settings.scanner_use_external_tools,
            "pdf_export": True,
            "csv_export": True,
            "prometheus_metrics": True,
            "slack_alerts": bool(settings.alert_slack_webhook),
        },
        "scanner_modes": {
            "dns": "subfinder" if settings.scanner_use_external_tools else "builtin_brute",
            "port": "naabu" if settings.scanner_use_external_tools else "tcp_connect",
            "ssl": "live_tls",
            "cloud": "configured_inventory",
            "vulnerability": "nuclei" if settings.scanner_use_external_tools else "disabled",
        },
        "roadmap": [
            "AWS / Azure / GCP canlı API entegrasyonu",
            "Shodan / Certificate Transparency pasif keşif",
            "Multi-tenant RBAC",
        ],
        "demo_notice": (
            "Demo organizasyonu (example.com) eğitim amaçlıdır. "
            "Cloud kaynakları yapılandırılmış envanterden gelir; gerçek API taraması değildir. "
            "Production kullanım için kendi domain'inizi doğrulayın."
            if org is None or is_demo_organization(org)
            else None
        ),
    }
