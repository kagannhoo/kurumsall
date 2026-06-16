"""Dashboard yardımcıları — kurumsal dil etiketleri."""

from app.models.entities import AssetType

ASSET_TYPE_LABELS: dict[AssetType, tuple[str, str]] = {
    AssetType.DOMAIN: ("Ana Domain", "Kayıtlı kök domain ve DNS kayıtları"),
    AssetType.SUBDOMAIN: ("Alt Domain", "Keşfedilen subdomain ve DNS yüzeyi"),
    AssetType.PORT: ("Açık Port / Servis", "İnternete açık TCP portları ve servisler"),
    AssetType.SSL_CERT: ("SSL / TLS Sertifikası", "Sertifika geçerliliği, süre ve cipher durumu"),
    AssetType.CLOUD_RESOURCE: ("Cloud Kaynağı", "AWS / Azure / GCP üzerindeki expose edilmiş kaynaklar"),
    AssetType.VULNERABILITY: ("Güvenlik Açığı", "CVE ve bilinen zafiyet eşleşmeleri"),
}

SCANNER_LABELS: dict[str, str] = {
    "dns": "DNS & Subdomain Keşfi (Subfinder, passive DNS)",
    "port": "Port Tarama (Naabu / TCP connect, top portlar)",
    "ssl": "SSL/TLS Denetimi (sertifika süresi, cipher grade)",
    "cloud": "Cloud Envanter (S3, RDS, public exposure)",
    "vulnerability": "Zafiyet Taraması (Nuclei CVE şablonları)",
}


def build_executive_summary(
    org_name: str,
    total_assets: int,
    previous_total: int | None,
    risk_score: float,
    risk_delta: float | None,
    critical_count: int,
    change_count: int,
) -> str:
    parts = [f"{org_name} internet yüzeyinde şu an {total_assets} izlenen sistem kaydı bulunuyor."]

    if previous_total is not None and previous_total != total_assets:
        diff = total_assets - previous_total
        direction = "genişledi" if diff > 0 else "daraldı"
        parts.append(f"Önceki taramaya göre envanter {abs(diff)} kayıt {direction}.")

    if risk_delta is not None:
        if risk_delta > 5:
            parts.append(f"Genel risk seviyesi %{abs(risk_delta):.0f} arttı — inceleme önerilir.")
        elif risk_delta < -5:
            parts.append(f"Genel risk seviyesi %{abs(risk_delta):.0f} azaldı.")
        else:
            parts.append(f"Risk skoru {risk_score:.1f}/10 seviyesinde stabil.")

    if critical_count > 0:
        parts.append(f"{critical_count} kritik/yüksek öncelikli bulgu tespit edildi.")
    elif change_count > 0:
        parts.append(f"Son taramada {change_count} yapısal değişiklik algılandı.")

    return " ".join(parts)
