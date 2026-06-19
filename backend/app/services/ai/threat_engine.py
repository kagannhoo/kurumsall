"""Kural tabanlı saldırı senaryoları ve aksiyon planı — Ollama olmadan da çalışır."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.entities import AssetType, ChangeType, RiskLevel
from app.services.diff.engine import DiffResult, SnapshotRecord


@dataclass
class AttackScenario:
    id: str
    title: str
    severity: str
    attack_chain: list[str]
    business_impact: str
    related_findings: list[str]
    mitre_tactics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "attack_chain": self.attack_chain,
            "business_impact": self.business_impact,
            "related_findings": self.related_findings,
            "mitre_tactics": self.mitre_tactics,
        }


@dataclass
class ActionItem:
    priority: str
    title: str
    description: str
    owner: str
    timeframe: str
    related_scenario_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "priority": self.priority,
            "title": self.title,
            "description": self.description,
            "owner": self.owner,
            "timeframe": self.timeframe,
            "related_scenario_id": self.related_scenario_id,
        }


PORT_RULES: dict[int, dict] = {
    3306: {
        "title": "MySQL Veritabanı Sızıntısı",
        "severity": "critical",
        "tactics": ["Keşif", "Initial Access", "Collection"],
        "chain": [
            "Saldırgan internetten 3306 portunu tarar",
            "Zayıf parola veya bilinen CVE ile MySQL'e bağlanır",
            "Müşteri/operasyon veritabanı dump alınır veya ransomware için hazırlık yapılır",
        ],
        "impact": "Kişisel veri sızıntısı (KVKK), operasyonel durma, itibar kaybı",
        "actions": [
            ("3306 portunu sadece VPN/bastion IP'lerine kısıtla", "Altyapı", "4 saat"),
            ("Veritabanı audit log ve anomali izlemeyi aç", "Güvenlik", "1 gün"),
        ],
    },
    5432: {
        "title": "PostgreSQL Doğrudan Erişim",
        "severity": "critical",
        "tactics": ["Keşif", "Initial Access", "Exfiltration"],
        "chain": [
            "PostgreSQL portu internete açık tespit edilir",
            "Default credential veya misconfiguration exploit edilir",
            "Tablo dump veya lateral movement başlatılır",
        ],
        "impact": "Kurumsal veri sızıntısı, compliance ihlali",
        "actions": [
            ("Security group / firewall ile 5432'yi internal-only yap", "Altyapı", "4 saat"),
            ("pg_hba.conf ve SSL zorunluluğunu doğrula", "DBA", "1 gün"),
        ],
    },
    6379: {
        "title": "Redis Cache Ele Geçirme",
        "severity": "critical",
        "tactics": ["Keşif", "Initial Access", "Impact"],
        "chain": [
            "Redis auth olmadan veya zayıf auth ile erişilir",
            "CONFIG SET ile webshell / cron enjeksiyonu (eski sürümler)",
            "Session token ve cache verisi okunur",
        ],
        "impact": "Oturum hijacking, cache poisoning, servis kesintisi",
        "actions": [
            ("Redis'i auth + bind 127.0.0.1 / private subnet ile koru", "Altyapı", "2 saat"),
            ("requirepass ve ACL politikalarını uygula", "DevOps", "4 saat"),
        ],
    },
    3389: {
        "title": "RDP Brute Force / Ransomware Girişi",
        "severity": "critical",
        "tactics": ["Keşif", "Initial Access", "Impact"],
        "chain": [
            "RDP portu internetten taranır",
            "Credential stuffing veya brute force",
            "Ransomware operatörü domain join sunucuya sıçrar",
        ],
        "impact": "Tam sistem ele geçirme, fidye yazılımı, iş durması",
        "actions": [
            ("RDP'yi VPN arkasına al, NLA zorunlu kıl", "Altyapı", "1 gün"),
            ("MFA ve IP allowlist uygula", "Güvenlik", "1 gün"),
        ],
    },
    8443: {
        "title": "Alternatif HTTPS Yönetim Yüzeyi",
        "severity": "high",
        "tactics": ["Keşif", "Initial Access"],
        "chain": [
            "Standart dışı 8443 portunda admin/API servisi keşfedilir",
            "Zayıf TLS veya default admin paneli hedeflenir",
            "API key veya admin hesabı ele geçirilir",
        ],
        "impact": "Yetkisiz yönetim erişimi, API abuse",
        "actions": [
            ("8443'ün iş gereksinimini doğrula; gereksizse kapat", "Altyapı", "4 saat"),
            ("WAF / rate limit / mTLS değerlendir", "Güvenlik", "2 gün"),
        ],
    },
    22: {
        "title": "SSH Brute Force",
        "severity": "high",
        "tactics": ["Keşif", "Credential Access"],
        "chain": ["SSH servisi keşfedilir", "Otomatik brute force botnet", "Shell erişimi"],
        "impact": "Sunucu ele geçirme, pivot noktası",
        "actions": [
            ("SSH key-only auth, fail2ban / CrowdSec", "Altyapı", "4 saat"),
            ("Portu bastion/VPN arkasına taşı", "Altyapı", "1 gün"),
        ],
    },
}


class ThreatScenarioEngine:
    def analyze(
        self,
        changes: list[DiffResult],
        snapshots: list[SnapshotRecord],
    ) -> tuple[list[AttackScenario], list[ActionItem]]:
        scenarios: list[AttackScenario] = []
        actions: list[ActionItem] = []
        seen_ids: set[str] = set()

        for change in changes:
            self._from_change(change, scenarios, actions, seen_ids)

        for snap in snapshots:
            self._from_snapshot(snap, scenarios, actions, seen_ids)

        scenarios.sort(key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s.severity, 4))
        actions.sort(key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.priority, 4))
        return scenarios[:8], actions[:12]

    def _from_change(
        self,
        change: DiffResult,
        scenarios: list[AttackScenario],
        actions: list[ActionItem],
        seen: set[str],
    ) -> None:
        if change.asset_type == AssetType.PORT and change.change_type == ChangeType.ADDED:
            port = change.current_value.get("port") if change.current_value else None
            if port and int(port) in PORT_RULES:
                self._add_port_rule(int(port), change.summary, scenarios, actions, seen)

        if change.asset_type == AssetType.SSL_CERT:
            days = (change.current_value or {}).get("days_until_expiry")
            if days is not None and int(days) <= 30:
                sid = "ssl-expiry"
                if sid not in seen:
                    seen.add(sid)
                    scenarios.append(
                        AttackScenario(
                            id=sid,
                            title="Sertifika Süresi Dolması — MITM ve Kesinti",
                            severity="high" if int(days) > 7 else "critical",
                            attack_chain=[
                                "Geçersiz/expired sertifika ile TLS uyarıları kullanıcıyı alıştırır",
                                "Aynı domain için sahte sertifika ile MITM (captive portal senaryosu)",
                                "Servis kesintisi — müşteri güven kaybı",
                            ],
                            business_impact="Web/API erişim kesintisi, müşteri güven kaybı, compliance",
                            related_findings=[change.summary],
                            mitre_tactics=["Impact", "Defense Evasion"],
                        )
                    )
                    actions.append(
                        ActionItem(
                            priority="high",
                            title="SSL sertifikasını yenile ve otomatik renewal kur",
                            description=f"{change.summary} — Let's Encrypt veya kurumsal CA ile 30 gün kuralı.",
                            owner="DevOps",
                            timeframe="24 saat",
                            related_scenario_id=sid,
                        )
                    )

        if change.asset_type == AssetType.CLOUD_RESOURCE and change.change_type == ChangeType.ADDED:
            payload = change.current_value or {}
            if payload.get("public"):
                sid = "cloud-public-exposure"
                if sid not in seen:
                    seen.add(sid)
                    rtype = payload.get("resource_type", "kaynak")
                    scenarios.append(
                        AttackScenario(
                            id=sid,
                            title="Public Cloud Kaynağı — Veri Sızıntısı",
                            severity="critical",
                            attack_chain=[
                                f"Internetten {rtype} listelenir (bucket enumeration)",
                                "Read/write izni varsa veri indirilir veya ransomware",
                                "Compliance ihlali ve medya/regülatör bildirimi",
                            ],
                            business_impact="Toplu veri sızıntısı, KVKK/GDPR, ceza riski",
                            related_findings=[change.summary],
                            mitre_tactics=["Collection", "Exfiltration"],
                        )
                    )
                    actions.append(
                        ActionItem(
                            priority="critical",
                            title="Public erişimi kapat ve bucket policy audit",
                            description="Block Public Access, least privilege IAM, versioning + logging aç.",
                            owner="Cloud / Güvenlik",
                            timeframe="4 saat",
                            related_scenario_id=sid,
                        )
                    )

        if change.asset_type == AssetType.SUBDOMAIN and change.change_type == ChangeType.ADDED:
            host = change.identifier
            if host.startswith("api.") or "api" in host.split(".")[0]:
                sid = f"subdomain-api-{host}"
                if sid not in seen:
                    seen.add(sid)
                    scenarios.append(
                        AttackScenario(
                            id=sid,
                            title="Yeni API Yüzeyi — Genişleyen Saldırı Alanı",
                            severity="medium",
                            attack_chain=[
                                f"{host} keşfedilir (OSINT / cert transparency)",
                                "API endpoint enumeration, auth bypass testleri",
                                "IDOR, rate limit aşımı, veri sızıntısı",
                            ],
                            business_impact="API abuse, veri sızıntısı, servis kötüye kullanımı",
                            related_findings=[change.summary],
                            mitre_tactics=["Reconnaissance", "Initial Access"],
                        )
                    )
                    actions.append(
                        ActionItem(
                            priority="medium",
                            title="Yeni API subdomain güvenlik review",
                            description="Auth, rate limit, WAF, API gateway ve penetration test planla.",
                            owner="Uygulama Güvenliği",
                            timeframe="3 gün",
                            related_scenario_id=sid,
                        )
                    )

        if change.asset_type == AssetType.VULNERABILITY and change.change_type == ChangeType.ADDED:
            self._from_vulnerability(change.current_value or {}, change.summary, scenarios, actions, seen)

    def _from_snapshot(
        self,
        snap: SnapshotRecord,
        scenarios: list[AttackScenario],
        actions: list[ActionItem],
        seen: set[str],
    ) -> None:
        if snap.asset_type == AssetType.PORT:
            port = snap.payload.get("port")
            if port and int(port) in PORT_RULES:
                self._add_port_rule(int(port), snap.identifier, scenarios, actions, seen)

        if snap.asset_type == AssetType.VULNERABILITY:
            self._from_vulnerability(snap.payload, snap.identifier, scenarios, actions, seen)

    def _from_vulnerability(
        self,
        payload: dict,
        finding: str,
        scenarios: list[AttackScenario],
        actions: list[ActionItem],
        seen: set[str],
    ) -> None:
        template_id = payload.get("template_id") or "unknown"
        sid = f"nuclei-{template_id}"
        if sid in seen:
            return
        seen.add(sid)

        name = payload.get("name") or template_id
        severity = str(payload.get("severity") or "medium").lower()
        host = payload.get("host") or payload.get("matched_at") or "hedef"
        cve_ids = payload.get("cve_ids") or []
        cve_label = ", ".join(cve_ids[:3]) if cve_ids else "bilinen CVE"

        scenario_severity = severity if severity in ("critical", "high", "medium") else "high"
        scenarios.append(
            AttackScenario(
                id=sid,
                title=f"Nuclei Zafiyeti — {name}",
                severity=scenario_severity,
                attack_chain=[
                    f"Nuclei şablonu ({template_id}) {host} üzerinde eşleşti",
                    f"Saldırgan {cve_label} exploit zincirini otomatik tarayıcılarla dener",
                    "Başarılı exploit → servis ele geçirme veya veri sızıntısı",
                ],
                business_impact="Bilinen CVE exploit'i — patch gecikmesi compliance ve operasyonel risk",
                related_findings=[finding],
                mitre_tactics=["Initial Access", "Exploitation"],
            )
        )
        actions.append(
            ActionItem(
                priority=scenario_severity,
                title=f"{name} — patch / mitigasyon uygula",
                description=f"{finding}. Nuclei eşleşmesi doğrulanmalı, vendor advisory takip edilmeli.",
                owner="Uygulama Güvenliği",
                timeframe="24 saat" if scenario_severity == "critical" else "3 gün",
                related_scenario_id=sid,
            )
        )

    def _add_port_rule(
        self,
        port: int,
        finding: str,
        scenarios: list[AttackScenario],
        actions: list[ActionItem],
        seen: set[str],
    ) -> None:
        sid = f"port-{port}"
        if sid in seen:
            return
        seen.add(sid)
        rule = PORT_RULES[port]
        scenarios.append(
            AttackScenario(
                id=sid,
                title=rule["title"],
                severity=rule["severity"],
                attack_chain=rule["chain"],
                business_impact=rule["impact"],
                related_findings=[finding],
                mitre_tactics=rule["tactics"],
            )
        )
        for i, (desc, owner, timeframe) in enumerate(rule["actions"]):
            actions.append(
                ActionItem(
                    priority=rule["severity"] if i == 0 else "medium",
                    title=desc.split("—")[0].strip() if "—" in desc else desc[:60],
                    description=desc,
                    owner=owner,
                    timeframe=timeframe,
                    related_scenario_id=sid,
                )
            )
