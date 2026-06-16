"""AI tehdit analizi — kural tabanlı motor + Ollama zenginleştirme."""

from __future__ import annotations

import json

import structlog

from app.config import get_settings
from app.services.ai.ollama_client import OllamaClient
from app.services.ai.threat_engine import ActionItem, AttackScenario, ThreatScenarioEngine
from app.services.diff.engine import DiffResult, SnapshotRecord
from app.services.risk.calculator import RiskBreakdown

logger = structlog.get_logger(__name__)
settings = get_settings()

SYSTEM_PROMPT = """Sen Türkiye'deki kurumsal firmalar için çalışan kıdemli bir siber güvenlik danışmanısın.
Attack surface tarama sonuçlarını yönetici ve teknik ekip anlayacak şekilde analiz edersin.
Saldırı senaryolarını gerçekçi ama abartısız anlatırsın. JSON dışında hiçbir şey yazma."""


class AIAnalysisService:
    def __init__(self) -> None:
        self.threat_engine = ThreatScenarioEngine()
        self.ollama = OllamaClient()

    async def generate_insight(
        self,
        organization_name: str,
        total_assets: int,
        previous_total: int | None,
        risk: RiskBreakdown,
        changes: list[DiffResult],
        snapshots: list[SnapshotRecord] | None = None,
    ) -> dict:
        snapshots = snapshots or []
        scenarios, actions = self.threat_engine.analyze(changes, snapshots)
        ollama_health = await self.ollama.health()

        base = self._build_base_result(
            organization_name,
            total_assets,
            previous_total,
            risk,
            changes,
            scenarios,
            actions,
            ollama_health,
        )

        if not settings.ai_enabled or not ollama_health.get("connected") or not ollama_health.get("model_ready"):
            return base

        enriched = await self._enrich_with_ollama(
            organization_name,
            total_assets,
            previous_total,
            risk,
            changes,
            scenarios,
            actions,
        )
        if enriched:
            base.update(enriched)
            base["model_name"] = settings.ollama_model
            base["ollama_connected"] = True
        return base

    async def check_ollama(self) -> dict:
        return await self.ollama.health()

    def _build_base_result(
        self,
        org_name: str,
        total_assets: int,
        previous_total: int | None,
        risk: RiskBreakdown,
        changes: list[DiffResult],
        scenarios: list[AttackScenario],
        actions: list[ActionItem],
        ollama_health: dict,
    ) -> dict:
        asset_delta = ""
        if previous_total is not None and previous_total != total_assets:
            asset_delta = f" Envanter {previous_total} → {total_assets} ({total_assets - previous_total:+d})."

        delta_text = ""
        if risk.delta_percent is not None:
            direction = "arttı" if risk.delta_percent > 0 else "azaldı"
            delta_text = f" Risk %{abs(risk.delta_percent):.0f} {direction}."

        scenario_count = len(scenarios)
        summary = (
            f"{org_name}: {total_assets} izlenen asset.{asset_delta}"
            f"{delta_text} "
            f"{scenario_count} olası saldırı senaryosu ve {len(actions)} aksiyon önerisi üretildi."
        )

        if scenarios:
            top = scenarios[0]
            commentary = (
                f"En yüksek öncelik: «{top.title}». "
                f"İş etkisi: {top.business_impact} "
                f"İlgili bulgular: {', '.join(top.related_findings[:2])}."
            )
        else:
            commentary = (
                f"Kritik saldırı senaryosu tespit edilmedi. Genel risk skoru {risk.total_score:.1f}/10. "
                "Perimetreyi daraltmak ve düzenli diff takibi önerilir."
            )

        if not ollama_health.get("connected"):
            commentary += (
                " Not: Ollama şu an erişilemiyor — analiz kural tabanlı motora dayanıyor. "
                f"Ollama'yı başlatın: ollama serve (beklenen: {settings.ollama_base_url})."
            )

        recs = [a.description for a in actions[:5]]
        if not recs:
            recs = ["Haftalık attack surface taramasını sürdürün.", "Firewall ve cloud IAM politikasını gözden geçirin."]

        model = settings.ollama_model if ollama_health.get("model_ready") else "threat-engine-v1"

        return {
            "summary": summary.strip(),
            "risk_commentary": commentary.strip(),
            "recommendations": recs,
            "attack_scenarios": [s.to_dict() for s in scenarios],
            "action_items": [a.to_dict() for a in actions],
            "model_name": model if ollama_health.get("connected") else "threat-engine-v1 (Ollama kapalı)",
            "ollama_connected": bool(ollama_health.get("connected") and ollama_health.get("model_ready")),
            "ollama_status": ollama_health,
        }

    async def _enrich_with_ollama(
        self,
        org_name: str,
        total_assets: int,
        previous_total: int | None,
        risk: RiskBreakdown,
        changes: list[DiffResult],
        scenarios: list[AttackScenario],
        actions: list[ActionItem],
    ) -> dict | None:
        change_lines = "\n".join(f"- {c.summary} [{c.risk_level.value}]" for c in changes[:12])
        scenario_json = json.dumps([s.to_dict() for s in scenarios[:4]], ensure_ascii=False, indent=2)

        user_prompt = f"""Organizasyon: {org_name}
Asset sayısı: {total_assets} (önceki: {previous_total or "yok"})
Risk: {risk.total_score}/10, delta: {risk.delta_percent or 0}%

Değişiklikler:
{change_lines or "Yok"}

Mevcut saldırı senaryoları (bunları zenginleştir, tekrarlama):
{scenario_json}

Aşağıdaki JSON şemasında yanıt ver:
{{
  "summary": "Yönetici için 2 cümle",
  "risk_commentary": "Somut tehdit ve risk artışı yorumu",
  "attack_scenarios": [
    {{
      "id": "benzersiz-id",
      "title": "Senaryo başlığı",
      "severity": "critical|high|medium|low",
      "attack_chain": ["adım1", "adım2", "adım3"],
      "business_impact": "iş etkisi Türkçe",
      "related_findings": ["bulgu"],
      "mitre_tactics": ["Tactic1"]
    }}
  ],
  "action_items": [
    {{
      "priority": "critical|high|medium|low",
      "title": "Kısa başlık",
      "description": "Ne yapılmalı, nasıl",
      "owner": "Altyapı|Güvenlik|DevOps|Cloud",
      "timeframe": "4 saat|1 gün|1 hafta"
    }}
  ],
  "recommendations": ["özet madde 1", "özet madde 2"]
}}
En fazla 4 senaryo, 6 aksiyon. Türkçe yaz."""

        parsed = await self.ollama.chat_json(SYSTEM_PROMPT, user_prompt)
        if not parsed:
            return None

        result: dict = {}
        if parsed.get("summary"):
            result["summary"] = parsed["summary"]
        if parsed.get("risk_commentary"):
            result["risk_commentary"] = parsed["risk_commentary"]
        if parsed.get("recommendations"):
            result["recommendations"] = parsed["recommendations"]

        llm_scenarios = parsed.get("attack_scenarios") or []
        if llm_scenarios:
            merged = [s.to_dict() for s in scenarios]
            existing_ids = {s["id"] for s in merged}
            for ls in llm_scenarios[:3]:
                if ls.get("id") not in existing_ids and ls.get("title"):
                    merged.append(ls)
            result["attack_scenarios"] = merged[:8]

        llm_actions = parsed.get("action_items") or []
        if llm_actions:
            merged_actions = [a.to_dict() for a in actions]
            result["action_items"] = (merged_actions + llm_actions)[:12]

        return result or None
