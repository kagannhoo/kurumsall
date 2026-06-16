# Kurumsal Attack Surface Monitor (ASM)

[![CI](https://github.com/YOUR_USER/kurumsall/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USER/kurumsall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)

Şirketin internete açık tüm dijital varlıklarını (portlar, domainler, SSL sertifikaları, cloud kaynakları) sürekli izleyen, değişiklikleri tespit eden ve AI destekli saldırı senaryoları üreten **self-hosted** kurumsal güvenlik platformu.

---

## Ne yapar?

| Özellik | Açıklama |
|---------|----------|
| **Asset keşfi** | DNS brute-force, port tarama (TCP connect), SSL sertifika analizi, cloud envanter |
| **Snapshot diff** | Her taramayı öncekiyle karşılaştırır; eklenen port, kaybolan domain, değişen SSL süresi |
| **Risk skoru** | 0–10 arası CVSS ağırlıklı skor, haftalık delta (örn. "Risk +%18") |
| **Saldırı senaryoları** | Bulgulara göre rule-based + Ollama LLM ile zenginleştirilmiş red team senaryoları |
| **Aksiyon planı** | Öncelik, sorumlu ekip ve süre içeren yapılacaklar listesi |
| **Yönetici raporu** | PDF + CSV export, executive summary |
| **Alert** | Slack webhook, kritik bulgu bildirimi |

---

## Mimari

```
┌──────────────────────────────────────────────────┐
│  React + Vite Dashboard  (localhost:5173)         │
│  JWT Auth · Attack Scenarios · Export · Timeline  │
└────────────────────┬─────────────────────────────┘
                     │ HTTP / REST
┌────────────────────▼─────────────────────────────┐
│  FastAPI  (localhost:8087)                        │
│  /api/v1 · JWT · Domain Verification · /metrics  │
└──────┬─────────┬──────────┬────────────┬─────────┘
       │         │          │            │
  Celery    Diff Engine  Risk Calc    AI Analysis
  Worker    (snapshot    (CVSS        (rule-based
  (Redis)    compare)     weight)      + Ollama)
       │
┌──────▼─────────────────────────────────────────┐
│  Scanners                                       │
│  DNS Brute │ Port TCP │ SSL Cert │ Cloud Enum   │
└─────────────────────────────────────────────────┘
       │
  PostgreSQL (snapshot store · change history)
```

---

## Hızlı başlangıç

### Gereksinimler

- Docker + Docker Compose
- (Opsiyonel) [Ollama](https://ollama.com) — yerel LLM için

### 1. Kur ve başlat

```bash
git clone https://github.com/YOUR_USER/kurumsall
cd kurumsall
cp .env.example .env        # production'da SECRET_KEY ve ADMIN_PASSWORD değiştir
docker compose up -d postgres redis
docker compose run --rm api alembic upgrade head
docker compose up -d
```

### 2. Demo veri yükle

```bash
docker compose exec api python scripts/seed_demo.py
```

### 3. Aç

| Servis | URL |
|--------|-----|
| Dashboard | http://localhost:5173 |
| API / Swagger | http://localhost:8087/docs |
| Health | http://localhost:8087/health |
| Prometheus | http://localhost:8087/metrics |

Giriş: **admin@local / admin123** (`.env`'den değiştirilebilir)

---

## Ollama (AI saldırı analizi)

Sistem Ollama olmadan da çalışır — kural tabanlı saldırı senaryoları üretir. Ollama açıkken analiz LLM ile zenginleştirilir, veri dışarı çıkmaz.

```bash
# Ayrı terminalde
ollama serve
ollama pull llama3.1
```

Durum: http://localhost:8087/api/v1/system/status

---

## Gelişmiş tarama (Opsiyonel)

[Subfinder](https://github.com/projectdiscovery/subfinder) ve [Naabu](https://github.com/projectdiscovery/naabu) kuruluysa daha geniş subdomain ve port taraması yapılır:

```bash
# .env veya docker-compose.yml içinde
SCANNER_USE_EXTERNAL_TOOLS=true
```

---

## Testler

```bash
cd backend
python -m pytest tests/ -q
```

---

## Servisler ve portlar

| Servis | Host port | Container port |
|--------|-----------|---------------|
| API (FastAPI) | 8087 | 8000 |
| Dashboard (Vite) | 5173 | 5173 |
| PostgreSQL | 5433 | 5432 |
| Redis | — | 6379 (sadece internal) |

---

## Modüller

| Modül | Konum | Görev |
|-------|-------|-------|
| Scanners | `backend/app/services/scanners/` | DNS, port, SSL, cloud keşfi |
| Diff Engine | `backend/app/services/diff/` | Snapshot karşılaştırma |
| Risk Calculator | `backend/app/services/risk/` | CVSS ağırlıklı skorlama |
| Threat Engine | `backend/app/services/ai/threat_engine.py` | Saldırı senaryoları |
| AI Analysis | `backend/app/services/ai/analysis.py` | Ollama entegrasyonu |
| Export | `backend/app/services/export/` | PDF + CSV rapor |
| Auth | `backend/app/core/` | JWT + API key |
| Alerts | `backend/app/services/alerts/` | Slack webhook |

---

## Katkı

Bkz. [CONTRIBUTING.md](CONTRIBUTING.md)

## Lisans

[MIT](LICENSE)
