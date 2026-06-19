# KurSal — Kurumsal Saldırı Yüzeyi İzleme

[![CI](https://github.com/kagannhoo/kurumsall/actions/workflows/ci.yml/badge.svg)](https://github.com/kagannhoo/kurumsall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)

Şirketin internete açık tüm dijital varlıklarını (portlar, domainler, SSL sertifikaları, cloud kaynakları) sürekli izleyen, değişiklikleri tespit eden ve AI destekli saldırı senaryoları üreten **self-hosted** kurumsal güvenlik platformu.

> **Repo:** https://github.com/kagannhoo/kurumsall  
> **Durum:** Açık kaynak POC — demo modu ile hemen denenebilir, production için [PRODUCTION.md](PRODUCTION.md) rehberini takip edin.

---

## Ne işe yarar?

Kurumsal firmaların en büyük kör noktası genelde **dışarıdan görünen dijital yüzeydir**. KurSal şu sorulara otomatik cevap verir:

- İnternete hangi portlar açık?
- Hangi subdomain'ler keşfedilebilir durumda?
- SSL sertifikalarının süresi ne zaman doluyor?
- Cloud'da public erişime açık kaynak var mı?
- Dün'e göre yüzeyimizde ne değişti?
- Bir saldırgan bu bulguları nasıl kullanabilir?
- Ne yapmalıyız, kim sorumlu, ne kadar sürede?

---

## Ne fayda sağlar?

| Fayda | Açıklama |
|-------|----------|
| **Erken uyarı** | Yeni açılan port veya subdomain anında diff raporuna düşer |
| **Risk önceliklendirme** | 0–10 skor + haftalık delta ile yönetici dili |
| **Saldırı perspektifi** | Red team senaryoları — "3306 açıksa MySQL sızıntısı nasıl olur?" |
| **Aksiyon planı** | Öncelik, sorumlu ekip, süre — doğrudan ticket'a dönüştürülebilir |
| **Yönetici raporu** | PDF/CSV export, executive summary |
| **Veri gizliliği** | Self-hosted — Ollama ile local AI, veri dışarı çıkmaz |
| **Yasal koruma** | Domain ownership verification — yalnızca yetkili sistemler taranır |

---

## Özellikler

| Özellik | Açıklama |
|---------|----------|
| **Asset keşfi** | DNS brute-force, port tarama, SSL analizi, cloud envanter, **Nuclei CVE taraması** |
| **Snapshot diff** | Her taramayı öncekiyle karşılaştırır; eklenen port, kaybolan domain, değişen SSL |
| **Risk skoru** | CVSS ağırlıklı 0–10 skor, haftalık delta |
| **Saldırı senaryoları** | Rule-based + Ollama LLM zenginleştirme |
| **Aksiyon planı** | Öncelik, sorumlu, süre |
| **JWT auth** | API key alternatifi, domain doğrulama |
| **Export** | PDF + CSV yönetici raporu |
| **Alert** | Slack webhook (kritik bulgular) |
| **Metrikler** | Prometheus `/metrics` |

---

## Mimari

```
┌──────────────────────────────────────────────────┐
│  React Dashboard  (localhost:5173)                │
│  Auth · Saldırı Senaryoları · Export · Timeline  │
└────────────────────┬─────────────────────────────┘
                     │ REST API
┌────────────────────▼─────────────────────────────┐
│  FastAPI  (localhost:8087)                        │
│  JWT · Domain Verification · Prometheus           │
└──────┬─────────┬──────────┬────────────┬─────────┘
       │         │          │            │
  Celery    Diff Engine  Risk Calc    AI Analysis
  Worker               (CVSS)       (rule + Ollama)
       │
  DNS │ Port │ SSL │ Cloud │ Nuclei Scanners
       │
  PostgreSQL (snapshot · change history)
```

---

## Hızlı başlangıç (Demo)

### Gereksinimler

- Docker + Docker Compose
- (Opsiyonel) [Ollama](https://ollama.com) — yerel LLM

### Kurulum

```bash
git clone https://github.com/kagannhoo/kurumsall
cd kurumsall
cp .env.example .env
docker compose up -d postgres redis
docker compose run --rm api alembic upgrade head
docker compose up -d
docker compose exec api python scripts/seed_demo.py
```

### Erişim

| Servis | URL |
|--------|-----|
| Dashboard | http://localhost:5173 |
| API / Swagger | http://localhost:8087/docs |
| Health | http://localhost:8087/health |

Giriş: **admin@local / admin123**

> **Bilgisayarı yeniden başlattıktan sonra** API cevap vermezse:
> `docker compose up -d && docker compose restart api worker`

---

## Demo vs Production

| | Demo | Production |
|---|------|------------|
| Domain | `example.com` (test domain) | Kendi doğrulanmış domain |
| Cloud | JSON config envanteri | AWS/Azure API (roadmap) |
| Port/DNS | Yerleşik (sınırlı) | Naabu + Subfinder |
| Zafiyet | Kapalı (Nuclei devre dışı) | Nuclei CVE şablonları |
| Doğrulama | "Demo: Doğrula" butonu | DNS TXT kaydı zorunlu |
| Banner | Dashboard'da sarı uyarı | Yok |

**Gerçek kullanım için ne değiştirmelisiniz?**

1. `.env` → `SECRET_KEY`, `ADMIN_PASSWORD`, `DEMO_MODE=false`
2. Kendi organizasyonunuzu oluşturun (demo-company kullanmayın)
3. Domain'inizi DNS TXT ile doğrulayın
4. Naabu/Subfinder/Nuclei kurun → `SCANNER_USE_EXTERNAL_TOOLS=true`
5. Ollama başlatın → AI analiz zenginleşir
6. Slack webhook → kritik bulgu alertleri

Detaylı adımlar: **[PRODUCTION.md](PRODUCTION.md)**

---

## Ollama (AI tehdit analizi)

Ollama olmadan da çalışır (kural tabanlı motor). Açıkken LLM ile zenginleşir, veri dışarı çıkmaz.

```bash
ollama serve
ollama pull llama3.1
```

---

## Testler

```bash
cd backend && python -m pytest tests/ -q
# 16 test — diff, risk, threat engine, API health
```

---

## Yol haritası

- AWS / Azure / GCP canlı API entegrasyonu
- Shodan / Certificate Transparency pasif keşif
- Multi-tenant RBAC

`GET /api/v1/system/info` → `roadmap` alanı

---

## Dokümantasyon

| Dosya | İçerik |
|-------|--------|
| [PRODUCTION.md](PRODUCTION.md) | Gerçek kullanım kurulum rehberi |
| [SECURITY.md](SECURITY.md) | Yasal sınırlar, TCK 243–245 |
| [CREDITS.md](CREDITS.md) | Bağımlılıklar, MITRE ATT&CK atıfı |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Katkı rehberi |
| [docs/LINKEDIN.md](docs/LINKEDIN.md) | LinkedIn paylaşım metni |

---

## Yasal uyarı

> KurSal **yalnızca yetkili olduğunuz sistemlerde** kullanılabilir. İzinsiz tarama TCK 243–245 kapsamında suçtur.

---

## Yazar ve geliştirme

**Kagan** ([@kagannhoo](https://github.com/kagannhoo)) — proje sahibi

**Cursor + Auto** — AI destekli geliştirme asistanı

## Lisans

[MIT](LICENSE) — Copyright (c) 2026 Kagan (kagannhoo)
