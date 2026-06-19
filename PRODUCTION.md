# KurSal — Production Kurulum Rehberi

Bu rehber, demo ortamından **gerçek kurumsal kullanıma** geçmek için yapmanız gerekenleri adım adım açıklar.

---

## Demo ile production arasındaki fark

| Bileşen | Demo (şu an) | Production (yapmanız gereken) |
|---------|--------------|-------------------------------|
| Domain | `example.com` — test domain | Kendi şirket domain'iniz |
| Domain doğrulama | UI'da "Demo: Doğrula" butonu | DNS TXT kaydı (`_asm-verify.domain.com`) |
| Cloud envanter | JSON config'ten okunur | AWS/Azure API (roadmap) veya manuel envanter |
| Port/DNS tarama | Naabu + Subfinder (Docker'da hazır) | Aynı |
| Zafiyet tarama | Nuclei CVE şablonları (Docker'da hazır) | Periyodik şablon güncellemesi |
| AI analiz | Ollama kapalıysa kural tabanlı | `ollama serve` + `llama3.1` |
| Kimlik bilgileri | `admin@local / admin123` | Güçlü şifre + `SECRET_KEY` |
| Alert | Kapalı | Slack webhook URL |

---

## Adım 1 — Ortam değişkenlerini ayarlayın

```bash
cp .env.example .env
```

`.env` dosyasını düzenleyin:

```bash
# Zorunlu değişiklikler
SECRET_KEY=<openssl rand -hex 32 ile üretin>
ADMIN_PASSWORD=<güçlü şifre>
ADMIN_EMAIL=guvenlik@sirketiniz.com

# Production modu
DEMO_MODE=false
REQUIRE_DOMAIN_VERIFICATION=true
AUTH_ENABLED=true

# Opsiyonel — harici tarayıcılar
SCANNER_USE_EXTERNAL_TOOLS=true
SCANNER_NUCLEI_SEVERITY=critical,high,medium
SCANNER_NUCLEI_TAGS=cve
SCANNER_NUCLEI_TIMEOUT=900

# Opsiyonel — Slack alert
ALERT_SLACK_WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Opsiyonel — Ollama (host makinede çalışıyorsa)
OLLAMA_BASE_URL=http://host.docker.internal:11434
AI_ENABLED=true
```

---

## Adım 2 — Stack'i başlatın

```powershell
cd kurumsall
docker compose up -d postgres redis
docker compose run --rm api alembic upgrade head
docker compose up -d
```

**Not:** Bilgisayarı yeniden başlattıktan sonra Postgres/Redis kapalı kalabilir. API cevap vermezse:

```powershell
docker compose up -d
docker compose restart api worker
```

Kontrol: http://localhost:8087/health → `{"status":"ok","service":"KurSal"}`

---

## Adım 3 — Organizasyon oluşturun

Dashboard → giriş yapın → yeni organizasyon:

- **Name:** Şirketiniz A.Ş.
- **Slug:** sirketiniz
- **Root domains:** `sirketiniz.com`

Demo organizasyonu (`demo-company`) kullanmayın — o eğitim amaçlıdır.

---

## Adım 4 — Domain sahipliğini doğrulayın

Dashboard'da domain doğrulama paneli görünür. DNS'e TXT kaydı ekleyin:

```
Host:  _asm-verify.sirketiniz.com
Value: asm-verify-<token>   ← API'den alınır
```

Doğrulama:
- Dashboard'da "DNS ile Doğrula" butonu, veya
- `POST /api/v1/organizations/{id}/domains/sirketiniz.com/verify`

**Tarama, domain doğrulanmadan başlamaz** — bu yasal koruma katmanıdır.

---

## Adım 5 — Harici tarayıcılar (Docker'da hazır)

**Nuclei, Naabu ve Subfinder** worker imajına varsayılan olarak gömülüdür. `docker compose build && docker compose up -d` yeterli.

```powershell
docker compose build
docker compose up -d
```

İlk worker başlatılışında Nuclei CVE şablonları otomatik indirilir. Manuel güncelleme:

```powershell
docker compose exec worker nuclei -update-templates
```

`.env` varsayılanları:
```bash
SCANNER_USE_EXTERNAL_TOOLS=true
SCANNER_NUCLEI_SEVERITY=critical,high,medium
SCANNER_NUCLEI_TAGS=cve
```

Tarayıcıları devre dışı bırakmak isterseniz (sadece yerleşik mod):
```bash
SCANNER_USE_EXTERNAL_TOOLS=false
INSTALL_SCANNERS=false
docker compose build --build-arg INSTALL_SCANNERS=false
```

Yerleşik fallback (harici araçlar kapalıysa):
- DNS: 15 yaygın subdomain brute-force
- Port: 16 kritik port TCP connect
- SSL: Canlı TLS handshake
- Zafiyet: atlanır

---

## Adım 6 — Ollama (AI tehdit analizi)

```powershell
# Ayrı terminal — host makinede
ollama serve
ollama pull llama3.1
```

Docker'da API zaten `host.docker.internal:11434` kullanıyor. Durum kontrolü:

http://localhost:8087/api/v1/system/status

Ollama kapalıysa sistem **kural tabanlı tehdit motoru** ile çalışmaya devam eder.

---

## Adım 7 — Cloud envanter (şu anki sınırlama)

Cloud modülü **yapılandırılmış envanter** modunda çalışır — AWS/Azure API'sine bağlanmaz.

Organizasyon oluştururken `cloud_accounts` JSON ile kaynak tanımlayın:

```json
{
  "aws": {
    "resources": [
      {
        "type": "s3_bucket",
        "id": "prod-backups",
        "name": "prod-backups",
        "region": "eu-west-1",
        "public": false
      }
    ]
  }
}
```

Canlı AWS/Azure API entegrasyonu yol haritasındadır (`GET /api/v1/system/info` → `roadmap`).

---

## Adım 8 — İlk tarama

1. Dashboard → **Yüzey Taraması Başlat**
2. Tarama Celery worker'da arka planda çalışır (~30 sn)
3. **Tarama Modül Durumu** panelinde her modülün sonucu görünür
4. İkinci taramadan itibaren **diff raporu** aktif olur

Slack alert için `ALERT_SLACK_WEBHOOK` ayarlayın — kritik bulgularda otomatik bildirim gelir.

---

## Sorun giderme

| Sorun | Çözüm |
|-------|-------|
| `/health` boş sayfa | http://127.0.0.1:8087/health veya `/docs` dene |
| API başlamıyor | `docker compose ps` — postgres/redis çalışıyor mu? |
| Tarama başlamıyor | Domain doğrulandı mı? Cooldown (60 sn) bitti mi? |
| Ollama kapalı | Normal — kural tabanlı analiz devam eder |
| Worker hatası | `docker compose logs worker --tail 30` |

---

## Yasal hatırlatma

KurSal yalnızca **yetkili sistemlerde** kullanılabilir. Kendi domain'inizi DNS TXT ile doğrulamanız bu yetkinin kanıtı olarak tasarlanmıştır. Bkz. [SECURITY.md](SECURITY.md).
