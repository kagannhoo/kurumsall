# Kaynakça ve Teşekkürler

Bu proje aşağıdaki açık kaynak kütüphaneler ve referans materyaller üzerine inşa edilmiştir.
Her birinin lisans şartlarına eksiksiz uyulmaktadır.

---

## Backend bağımlılıkları

| Kütüphane | Sürüm | Lisans | Kullanım |
|-----------|-------|--------|---------|
| [FastAPI](https://github.com/fastapi/fastapi) | 0.115.6 | MIT | REST API çerçevesi |
| [Uvicorn](https://github.com/encode/uvicorn) | 0.34.0 | BSD-3-Clause | ASGI sunucu |
| [SQLAlchemy](https://github.com/sqlalchemy/sqlalchemy) | 2.0.36 | MIT | ORM ve veritabanı katmanı |
| [asyncpg](https://github.com/MagicStack/asyncpg) | 0.30.0 | Apache-2.0 | PostgreSQL async sürücü |
| [psycopg2-binary](https://github.com/psycopg/psycopg2) | 2.9.10 | LGPL-3.0 | PostgreSQL sync sürücü (Alembic) |
| [Alembic](https://github.com/sqlalchemy/alembic) | 1.14.0 | MIT | Veritabanı migration |
| [Pydantic](https://github.com/pydantic/pydantic) | 2.10.3 | MIT | Veri doğrulama ve serialization |
| [pydantic-settings](https://github.com/pydantic/pydantic-settings) | 2.7.0 | MIT | Ortam değişkeni yönetimi |
| [Celery](https://github.com/celery/celery) | 5.4.0 | BSD-3-Clause | Dağıtık görev kuyruğu |
| [redis-py](https://github.com/redis/redis-py) | 5.2.1 | MIT | Redis istemcisi |
| [HTTPX](https://github.com/encode/httpx) | 0.28.1 | BSD-3-Clause | Async HTTP istemcisi (Ollama) |
| [dnspython](https://github.com/rthalley/dnspython) | 2.7.0 | ISC | DNS çözümleme ve brute-force |
| [cryptography](https://github.com/pyca/cryptography) | 44.0.0 | Apache-2.0 / BSD | Fernet şifreleme |
| [structlog](https://github.com/hynek/structlog) | 24.4.0 | Apache-2.0 / MIT | Yapılandırılmış loglama |
| [tenacity](https://github.com/jd/tenacity) | 9.0.0 | Apache-2.0 | Yeniden deneme mekanizması |
| [PyJWT](https://github.com/jpadilla/pyjwt) | 2.10.1 | MIT | JWT token üretimi ve doğrulama |
| [passlib](https://github.com/passlib-project/passlib) | 1.7.4 | BSD-2-Clause | Şifre hash (bcrypt) |
| [bcrypt](https://github.com/pyca/bcrypt) | 4.2.1 | Apache-2.0 | Bcrypt hash algoritması |
| [prometheus-client](https://github.com/prometheus/client_python) | 0.21.1 | Apache-2.0 | Prometheus metrikleri |
| [ReportLab](https://www.reportlab.com/opensource/) | 4.2.5 | BSD-3-Clause | PDF rapor üretimi |
| [python-dateutil](https://github.com/dateutil/dateutil) | 2.9.0 | Apache-2.0 / BSD | Tarih işlemleri |
| [pytest](https://github.com/pytest-dev/pytest) | 8.3.4 | MIT | Test çerçevesi |
| [pytest-asyncio](https://github.com/pytest-dev/pytest-asyncio) | 0.25.0 | Apache-2.0 | Async test desteği |

---

## Frontend bağımlılıkları

| Kütüphane | Sürüm | Lisans | Kullanım |
|-----------|-------|--------|---------|
| [React](https://github.com/facebook/react) | 19.0.0 | MIT | UI çerçevesi |
| [ReactDOM](https://github.com/facebook/react) | 19.0.0 | MIT | DOM render |
| [Vite](https://github.com/vitejs/vite) | 6.0.3 | MIT | Build aracı ve geliştirme sunucusu |
| [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react) | 4.3.4 | MIT | Vite React desteği |
| [TypeScript](https://github.com/microsoft/TypeScript) | 5.7.2 | Apache-2.0 | Tip güvenli JavaScript |

---

## Altyapı / araçlar

| Araç | Lisans | Kullanım |
|------|--------|---------|
| [PostgreSQL](https://www.postgresql.org/) | PostgreSQL License (MIT benzeri) | İlişkisel veritabanı |
| [Redis](https://redis.io/) | RSALv2 / SSPLv1 (7.x) | Mesaj kuyruğu ve cache |
| [Docker](https://www.docker.com/) | Apache-2.0 | Container altyapısı |
| [Ollama](https://ollama.com/) | MIT | Yerel LLM çalıştırma |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | MIT | Pasif subdomain keşfi (Docker imajında) |
| [Naabu](https://github.com/projectdiscovery/naabu) | MIT | Port tarama (Docker imajında) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | MIT | CVE / zafiyet taraması (Docker imajında) |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | Nuclei CVE ve güvenlik şablonları |

---

## Referans çerçeveler ve standartlar

### MITRE ATT&CK®

Tehdit senaryolarındaki taktik etiketleri (Reconnaissance, Initial Access, Exfiltration vb.)
**MITRE ATT&CK®** çerçevesine atıfla kullanılmaktadır.

> MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
> ATT&CK content is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
> Kaynak: https://attack.mitre.org/

Bu proje MITRE tarafından onaylanmamış veya ilişkilendirilmemiştir.
ATT&CK verisi bu projede **referans amaçlı** kullanılmakta, olduğu gibi dağıtılmamaktadır.

### CVSS (Common Vulnerability Scoring System)

Risk skorlama mantığı CVSS metodolojisinden ilham almaktadır.

> CVSS is owned and managed by FIRST.Org, Inc.
> https://www.first.org/cvss/

### OWASP

Attack surface monitoring ve dış yüzey yönetimi kavramları [OWASP](https://owasp.org/) ASM rehberlerinden ilham almaktadır.

### ProjectDiscovery

DNS, port ve zafiyet tarama modülleri [ProjectDiscovery](https://projectdiscovery.io/) araç ekosistemini (Subfinder, Naabu, Nuclei) kullanmaktadır.
Şablonlar: https://github.com/projectdiscovery/nuclei-templates

---

## Geliştirme araçları

| Araç | Kullanım |
|------|---------|
| [Cursor](https://cursor.com/) | AI destekli IDE — mimari tasarım, kod üretimi, hata ayıklama ve dokümantasyon |
| [Auto (Cursor Agent)](https://cursor.com/) | AI kod asistanı — backend/frontend geliştirme, test ve DevOps otomasyonu |

> Bu proje **Kagan** tarafından yönetilmiş; Cursor ve Auto (Cursor Agent) ile birlikte geliştirilmiştir.
> Tüm tasarım kararları, domain doğrulama, yasal sınırlar ve nihai onay proje sahibine aittir.
> AI tarafından üretilen kod MIT lisansı altında yayınlanmaktadır.

---

## Yasal uyarı / Disclaimer

> **KurSal yalnızca yetkili olduğunuz sistemlerde kullanılmak üzere tasarlanmıştır.**
>
> Bu araç ile gerçekleştirilen taramalar; hedef sistemin sahibi veya yetkili yöneticisi
> tarafından açıkça izin verilmiş olmadıkça yasal değildir.
>
> Türkiye'de **5651 sayılı Kanun** ve **Türk Ceza Kanunu'nun 243–245. maddeleri**
> izinsiz erişim ve sistem taramasını suç olarak tanımlamaktadır.
> Uluslararası kullanımda ilgili ülkenin siber güvenlik mevzuatı geçerlidir.
>
> Geliştirici bu aracın kötüye kullanımından doğacak hukuki veya cezai sorumlulukları
> kabul etmez.

---

## Yazar ve geliştirme

**Kagan** ([@kagannhoo](https://github.com/kagannhoo)) — proje sahibi ve sorumlu geliştirici

**Cursor + Auto (Cursor Agent)** — AI destekli geliştirme asistanı ([cursor.com](https://cursor.com/))

Proje: https://github.com/kagannhoo/kurumsall
