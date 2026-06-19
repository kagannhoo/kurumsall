# LinkedIn Paylaşım Metni — KurSal

Dashboard ekran görüntüsü ekle (saldırı senaryoları + tarama modül durumu paneli ideal).

Aşağıdaki **çift dilli post** tek paylaşımda TR + EN içerir — LinkedIn'e olduğu gibi yapıştır.

---

## Post (Türkçe + English — tek paylaşım)

🇹🇷 **KurSal — Self-Hosted Attack Surface Monitor**

Son dönemde sıfırdan geliştirdiğim açık kaynak bir siber güvenlik projesini paylaşmak istiyorum.

KurSal, şirketin internete açık dijital varlıklarını (portlar, domainler, SSL sertifikaları, cloud kaynakları) izleyen, değişiklikleri tespit eden ve AI destekli saldırı senaryoları üreten **self-hosted** bir platform.

**Ne problemi çözüyor?**
Kurumsal firmalar genelde "dışarıdan bize neler görünüyor?" sorusuna net cevap veremiyor. Yeni açılan bir port, unutulan bir subdomain, süresi dolmak üzere olan SSL sertifikası veya bilinen bir CVE — saldırganlar için fırsat, güvenlik ekipleri için kör nokta.

**KurSal ne yapıyor?**
→ Günlük snapshot + diff (ne eklendi, ne değişti?)
→ Risk skoru (0–10, haftalık delta)
→ Nuclei ile CVE zafiyet taraması
→ Saldırı senaryoları + aksiyon planı (kim, ne, ne kadar sürede)
→ Yönetici raporu (PDF/CSV)

**Kurulum kolay:** `docker compose up` — Nuclei, Naabu, Subfinder imaja gömülü geliyor, ayrı kurulum yok.

Stack: FastAPI · Celery · PostgreSQL · React · Nuclei · Ollama (opsiyonel)

Demo modunda `example.com` ile denenebilir. Production için domain DNS doğrulama + credential hardening yeterli.

🔗 https://github.com/kagannhoo/kurumsall
MIT lisanslı, katkıya açık.

#CyberSecurity #AttackSurface #DevSecOps #OpenSource #Nuclei #InfoSec

---

🇬🇧 **KurSal — Self-Hosted Attack Surface Monitor**

I'm sharing an open-source security platform I built from scratch.

KurSal monitors your organization's internet-facing assets — open ports, domains, SSL certificates, and cloud resources — detects changes over time, and generates AI-assisted attack scenarios with actionable remediation plans. Everything runs **self-hosted**; your data never leaves your network.

**The problem:** Most teams can't answer "what do attackers see from the outside?" New ports, forgotten subdomains, expiring certs, or known CVEs are blind spots until it's too late.

**What KurSal does:**
→ Daily snapshots + diff engine
→ Risk score (0–10, weekly delta)
→ CVE scanning with Nuclei
→ Attack scenarios + action items (owner, priority, timeline)
→ Executive reports (PDF/CSV)

**Zero-hassle setup:** `docker compose up` — Nuclei, Naabu, and Subfinder are pre-baked into the Docker image. No manual scanner install.

Stack: FastAPI · Celery · PostgreSQL · React · Nuclei · Ollama (optional)

Try it in demo mode with example.com. For production: verify your domain via DNS TXT and rotate secrets.

🔗 https://github.com/kagannhoo/kurumsall
MIT licensed, contributions welcome.

#CyberSecurity #AttackSurface #DevSecOps #OpenSource #Nuclei #InfoSec

---

## Kısa versiyon (yorum / story)

TR: KurSal — self-hosted attack surface monitor. Docker ile tek komut, Nuclei dahil. https://github.com/kagannhoo/kurumsall

EN: KurSal — self-hosted ASM with Nuclei baked in. One `docker compose up`. https://github.com/kagannhoo/kurumsall
