# LinkedIn Paylaşım Metni — KurSal

Aşağıdaki metni kopyalayıp LinkedIn'e yapıştırabilirsin. Dashboard ekran görüntüsü ekle (saldırı senaryoları paneli en etkileyici olanı).

---

## Post (Türkçe)

**KurSal — Self-Hosted Attack Surface Monitor**

Son dönemde sıfırdan geliştirdiğim açık kaynak bir siber güvenlik projesini paylaşmak istiyorum.

KurSal, şirketin internete açık dijital varlıklarını (portlar, domainler, SSL sertifikaları, cloud kaynakları) izleyen, değişiklikleri tespit eden ve AI destekli saldırı senaryoları üreten self-hosted bir platform.

**Ne problemi çözüyor?**

Kurumsal firmalar genelde "dışarıdan bize neler görünüyor?" sorusuna net cevap veremiyor. Yeni açılan bir port, unutulan bir subdomain veya süresi dolmak üzere olan SSL sertifikası — bunlar saldırganlar için fırsat, güvenlik ekipleri için kör nokta.

KurSal bunu otomatikleştiriyor:
→ Günlük snapshot + diff (ne eklendi, ne değişti?)
→ Risk skoru (0–10, haftalık delta)
→ Saldırı senaryoları ("MySQL portu açıksa ne olur?")
→ Aksiyon planı (kim, ne yapmalı, ne kadar sürede)
→ Yönetici raporu (PDF/CSV)

**Teknik stack:**
FastAPI · Celery · PostgreSQL · React · Ollama (opsiyonel, veri dışarı çıkmaz)

**Önemli not — dürüst olmak gerekirse:**

Bu bir production-ready POC / açık kaynak side project. Demo modunda `example.com` ile çalışıyor; cloud envanteri yapılandırılmış JSON'dan geliyor (henüz canlı AWS/Azure API yok). Port ve DNS taraması yerleşik modda sınırlı kapsamda.

Gerçek kurumsal kullanım için:
• Kendi domain'inizi DNS TXT ile doğrulamanız
• SECRET_KEY ve admin şifresini değiştirmeniz
• Naabu/Subfinder ile tarama kapsamını genişletmeniz
• Ollama ile AI analizini aktifleştirmeniz gerekiyor

Tüm adımlar repoda detaylı: github.com/kagannhoo/kurumsall

MIT lisanslı, katkıya açık.

#CyberSecurity #AttackSurface #DevSecOps #OpenSource #FastAPI #InfoSec

---

## Kısa versiyon (story / yorum için)

KurSal: self-hosted attack surface monitor — port/domain/SSL/cloud izleme, diff analizi, AI saldırı senaryoları. Açık kaynak (MIT): github.com/kagannhoo/kurumsall

---

## İngilizce versiyon (opsiyonel)

**KurSal — Self-Hosted Attack Surface Monitor**

I built an open-source security platform that monitors your organization's external-facing assets: open ports, domains, SSL certificates, and cloud resources.

It runs daily snapshots, detects changes (diff engine), scores risk, and generates AI-powered attack scenarios with actionable remediation plans — all self-hosted, no data leaves your network.

Stack: FastAPI · Celery · PostgreSQL · React · Ollama (optional)

Currently a POC with demo mode (example.com). Production setup requires domain verification, credential hardening, and optional external scanners (Naabu/Subfinder).

MIT licensed: github.com/kagannhoo/kurumsall

#CyberSecurity #AttackSurface #DevSecOps #OpenSource
