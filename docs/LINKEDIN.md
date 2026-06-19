# LinkedIn Paylaşım Metni — KurSal

Aşağıdaki metni kopyalayıp LinkedIn'e yapıştırabilirsin. Dashboard ekran görüntüsü ekle (saldırı senaryoları paneli en etkileyici olanı).

---

## Post (Türkçe)

**KurSal — Self-Hosted Attack Surface Monitor**

Son dönemde sıfırdan geliştirdiğim açık kaynak bir siber güvenlik projesini paylaşmak istiyorum.

KurSal, şirketin internete açık dijital varlıklarını (portlar, domainler, SSL sertifikaları, cloud kaynakları) izleyen, değişiklikleri tespit eden ve AI destekli saldırı senaryoları üreten self-hosted bir platform.

**Ne problemi çözüyor?**

Kurumsal firmalar genelde "dışarıdan bize neler görünüyor?" sorusuna net cevap veremiyor. Yeni açılan bir port, unutulan bir subdomain, süresi dolmak üzere olan SSL sertifikası veya bilinen bir CVE — bunlar saldırganlar için fırsat, güvenlik ekipleri için kör nokta.

KurSal bunu otomatikleştiriyor:
→ Günlük snapshot + diff (ne eklendi, ne değişti?)
→ Risk skoru (0–10, haftalık delta)
→ **Nuclei ile CVE zafiyet taraması** (critical/high/medium)
→ Saldırı senaryoları ("MySQL portu açıksa ne olur?", "CVE eşleşmesi varsa ne olur?")
→ Aksiyon planı (kim, ne yapmalı, ne kadar sürede)
→ Yönetici raporu (PDF/CSV)

**Teknik stack:**
FastAPI · Celery · PostgreSQL · React · Nuclei · Ollama (opsiyonel, veri dışarı çıkmaz)

**Önemli not — dürüst olmak gerekirse:**

Bu bir production-ready POC / açık kaynak side project. Demo modunda `example.com` ile çalışıyor; cloud envanteri yapılandırılmış JSON'dan geliyor (henüz canlı AWS/Azure API yok). Nuclei modülü harici araçlar açıkken aktif — Docker demo'da varsayılan kapalı.

Gerçek kurumsal kullanım için:
• Kendi domain'inizi DNS TXT ile doğrulamanız
• SECRET_KEY ve admin şifresini değiştirmeniz
• Naabu/Subfinder/Nuclei kurup `SCANNER_USE_EXTERNAL_TOOLS=true` yapmanız
• `nuclei -update-templates` ile CVE şablonlarını güncellemeniz
• Ollama ile AI analizini aktifleştirmeniz gerekiyor

Tüm adımlar repoda detaylı: https://github.com/kagannhoo/kurumsall

MIT lisanslı, katkıya açık.

#CyberSecurity #AttackSurface #DevSecOps #OpenSource #FastAPI #Nuclei #InfoSec

---

## Kısa versiyon (story / yorum için)

KurSal: self-hosted attack surface monitor — port/domain/SSL/cloud izleme, Nuclei CVE taraması, diff analizi, AI saldırı senaryoları. Açık kaynak (MIT): https://github.com/kagannhoo/kurumsall

---

## İngilizce versiyon (opsiyonel)

**KurSal — Self-Hosted Attack Surface Monitor**

I built an open-source security platform that monitors your organization's external-facing assets: open ports, domains, SSL certificates, and cloud resources.

It runs daily snapshots, detects changes (diff engine), scores risk, scans for known CVEs with **Nuclei**, and generates AI-powered attack scenarios with actionable remediation plans — all self-hosted, no data leaves your network.

Stack: FastAPI · Celery · PostgreSQL · React · Nuclei · Ollama (optional)

Currently a POC with demo mode (example.com). Production setup requires domain verification, credential hardening, and external scanners (Naabu/Subfinder/Nuclei) with `SCANNER_USE_EXTERNAL_TOOLS=true`.

MIT licensed: https://github.com/kagannhoo/kurumsall

#CyberSecurity #AttackSurface #DevSecOps #OpenSource #Nuclei
