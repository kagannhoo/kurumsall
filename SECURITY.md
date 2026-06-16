# Güvenlik Politikası

## Yasal kullanım sınırları

**KurSal yalnızca yetkili olduğunuz sistemlerde kullanılabilir.**

Aşağıdaki durumlar **yasaldır:**
- Kendi sahip olduğunuz altyapı (sunucular, domainler, cloud hesapları)
- Yazılı izin aldığınız müşteri veya işveren sistemleri
- Penetrasyon testi sözleşmesi kapsamındaki hedefler
- Kendi kurduğunuz test ortamları (lab, sandbox)

Aşağıdaki durumlar **yasadışıdır:**
- İzinsiz üçüncü taraf sistemleri taramak
- Elde edilen bilgileri yetkisiz erişim için kullanmak
- Sonuçları zararlı amaçlarla paylaşmak

### Türkiye

- **TCK Madde 243** — Bilişim sistemine girme: 1–3 yıl hapis
- **TCK Madde 244** — Sistemi engelleme, bozma, verileri yok etme: 1–5 yıl hapis
- **TCK Madde 245** — Banka veya kredi kartı bilgilerini ele geçirme: 3–7 yıl hapis
- **5651 Sayılı Kanun** — İnternet ortamında yapılan yayınlar

### Uluslararası

- AB: NIS2 Direktifi, GDPR
- ABD: Computer Fraud and Abuse Act (CFAA)
- İngiltere: Computer Misuse Act

---

## Güvenlik açığı bildirimi

Bu projede bir güvenlik açığı bulduysanız lütfen **kamuya açıklamadan önce** bildirin:

1. GitHub üzerinden [Security Advisory](https://github.com/kagannhoo/kurumsall/security/advisories/new) oluşturun
2. Açıklama, etki ve (varsa) PoC bilgisi ekleyin
3. 90 gün içinde yanıt alamamanız durumunda kamuoyuyla paylaşabilirsiniz

Responsible disclosure ilkesine uyulduğu sürece yasal işlem başlatılmayacaktır.

---

## Kapsam dışı

Aşağıdakiler güvenlik açığı olarak değerlendirilmez:

- Sosyal mühendislik saldırıları
- Fiziksel erişim gerektiren senaryolar
- Test ortamlarındaki demo kimlik bilgileri (admin123) — production'da değiştirilmesi kullanıcının sorumluluğundadır
