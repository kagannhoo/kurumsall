# Contributing

Katkıda bulunmak isteyenler için kısa rehber.

## Kurulum

```bash
# Repo'yu fork'la, sonra:
git clone https://github.com/kagannhoo/kurumsall
cd kurumsall
cp .env.example .env
docker compose up -d postgres redis
docker compose run --rm api alembic upgrade head
docker compose up -d
```

## Geliştirme ortamı

```bash
# Backend (hot-reload)
cd backend
python -m venv .venv
.venv/Scripts/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env     # backend/.env ayarlarını düzenle
uvicorn app.main:app --reload

# Frontend (hot-reload)
cd frontend
npm install
npm run dev
```

## Testler

```bash
cd backend
python -m pytest tests/ -q
```

## Kod standartları

- Python: `ruff` (linting), `black` (format)
- TypeScript: `eslint`
- Commit mesajları: `feat:`, `fix:`, `docs:`, `refactor:` önekleri

## PR kuralları

1. `main` yerine `develop` branch'ine açın
2. Test coverage düşürmeyin
3. Yeni scanner veya threat rule eklerken `tests/` altına test yazın
4. PR açıklamasına "ne değiştirdi, neden" ekleyin

## Mimari kararlar

Büyük mimari değişiklikler için önce bir issue açın — tartışma sonrası PR açmak daha verimli.
