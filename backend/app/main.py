from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.auth_routes import router as auth_router
from app.api.routes import router
from app.config import get_settings
from app.core.bootstrap import ensure_admin_user
from app.core.metrics import PrometheusMiddleware, metrics_response

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ]
)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await ensure_admin_user()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "**KurSal** — Kurumsal Saldırı Yüzeyi İzleme Platformu\n\n"
        "Port, domain, SSL ve cloud varlıklarını izler; risk skorlar; "
        "AI destekli saldırı senaryoları üretir.\n\n"
        "> ⚠️ **Yasal uyarı:** Bu araç yalnızca yetkili sistemlerde kullanılabilir. "
        "İzinsiz tarama TCK 243–245 kapsamında suçtur.\n\n"
        "Yazar: [kagannhoo](https://github.com/kagannhoo) · "
        "Lisans: MIT · "
        "Kaynak: [github.com/kagannhoo/kurumsall](https://github.com/kagannhoo/kurumsall)"
    ),
    contact={"name": "kagannhoo", "url": "https://github.com/kagannhoo/kurumsall"},
    license_info={"name": "MIT", "url": "https://github.com/kagannhoo/kurumsall/blob/main/LICENSE"},
    lifespan=lifespan,
)

app.add_middleware(PrometheusMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5180",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5180",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix=settings.api_prefix)
app.include_router(router, prefix=settings.api_prefix)


def _health_payload() -> dict:
    return {"status": "ok", "version": settings.app_version, "service": settings.app_name}


def _health_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <title>{settings.app_name} — Health</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0f1117; color: #e6edf3; padding: 2rem; }}
    .card {{ max-width: 480px; background: #161b22; border: 1px solid #2d333b; border-radius: 12px; padding: 1.5rem; }}
    .ok {{ color: #3fb950; font-size: 1.5rem; margin: 0 0 1rem; }}
    a {{ color: #58a6ff; }}
    code {{ background: #1c2333; padding: 0.2rem 0.4rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <div class="card">
    <p class="ok">● Sistem çalışıyor</p>
    <p><strong>{settings.app_name}</strong> v{settings.app_version}</p>
    <p>JSON: <code>GET /health</code> + <code>Accept: application/json</code></p>
    <p><a href="/docs">Swagger UI →</a></p>
    <p><a href="http://localhost:5173">Dashboard →</a></p>
  </div>
</body>
</html>"""


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "status": "ok",
        "version": settings.app_version,
        "health": "/health",
        "docs": "/docs",
        "api": settings.api_prefix,
    }


@app.get("/health")
async def health(request: Request):
    accept = request.headers.get("accept", "")
    # Tarayıcılar genelde text/html ister — boş sayfa yerine okunabilir HTML döndür
    if "text/html" in accept and "application/json" not in accept:
        return HTMLResponse(_health_html())
    return JSONResponse(_health_payload())


@app.get("/metrics")
async def metrics():
    return metrics_response()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    structlog.get_logger().exception("unhandled_error", path=str(request.url.path))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

