import time

from prometheus_client import Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

HTTP_REQUESTS = Counter(
    "asm_http_requests_total",
    "Toplam HTTP istekleri",
    ["method", "path", "status"],
)
HTTP_LATENCY = Histogram(
    "asm_http_request_duration_seconds",
    "HTTP istek süresi",
    ["method", "path"],
)
SCAN_TOTAL = Counter("asm_scans_total", "Tamamlanan taramalar", ["status"])
SCAN_DURATION = Histogram("asm_scan_duration_seconds", "Tarama süresi")


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == "/metrics":
            return await call_next(request)
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        path = request.url.path
        if len(path) > 80:
            path = path[:80]
        HTTP_REQUESTS.labels(request.method, path, response.status_code).inc()
        HTTP_LATENCY.labels(request.method, path).observe(duration)
        return response


def metrics_response() -> Response:
    return Response(generate_latest(), media_type="text/plain; version=0.0.4; charset=utf-8")
