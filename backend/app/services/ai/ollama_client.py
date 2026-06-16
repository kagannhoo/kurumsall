"""Ollama bağlantı ve chat istemcisi."""

from __future__ import annotations

import json
import time

import httpx
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()


class OllamaClient:
    def __init__(self) -> None:
        self._health_cache: dict | None = None
        self._health_cache_at: float = 0.0

    async def health(self) -> dict:
        ttl = settings.ollama_health_cache_seconds
        now = time.monotonic()
        if self._health_cache is not None and (now - self._health_cache_at) < ttl:
            return self._health_cache

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{settings.ollama_base_url}/api/tags")
                response.raise_for_status()
                data = response.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                configured = settings.ollama_model
                model_ready = any(configured in m or m.startswith(configured) for m in models)
                result = {
                    "connected": True,
                    "base_url": settings.ollama_base_url,
                    "models": models,
                    "configured_model": configured,
                    "model_ready": model_ready,
                }
        except Exception as exc:
            logger.debug("ollama_health_failed", error=str(exc))
            result = {
                "connected": False,
                "base_url": settings.ollama_base_url,
                "models": [],
                "configured_model": settings.ollama_model,
                "model_ready": False,
                "error": str(exc),
            }

        self._health_cache = result
        self._health_cache_at = now
        return result

    async def chat_json(self, system: str, user: str) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                response = await client.post(
                    f"{settings.ollama_base_url}/api/chat",
                    json={
                        "model": settings.ollama_model,
                        "stream": False,
                        "format": "json",
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "options": {"temperature": 0.2, "num_predict": 2048},
                    },
                )
                response.raise_for_status()
                content = response.json().get("message", {}).get("content", "").strip()
                if not content:
                    return None
                return json.loads(content)
        except Exception as exc:
            logger.warning("ollama_chat_failed", error=str(exc))
            return None
