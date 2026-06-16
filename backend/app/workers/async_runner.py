"""Celery worker için kalıcı asyncio event loop — asyncpg loop çakışmasını önler."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import TypeVar

from celery.signals import worker_process_init, worker_process_shutdown

from app.db.session import engine

T = TypeVar("T")

_worker_loop: asyncio.AbstractEventLoop | None = None


def get_worker_loop() -> asyncio.AbstractEventLoop:
    global _worker_loop
    if _worker_loop is None or _worker_loop.is_closed():
        _worker_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_worker_loop)
    return _worker_loop


def run_async(coro: Coroutine[object, object, T]) -> T:
    loop = get_worker_loop()
    return loop.run_until_complete(coro)


@worker_process_init.connect
def _init_worker_loop(**kwargs) -> None:
    loop = get_worker_loop()
    # Fork sonrası parent process bağlantılarını temizle
    loop.run_until_complete(engine.dispose())


@worker_process_shutdown.connect
def _shutdown_worker_loop(**kwargs) -> None:
    global _worker_loop
    if _worker_loop is None or _worker_loop.is_closed():
        return
    try:
        _worker_loop.run_until_complete(engine.dispose())
    finally:
        _worker_loop.close()
        _worker_loop = None
        asyncio.set_event_loop(None)
