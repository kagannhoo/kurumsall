from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "KurSal"
    app_version: str = "0.1.0"
    debug: bool = False
    api_prefix: str = "/api/v1"

    database_url: str = "postgresql+asyncpg://asm:asm@localhost:5432/asm"
    database_url_sync: str = "postgresql://asm:asm@localhost:5432/asm"

    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    scan_schedule_cron: str = "0 0 * * *"
    scan_timeout_seconds: int = 3600
    snapshot_retention_days: int = 90

    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ai_enabled: bool = True

    nvd_api_key: str = ""
    alert_slack_webhook: str = ""
    alert_email_from: str = ""
    alert_email_to: str = ""

    scanner_naabu_path: str = "naabu"
    scanner_subfinder_path: str = "subfinder"
    scanner_nuclei_path: str = "nuclei"
    scanner_nuclei_severity: str = "critical,high,medium"
    scanner_nuclei_tags: str = "cve"
    scanner_nuclei_timeout: int = 900
    scanner_use_external_tools: bool = True

    secret_key: str = "change-me-in-production-use-openssl-rand"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24

    auth_enabled: bool = True
    api_key: str = ""
    admin_email: str = "admin@local"
    admin_password: str = "admin123"

    require_domain_verification: bool = True
    ollama_health_cache_seconds: int = 30

    demo_mode: bool = True
    scan_cooldown_seconds: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
