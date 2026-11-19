from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    app_name: str = "The Guardian Integration Gateway"
    app_version: str = "1.0.0"

    # Base64-encoded 32-byte key for AES-256-GCM audit encryption.
    # Default value is strictly for local/demo convenience; override in production.
    encryption_key: str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

    audit_log_path: str = "data/audit_log.json"
    mock_ai_delay_seconds: float = 2.0

    cb_failure_threshold: int = 3
    cb_recovery_timeout_seconds: float = 30.0

    spacy_model_name: str = "en_core_web_sm"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
