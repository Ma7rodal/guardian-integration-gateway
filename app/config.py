from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DEMO_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


class Settings(BaseSettings):
    """Application settings loaded from environment variables with fail-safe guards."""

    app_name: str = "The Guardian Integration Gateway"
    app_version: str = "1.0.0"

    environment: Literal["development", "staging", "production"] = "development"
    allow_failure_simulation: bool = True

    # Base64-encoded 32-byte key for AES-256-GCM audit encryption.
    # Default value is strictly for local/demo convenience; blocked in production.
    encryption_key: str = DEFAULT_DEMO_ENCRYPTION_KEY

    audit_log_path: str = "data/audit_log.jsonl"
    mock_ai_delay_seconds: float = 2.0

    cb_failure_threshold: int = 3
    cb_recovery_timeout_seconds: float = 30.0

    spacy_model_name: str = "en_core_web_sm"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        if (
            self.environment == "production"
            and self.encryption_key == DEFAULT_DEMO_ENCRYPTION_KEY
        ):
            raise ValueError(
                "ENCRYPTION_KEY must be explicitly overridden in production; "
                "default demo key is forbidden."
            )
        return self

    @property
    def can_simulate_failures(self) -> bool:
        """Never honor X-Simulate-Failure in production environments."""
        return self.allow_failure_simulation and self.environment != "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
