"""Application configuration management using Pydantic Settings.

Reads environment variables safely without hard-coding secrets.
"""

from pathlib import Path
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Centralized configuration for the URL Detection System backend."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        protected_namespaces=(),
    )

    app_name: str = Field(default="Suspicious Website / Malicious URL Detection System")
    app_env: str = Field(default="development")
    app_version: str = Field(default="1.0.0")
    developer_name: str = Field(default="Anil Biradar")

    backend_host: str = Field(default="127.0.0.1")
    backend_port: int = Field(default=8010)
    cors_origins: str = Field(default="http://localhost:5173,http://127.0.0.1:5173")

    max_url_length: int = Field(default=2048, ge=64, le=8192)
    max_request_bytes: int = Field(default=16384, ge=1024, le=1048576)
    rate_limit_requests: int = Field(default=60, ge=1, le=10000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)

    enable_history: bool = Field(default=True)
    database_url: str = Field(default=f"sqlite:///{(PROJECT_ROOT / 'url_analysis.db').as_posix()}")
    store_raw_url_in_history: bool = Field(default=True)

    model_artefact_path: str = Field(
        default=str(PROJECT_ROOT / "backend" / "app" / "ml" / "artefacts" / "url_model_v1.joblib")
    )
    allow_fallback_mode: bool = Field(default=True)

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()
