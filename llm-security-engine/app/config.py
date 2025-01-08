from pydantic_settings import BaseSettings
from pydantic import model_validator
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    # ── Ollama ──────────────────────────────────────────────────────────
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "phi4-mini"
    OLLAMA_TIMEOUT: int = 60

    # ── Service ─────────────────────────────────────────────────────────
    DEBUG: bool = False
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # ── Authentication ───────────────────────────────────────────────────
    # If set, all /analyze-* endpoints require header: X-API-Key: <value>
    # Leave unset (or empty) to disable auth for local development.
    LOCAL_LLM_API_KEY: Optional[str] = None

    # ── Rate Limiting ────────────────────────────────────────────────────
    # Max requests per RATE_LIMIT_WINDOW_SECONDS per client identity.
    # Set RATE_LIMIT_ENABLED=false to disable entirely.
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 60       # max requests per window
    RATE_LIMIT_WINDOW_SECONDS: int = 60 # sliding window size in seconds

    # ── Input Size Limits ────────────────────────────────────────────────
    MAX_DESCRIPTION_LENGTH: int = 4000  # max chars for event description
    MAX_CONTEXT_LENGTH: int = 4000      # max chars for context summary
    MAX_PROMPT_LENGTH: int = 8000       # max chars for raw prompt (debug)
    MAX_FIELD_LENGTH: int = 500         # max chars for optional string fields

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @model_validator(mode="after")
    def _validate_api_key(self) -> "Settings":
        if self.LOCAL_LLM_API_KEY is not None and len(self.LOCAL_LLM_API_KEY.strip()) == 0:
            self.LOCAL_LLM_API_KEY = None
        return self


@lru_cache()
def get_settings() -> Settings:
    return Settings()
