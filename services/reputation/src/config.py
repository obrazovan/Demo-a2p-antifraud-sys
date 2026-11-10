"""
Configuration settings for the Reputation Service.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application runtime settings loaded from environment or defaults."""
    SERVICE_NAME: str = "service-reputation"
    HOST: str = "0.0.0.0"
    PORT: int = 8002
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgrespassword@localhost:5433/reputation_db"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_PRE_PING: bool = True
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
