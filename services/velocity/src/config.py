"""
Configuration settings for the Velocity Service.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for Velocity Service loaded from environment or defaults."""
    SERVICE_NAME: str = "service-velocity"
    HOST: str = "0.0.0.0"
    PORT: int = 8003
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_SOCKET_TIMEOUT: float = 0.5
    REDIS_CONNECT_TIMEOUT: float = 0.5
    REDIS_OPERATION_TIMEOUT: float = 0.5
    IP_WINDOW_SECONDS: int = 60
    PHONE_WINDOW_SECONDS: int = 300
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
