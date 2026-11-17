"""
Configuration settings for the API Gateway.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for API Gateway loaded from environment or defaults."""
    SERVICE_NAME: str = "antifraud-gateway"
    HOST: str = "0.0.0.0"
    PORT: int = 8080

    # Downstream internal microservice base URLs
    SCORING_URL: str = "http://localhost:8004"
    ANALYTICS_URL: str = "http://localhost:8005"
    RULE_ENGINE_URL: str = "http://localhost:8001"
    REPUTATION_URL: str = "http://localhost:8002"
    ALERTING_URL: str = "http://localhost:8006"

    # Authentication credentials (comma-separated API keys + Basic Auth fallback)
    API_KEYS: str = "antifraud-demo-key,dev-bearer-token"
    BASIC_AUTH_USERNAME: str = "antifraud"
    BASIC_AUTH_PASSWORD: str = "antifraud-secret"

    # Reverse proxy HTTP timeouts
    PROXY_CONNECT_TIMEOUT: float = 1.0
    PROXY_READ_TIMEOUT: float = 5.0
    READY_CHECK_TIMEOUT: float = 0.5

    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def valid_api_keys(self) -> list[str]:
        return [key.strip() for key in self.API_KEYS.split(",") if key.strip()]


settings = Settings()
