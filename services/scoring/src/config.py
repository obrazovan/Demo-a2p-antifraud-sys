"""
Configuration settings for the Scoring Service.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or defaults."""
    SERVICE_NAME: str = "service-scoring"
    HOST: str = "0.0.0.0"
    PORT: int = 8004

    # Downstream microservice base URLs
    RULE_ENGINE_URL: str = "http://localhost:8001"
    REPUTATION_URL: str = "http://localhost:8002"
    VELOCITY_URL: str = "http://localhost:8003"

    # HTTP client performance and caching settings
    HTTP_CONNECT_TIMEOUT: float = 0.3
    HTTP_READ_TIMEOUT: float = 0.8
    RULES_CACHE_TTL_SECONDS: float = 30.0

    # Risk evaluation policy
    DENY_THRESHOLD: float = 60.0

    # RabbitMQ broker settings
    RABBITMQ_URL: str = "amqp://guest:guest@localhost:5672/"
    RABBITMQ_EXCHANGE: str = "antifraud.events"
    RABBITMQ_ROUTING_KEY: str = "inspection.completed"
    RABBITMQ_CONNECT_TIMEOUT: float = 3.0
    RABBITMQ_PUBLISH_TIMEOUT: float = 0.5

    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
