"""
Configuration settings for the Alerting Service.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for Alerting Service loaded from environment or defaults."""
    SERVICE_NAME: str = "service-alerting"
    HOST: str = "0.0.0.0"
    PORT: int = 8006

    # SQLite local audit storage path
    SQLITE_DB_PATH: str = "./alerts_audit.db"
    DEFAULT_ALERTS_LIMIT: int = 50
    MAX_ALERTS_LIMIT: int = 100

    # Alert triggering policy
    CRITICAL_RISK_THRESHOLD: float = 80.0

    # RabbitMQ consumer settings
    RABBITMQ_URL: str = "amqp://guest:guest@localhost:5672/"
    RABBITMQ_EXCHANGE: str = "antifraud.events"
    RABBITMQ_QUEUE: str = "security.alerts"
    RABBITMQ_ROUTING_KEY: str = "inspection.completed"
    RABBITMQ_ALERT_ROUTING_KEY: str = "alert.#"
    RABBITMQ_PREFETCH_COUNT: int = 50
    RABBITMQ_CONNECT_TIMEOUT: float = 3.0

    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
