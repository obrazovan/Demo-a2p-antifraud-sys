"""
Configuration settings for the Analytics Ingestion Service.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for Analytics Service loaded from environment or defaults."""
    SERVICE_NAME: str = "service-analytics"
    HOST: str = "0.0.0.0"
    PORT: int = 8005

    # ClickHouse OLAP settings
    CLICKHOUSE_HOST: str = "localhost"
    CLICKHOUSE_PORT: int = 8123
    CLICKHOUSE_DB: str = "analytics_db"
    CLICKHOUSE_USER: str = "default"
    CLICKHOUSE_PASSWORD: str = "clickhousepassword"
    CLICKHOUSE_CONNECT_TIMEOUT: float = 3.0
    CLICKHOUSE_SEND_RECEIVE_TIMEOUT: float = 5.0

    # RabbitMQ consumer settings
    RABBITMQ_URL: str = "amqp://guest:guest@localhost:5672/"
    RABBITMQ_EXCHANGE: str = "antifraud.events"
    RABBITMQ_QUEUE: str = "analytics.raw_events"
    RABBITMQ_ROUTING_KEY: str = "inspection.completed"
    RABBITMQ_PREFETCH_COUNT: int = 100
    RABBITMQ_CONNECT_TIMEOUT: float = 3.0

    # Batch ingestion parameters
    BATCH_SIZE: int = 50
    FLUSH_INTERVAL_SECONDS: float = 2.0

    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
