"""Configuration management for Zero-Day Research Lab."""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from zerodaylab.core.exceptions import ConfigurationError


class Config:
    """Application configuration from environment variables and defaults."""

    def __init__(self, env_file: Optional[str] = None):
        """Initialize configuration.

        Args:
            env_file: Path to .env file to load
        """
        if env_file and Path(env_file).exists():
            load_dotenv(env_file)
        elif Path(".env").exists():
            load_dotenv(".env")

        self._validate()

    def _validate(self):
        """Validate configuration."""
        # Basic validation - can be extended
        pass

    @property
    def workspace_path(self) -> Path:
        """Get workspace path."""
        path = Path(os.getenv("ZERODAYLAB_WORKSPACE", "./workspace"))
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def storage_path(self) -> Path:
        """Get storage path."""
        path = Path(os.getenv("ZERODAYLAB_STORAGE_PATH", str(self.workspace_path / "storage")))
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def logs_path(self) -> Path:
        """Get logs path."""
        path = Path(os.getenv("ZERODAYLAB_LOG_FILE", "./logs/zerodaylab.log")).parent
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def database_path(self) -> Path:
        """Get database path."""
        path = Path(os.getenv("ZERODAYLAB_DATABASE_PATH", str(self.workspace_path / "zerodaylab.db")))
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def log_level(self) -> str:
        """Get log level."""
        return os.getenv("ZERODAYLAB_LOG_LEVEL", "INFO")

    @property
    def default_timeout(self) -> int:
        """Get default timeout in seconds."""
        try:
            return int(os.getenv("ZERODAYLAB_DEFAULT_TIMEOUT", "5"))
        except ValueError:
            raise ConfigurationError("ZERODAYLAB_DEFAULT_TIMEOUT must be an integer")

    @property
    def default_memory_limit(self) -> int:
        """Get default memory limit in MB."""
        try:
            return int(os.getenv("ZERODAYLAB_DEFAULT_MEMORY_LIMIT", "2048"))
        except ValueError:
            raise ConfigurationError("ZERODAYLAB_DEFAULT_MEMORY_LIMIT must be an integer")

    @property
    def default_workers(self) -> int:
        """Get default number of workers."""
        try:
            return int(os.getenv("ZERODAYLAB_DEFAULT_WORKERS", "4"))
        except ValueError:
            raise ConfigurationError("ZERODAYLAB_DEFAULT_WORKERS must be an integer")

    @property
    def max_input_size(self) -> int:
        """Get maximum input size in bytes."""
        try:
            return int(os.getenv("ZERODAYLAB_MAX_INPUT_SIZE", "65536"))
        except ValueError:
            raise ConfigurationError("ZERODAYLAB_MAX_INPUT_SIZE must be an integer")

    @property
    def asan_enabled(self) -> bool:
        """Check if ASan is enabled."""
        return os.getenv("ZERODAYLAB_ASAN_ENABLED", "true").lower() == "true"

    @property
    def ubsan_enabled(self) -> bool:
        """Check if UBSan is enabled."""
        return os.getenv("ZERODAYLAB_UBSAN_ENABLED", "true").lower() == "true"

    @property
    def lsan_enabled(self) -> bool:
        """Check if LSan is enabled."""
        return os.getenv("ZERODAYLAB_LSAN_ENABLED", "true").lower() == "true"

    @property
    def msan_enabled(self) -> bool:
        """Check if MSan is enabled."""
        return os.getenv("ZERODAYLAB_MSAN_ENABLED", "false").lower() == "true"

    @property
    def enable_sandbox(self) -> bool:
        """Check if sandbox is enabled."""
        return os.getenv("ZERODAYLAB_ENABLE_SANDBOX", "false").lower() == "true"

    @property
    def enable_docker(self) -> bool:
        """Check if Docker is enabled."""
        return os.getenv("ZERODAYLAB_ENABLE_DOCKER", "false").lower() == "true"

    @property
    def backup_path(self) -> Path:
        """Get backup path."""
        path = Path(os.getenv("ZERODAYLAB_DATABASE_BACKUP_PATH", str(self.workspace_path / "backups")))
        path.mkdir(parents=True, exist_ok=True)
        return path
