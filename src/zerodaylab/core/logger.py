"""Structured logging for Zero-Day Research Lab."""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional
from zerodaylab.core.config import Config

_loggers = {}
_configured = False


def setup_logging(config: Optional[Config] = None, level: Optional[str] = None) -> None:
    """Set up structured logging.

    Args:
        config: Configuration object
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    global _configured

    if _configured:
        return

    if config is None:
        config = Config()

    if level is None:
        level = config.log_level

    log_level = getattr(logging, level.upper(), logging.INFO)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler
    log_file = Path(config.logs_path) / "zerodaylab.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    if name not in _loggers:
        _loggers[name] = logging.getLogger(name)
    return _loggers[name]
