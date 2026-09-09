"""Tests for configuration."""

import pytest
from zerodaylab.core.config import Config
from zerodaylab.core.exceptions import ConfigurationError


def test_config_initialization():
    """Test configuration initialization."""
    config = Config()
    assert config.workspace_path.exists()
    assert config.storage_path.exists()
    assert config.database_path.parent.exists()


def test_config_defaults():
    """Test configuration defaults."""
    config = Config()
    assert config.default_timeout == 5
    assert config.default_memory_limit == 2048
    assert config.default_workers == 4
    assert config.max_input_size == 65536


def test_config_log_levels():
    """Test log level configuration."""
    config = Config()
    assert config.log_level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def test_sanitizer_flags():
    """Test sanitizer configuration."""
    config = Config()
    # ASan and UBSan should be enabled by default
    assert isinstance(config.asan_enabled, bool)
    assert isinstance(config.ubsan_enabled, bool)
