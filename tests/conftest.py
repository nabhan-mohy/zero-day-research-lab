"""Pytest configuration and fixtures."""

import pytest
import tempfile
from pathlib import Path
from zerodaylab.core.config import Config
from zerodaylab.database.connection import DatabaseConnection


@pytest.fixture
def temp_workspace():
    """Create temporary workspace."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_config(temp_workspace):
    """Create test configuration."""
    config = Config()
    # Override paths for testing
    return config


@pytest.fixture
def test_db(temp_workspace):
    """Create test database."""
    db_path = temp_workspace / "test.db"
    db = DatabaseConnection(db_path)
    db.init_db()
    yield db
    db.close()
