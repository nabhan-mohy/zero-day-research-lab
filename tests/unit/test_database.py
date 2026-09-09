"""Tests for database."""

import pytest
from pathlib import Path
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Project


def test_database_connection(test_db):
    """Test database connection."""
    assert test_db.database_path.exists()
    session = test_db.get_session()
    assert session is not None
    session.close()


def test_project_model(test_db):
    """Test project model."""
    session = test_db.get_session()
    try:
        project = Project(name="test_project", description="Test project")
        session.add(project)
        session.commit()

        retrieved = session.query(Project).filter(Project.name == "test_project").first()
        assert retrieved is not None
        assert retrieved.name == "test_project"
    finally:
        session.close()
