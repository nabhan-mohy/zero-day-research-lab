"""Integration tests for project workflow."""

import pytest
from pathlib import Path
from zerodaylab.projects.manager import ProjectManager
from zerodaylab.database.connection import DatabaseConnection


def test_create_and_retrieve_project(temp_workspace):
    """Test creating and retrieving a project."""
    db_path = temp_workspace / "test.db"
    db = DatabaseConnection(db_path)
    db.init_db()

    from zerodaylab.projects.manager import ProjectManager
    from zerodaylab.core.config import Config

    config = Config()
    manager = ProjectManager(config)

    # Create project
    project = manager.create_project("integration_test", "Integration test project")
    assert project is not None
    assert project.name == "integration_test"

    # Retrieve project
    retrieved = manager.get_project("integration_test")
    assert retrieved is not None
    assert retrieved.name == "integration_test"

    db.close()
