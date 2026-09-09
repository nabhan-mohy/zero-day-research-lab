"""Project manager."""

from pathlib import Path
from sqlalchemy.orm import Session
from zerodaylab.core.config import Config
from zerodaylab.core.logger import get_logger
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Project, Target
from zerodaylab.core.exceptions import ZeroDayLabError
from datetime import datetime

logger = get_logger(__name__)


class ProjectManager:
    """Manage projects."""

    def __init__(self, config: Config = None):
        """Initialize project manager.

        Args:
            config: Configuration object
        """
        if config is None:
            config = Config()
        self.config = config
        self.db = DatabaseConnection(config.database_path)
        self.db.init_db()

    def create_project(self, name: str, description: str = "") -> Project:
        """Create a new project.

        Args:
            name: Project name
            description: Project description

        Returns:
            Created project
        """
        session = self.db.get_session()
        try:
            # Check if project already exists
            existing = session.query(Project).filter(Project.name == name).first()
            if existing:
                raise ZeroDayLabError(f"Project '{name}' already exists")

            project = Project(name=name, description=description)
            session.add(project)
            session.commit()
            logger.info(f"Created project: {name}")
            return project
        finally:
            session.close()

    def get_project(self, name: str) -> Project:
        """Get a project by name.

        Args:
            name: Project name

        Returns:
            Project or None
        """
        session = self.db.get_session()
        try:
            return session.query(Project).filter(Project.name == name).first()
        finally:
            session.close()

    def get_project_by_id(self, project_id: int) -> Project:
        """Get a project by ID.

        Args:
            project_id: Project ID

        Returns:
            Project or None
        """
        session = self.db.get_session()
        try:
            return session.query(Project).filter(Project.id == project_id).first()
        finally:
            session.close()

    def list_projects(self) -> list:
        """List all projects.

        Returns:
            List of projects
        """
        session = self.db.get_session()
        try:
            return session.query(Project).all()
        finally:
            session.close()

    def update_project(self, name: str, description: str = None) -> Project:
        """Update a project.

        Args:
            name: Project name
            description: New description (optional)

        Returns:
            Updated project
        """
        session = self.db.get_session()
        try:
            project = session.query(Project).filter(Project.name == name).first()
            if not project:
                raise ZeroDayLabError(f"Project '{name}' not found")

            if description is not None:
                project.description = description
            project.updated_at = datetime.utcnow()
            session.commit()
            logger.info(f"Updated project: {name}")
            return project
        finally:
            session.close()

    def delete_project(self, name: str) -> bool:
        """Delete a project.

        Args:
            name: Project name

        Returns:
            True if deleted
        """
        session = self.db.get_session()
        try:
            project = session.query(Project).filter(Project.name == name).first()
            if not project:
                raise ZeroDayLabError(f"Project '{name}' not found")

            session.delete(project)
            session.commit()
            logger.info(f"Deleted project: {name}")
            return True
        finally:
            session.close()

    def get_project_stats(self, name: str) -> dict:
        """Get project statistics.

        Args:
            name: Project name

        Returns:
            Project statistics
        """
        session = self.db.get_session()
        try:
            project = session.query(Project).filter(Project.name == name).first()
            if not project:
                raise ZeroDayLabError(f"Project '{name}' not found")

            target_count = session.query(Target).filter(Target.project_id == project.id).count()

            return {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "targets": target_count,
                "created_at": project.created_at,
                "updated_at": project.updated_at,
            }
        finally:
            session.close()
