"""Project manager."""

from pathlib import Path
from sqlalchemy.orm import Session
from zerodaylab.core.config import Config
from zerodaylab.core.logger import get_logger
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Project
from zerodaylab.core.exceptions import ZeroDayLabError

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
