"""Target management."""

from pathlib import Path
from sqlalchemy.orm import Session
from zerodaylab.core.config import Config
from zerodaylab.core.logger import get_logger
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Target, Project
from zerodaylab.core.exceptions import TargetError, ZeroDayLabError
from zerodaylab.security.path_validator import PathValidator
from datetime import datetime

logger = get_logger(__name__)


class TargetManager:
    """Manage targets for projects."""

    def __init__(self, config: Config = None):
        """Initialize target manager.

        Args:
            config: Configuration object
        """
        if config is None:
            config = Config()
        self.config = config
        self.db = DatabaseConnection(config.database_path)
        self.db.init_db()
        self.path_validator = PathValidator()

    def add_target(
        self,
        project_name: str,
        target_name: str,
        target_path: Path,
        target_type: str = "library",
        description: str = "",
    ) -> Target:
        """Add a target to a project.

        Args:
            project_name: Name of the project
            target_name: Name of the target
            target_path: Path to target source/binary
            target_type: Type (library, binary, harness)
            description: Target description

        Returns:
            Created target

        Raises:
            TargetError: If target addition fails
        """
        session = self.db.get_session()
        try:
            # Get project
            project = session.query(Project).filter(Project.name == project_name).first()
            if not project:
                raise TargetError(f"Project '{project_name}' not found")

            # Validate target path
            validated_path = self.path_validator.validate_read_path(target_path, check_exists=True)

            # Check if target already exists in project
            existing = (
                session.query(Target)
                .filter(
                    Target.project_id == project.id,
                    Target.name == target_name,
                )
                .first()
            )
            if existing:
                raise TargetError(
                    f"Target '{target_name}' already exists in project '{project_name}'"
                )

            # Create target
            target = Target(
                project_id=project.id,
                name=target_name,
                description=description,
                path=str(validated_path),
                type=target_type,
            )
            session.add(target)
            session.commit()
            logger.info(f"Added target: {target_name} to project: {project_name}")
            return target

        except TargetError:
            raise
        except Exception as e:
            logger.error(f"Failed to add target: {e}")
            raise TargetError(f"Failed to add target: {e}")
        finally:
            session.close()

    def get_target(self, project_name: str, target_name: str) -> Target:
        """Get a target by name.

        Args:
            project_name: Name of the project
            target_name: Name of the target

        Returns:
            Target or None
        """
        session = self.db.get_session()
        try:
            project = session.query(Project).filter(Project.name == project_name).first()
            if not project:
                return None
            return (
                session.query(Target)
                .filter(
                    Target.project_id == project.id,
                    Target.name == target_name,
                )
                .first()
            )
        finally:
            session.close()

    def list_targets(self, project_name: str) -> list:
        """List all targets in a project.

        Args:
            project_name: Name of the project

        Returns:
            List of targets
        """
        session = self.db.get_session()
        try:
            project = session.query(Project).filter(Project.name == project_name).first()
            if not project:
                return []
            return session.query(Target).filter(Target.project_id == project.id).all()
        finally:
            session.close()

    def delete_target(self, project_name: str, target_name: str) -> bool:
        """Delete a target.

        Args:
            project_name: Name of the project
            target_name: Name of the target

        Returns:
            True if deleted
        """
        session = self.db.get_session()
        try:
            project = session.query(Project).filter(Project.name == project_name).first()
            if not project:
                raise TargetError(f"Project '{project_name}' not found")

            target = (
                session.query(Target)
                .filter(
                    Target.project_id == project.id,
                    Target.name == target_name,
                )
                .first()
            )
            if not target:
                raise TargetError(
                    f"Target '{target_name}' not found in project '{project_name}'"
                )

            session.delete(target)
            session.commit()
            logger.info(f"Deleted target: {target_name} from project: {project_name}")
            return True
        finally:
            session.close()
