"""Path validation for security."""

import os
from pathlib import Path
from typing import Optional
from zerodaylab.core.exceptions import SecurityError
from zerodaylab.core.logger import get_logger

logger = get_logger(__name__)


class PathValidator:
    """Validates paths for security and consistency."""

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize path validator.

        Args:
            project_root: Root path for project (used for path traversal checks)
        """
        self.project_root = project_root

    def validate_read_path(self, path: Path, check_exists: bool = True) -> Path:
        """Validate a path for reading.

        Args:
            path: Path to validate
            check_exists: Whether to check path exists

        Returns:
            Validated absolute path

        Raises:
            SecurityError: If path is invalid
        """
        try:
            # Convert to absolute path
            abs_path = Path(path).resolve()

            # Check for path traversal if project_root is set
            if self.project_root:
                project_abs = Path(self.project_root).resolve()
                try:
                    abs_path.relative_to(project_abs)
                except ValueError:
                    raise SecurityError(
                        f"Path traversal detected: {path} escapes project root"
                    )

            # Check if path exists (if required)
            if check_exists and not abs_path.exists():
                raise SecurityError(f"Path does not exist: {abs_path}")

            # Check if readable
            if abs_path.exists() and not os.access(abs_path, os.R_OK):
                raise SecurityError(f"Path is not readable: {abs_path}")

            logger.debug(f"Validated read path: {abs_path}")
            return abs_path

        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError(f"Path validation failed: {e}")

    def validate_write_path(self, path: Path, allow_create: bool = True) -> Path:
        """Validate a path for writing.

        Args:
            path: Path to validate
            allow_create: Whether to allow creating parent directories

        Returns:
            Validated absolute path

        Raises:
            SecurityError: If path is invalid
        """
        try:
            # Convert to absolute path
            abs_path = Path(path).resolve()

            # Check for path traversal if project_root is set
            if self.project_root:
                project_abs = Path(self.project_root).resolve()
                try:
                    abs_path.relative_to(project_abs)
                except ValueError:
                    raise SecurityError(
                        f"Path traversal detected: {path} escapes project root"
                    )

            # Check parent directory permissions
            parent = abs_path.parent
            if parent.exists():
                if not os.access(parent, os.W_OK):
                    raise SecurityError(f"Parent directory not writable: {parent}")
            elif allow_create:
                parent.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created parent directories: {parent}")
            else:
                raise SecurityError(f"Parent directory does not exist: {parent}")

            logger.debug(f"Validated write path: {abs_path}")
            return abs_path

        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError(f"Path validation failed: {e}")

    def validate_executable_path(self, path: Path) -> Path:
        """Validate a path is an executable.

        Args:
            path: Path to validate

        Returns:
            Validated absolute path

        Raises:
            SecurityError: If path is not executable
        """
        try:
            abs_path = self.validate_read_path(path, check_exists=True)

            if not os.access(abs_path, os.X_OK):
                raise SecurityError(f"Path is not executable: {abs_path}")

            logger.debug(f"Validated executable path: {abs_path}")
            return abs_path

        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError(f"Executable path validation failed: {e}")
