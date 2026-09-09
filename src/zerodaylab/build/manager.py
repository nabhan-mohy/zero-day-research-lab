"""Build manager for targets."""

from pathlib import Path
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from zerodaylab.core.config import Config
from zerodaylab.core.logger import get_logger
from zerodaylab.core.exceptions import BuildError
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Target, TargetBuild
from zerodaylab.build.builders import (
    CMakeBuilder,
    MakeBuilder,
    AutotoolsBuilder,
    MesonBuilder,
    BuildResult,
    BaseBuilder,
)
from zerodaylab.instrumentation.profiles import InstrumentationProfile

logger = get_logger(__name__)


class BuildManager:
    """Manage target builds with multiple build systems and instrumentation."""

    BUILDERS = [CMakeBuilder, MakeBuilder, AutotoolsBuilder, MesonBuilder]

    def __init__(self, config: Config = None):
        """Initialize build manager.

        Args:
            config: Configuration object
        """
        if config is None:
            config = Config()
        self.config = config
        self.db = DatabaseConnection(config.database_path)
        self.db.init_db()

    def detect_build_system(self, project_path: Path) -> Optional[str]:
        """Detect which build system a project uses.

        Args:
            project_path: Path to project

        Returns:
            Build system name or None
        """
        project_path = Path(project_path).resolve()

        for builder_class in self.BUILDERS:
            builder = builder_class(project_path)
            if builder.detect():
                logger.info(f"Detected build system: {builder.name}")
                return builder.name

        return None

    def get_builder(self, project_path: Path) -> Optional[BaseBuilder]:
        """Get appropriate builder for a project.

        Args:
            project_path: Path to project

        Returns:
            Builder instance or None
        """
        project_path = Path(project_path).resolve()

        for builder_class in self.BUILDERS:
            builder = builder_class(project_path)
            if builder.detect():
                return builder

        return None

    def build(
        self,
        target_id: int,
        build_type: str = "normal",
        output_dir: Optional[Path] = None,
        **kwargs,
    ) -> BuildResult:
        """Build a target.

        Args:
            target_id: Target ID
            build_type: Build type (normal, asan, ubsan, etc.)
            output_dir: Output directory for build artifacts
            **kwargs: Additional build arguments

        Returns:
            Build result
        """
        session = self.db.get_session()
        try:
            target = session.query(Target).filter(Target.id == target_id).first()
            if not target:
                raise BuildError(f"Target {target_id} not found")

            target_path = Path(target.path)
            if not target_path.exists():
                raise BuildError(f"Target path does not exist: {target_path}")

            # Get builder
            builder = self.get_builder(target_path)
            if not builder:
                raise BuildError(f"No supported build system found for {target_path}")

            logger.info(
                f"Building target {target.name} with {builder.name} ({build_type})"
            )

            # Set up output directory
            if output_dir is None:
                output_dir = Path(self.config.storage_path) / f"builds" / f"target_{target_id}"
            output_dir = Path(output_dir).resolve()
            output_dir.mkdir(parents=True, exist_ok=True)

            build_dir = output_dir / f"build_{build_type}"

            # Get instrumentation profile if needed
            env = kwargs.get("env", {}).copy() if "env" in kwargs else {}
            if build_type != "normal":
                profile = InstrumentationProfile(build_type)
                env.update(profile.get_compiler_flags())

            # Configure
            config_result = builder.configure(build_dir, **kwargs)
            if not config_result.success:
                logger.error(f"Configure failed: {config_result.stderr}")
                raise BuildError(f"Configure failed: {config_result.stderr}")

            # Build
            build_result = builder.build(build_dir, **kwargs)
            if not build_result.success:
                logger.error(f"Build failed: {build_result.stderr}")
                raise BuildError(f"Build failed: {build_result.stderr}")

            logger.info(f"Build succeeded in {build_result.duration:.2f}s")

            # Store build result in database
            target_build = TargetBuild(
                target_id=target_id,
                build_type=build_type,
                path=str(build_dir),
                compiler=builder.name,
                flags=" ".join(kwargs.get("flags", [])),
                success=True,
            )
            session.add(target_build)
            session.commit()

            return build_result

        except BuildError:
            raise
        except Exception as e:
            logger.error(f"Build failed: {e}")
            raise BuildError(f"Build failed: {e}")
        finally:
            session.close()

    def clean(
        self,
        target_id: int,
        build_type: str = "normal",
        output_dir: Optional[Path] = None,
    ) -> BuildResult:
        """Clean a target build.

        Args:
            target_id: Target ID
            build_type: Build type
            output_dir: Output directory

        Returns:
            Clean result
        """
        session = self.db.get_session()
        try:
            target = session.query(Target).filter(Target.id == target_id).first()
            if not target:
                raise BuildError(f"Target {target_id} not found")

            target_path = Path(target.path)
            builder = self.get_builder(target_path)
            if not builder:
                raise BuildError(f"No supported build system found")

            if output_dir is None:
                output_dir = Path(self.config.storage_path) / f"builds" / f"target_{target_id}"

            build_dir = Path(output_dir) / f"build_{build_type}"

            logger.info(f"Cleaning build {build_type} for target {target.name}")
            return builder.clean(build_dir)

        finally:
            session.close()

    def rebuild(
        self,
        target_id: int,
        build_type: str = "normal",
        output_dir: Optional[Path] = None,
        **kwargs,
    ) -> BuildResult:
        """Rebuild a target.

        Args:
            target_id: Target ID
            build_type: Build type
            output_dir: Output directory
            **kwargs: Build arguments

        Returns:
            Build result
        """
        # Clean first
        self.clean(target_id, build_type, output_dir)
        # Then build
        return self.build(target_id, build_type, output_dir, **kwargs)

    def validate_build(self, build_dir: Path) -> bool:
        """Validate that a build was successful.

        Args:
            build_dir: Build directory

        Returns:
            True if build artifacts exist
        """
        build_dir = Path(build_dir)
        if not build_dir.exists():
            return False

        # Look for common output files
        for pattern in ["*.a", "*.so", "*.o", "bin/*", "lib/*"]:
            if list(build_dir.glob(f"**/{pattern}")):
                return True

        return False
