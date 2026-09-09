"""Build command execution with real subprocess handling."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import subprocess
import time

from zerodaylab.core.logger import get_logger
from zerodaylab.core.exceptions import BuildError
from zerodaylab.security.process_handler import ProcessHandler

logger = get_logger(__name__)


@dataclass
class BuildResult:
    """Result of a build operation."""

    success: bool
    command: List[str]
    cwd: Path
    environment: Dict[str, str]
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timestamp: datetime
    output_path: Optional[Path] = None

    def __str__(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        return (
            f"Build {status}\n"
            f"  Command: {' '.join(str(c) for c in self.command)}\n"
            f"  Exit Code: {self.exit_code}\n"
            f"  Duration: {self.duration:.2f}s\n"
            f"  Working Dir: {self.cwd}"
        )


class BaseBuilder:
    """Base class for build systems."""

    name = "base"
    config_file = None

    def __init__(self, project_path: Path):
        """Initialize builder.

        Args:
            project_path: Path to project
        """
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise BuildError(f"Project path does not exist: {project_path}")

    def detect(self) -> bool:
        """Detect if this build system is used.

        Returns:
            True if detected
        """
        if self.config_file is None:
            return False
        return (self.project_path / self.config_file).exists()

    def configure(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run configure step.

        Args:
            build_dir: Build directory
            **kwargs: Additional arguments

        Returns:
            Build result
        """
        raise NotImplementedError

    def build(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run build step.

        Args:
            build_dir: Build directory
            **kwargs: Additional arguments

        Returns:
            Build result
        """
        raise NotImplementedError

    def clean(self, build_dir: Path) -> BuildResult:
        """Run clean step.

        Args:
            build_dir: Build directory

        Returns:
            Build result
        """
        raise NotImplementedError

    def _execute_build_command(
        self,
        command: List[str],
        cwd: Path,
        env: Optional[Dict[str, str]] = None,
        timeout: int = 600,
    ) -> BuildResult:
        """Execute a build command safely.

        Args:
            command: Command to execute
            cwd: Working directory
            env: Environment variables
            timeout: Timeout in seconds

        Returns:
            Build result
        """
        logger.info(f"Executing build command: {' '.join(str(c) for c in command)}")

        cwd = Path(cwd).resolve()
        if not cwd.exists():
            cwd.mkdir(parents=True, exist_ok=True)

        start_time = time.time()
        timestamp = datetime.utcnow()

        try:
            exit_code, stdout, stderr = ProcessHandler.execute(
                command,
                cwd=cwd,
                env=env,
                timeout=timeout,
                capture_output=True,
            )
            duration = time.time() - start_time
            success = exit_code == 0

            logger.info(f"Build command completed with exit code {exit_code} ({duration:.2f}s)")

            return BuildResult(
                success=success,
                command=command,
                cwd=cwd,
                environment=env or {},
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration=duration,
                timestamp=timestamp,
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Build command failed: {e}")
            raise BuildError(f"Build command failed: {e}")


class CMakeBuilder(BaseBuilder):
    """CMake build system."""

    name = "cmake"
    config_file = "CMakeLists.txt"

    def configure(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run CMake configure."""
        build_dir = Path(build_dir).resolve()
        flags = kwargs.get("flags", [])

        command = ["cmake", "-B", str(build_dir), "-S", str(self.project_path)] + flags

        return self._execute_build_command(command, self.project_path, timeout=300)

    def build(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run CMake build."""
        build_dir = Path(build_dir).resolve()
        jobs = kwargs.get("jobs", 4)

        command = ["cmake", "--build", str(build_dir), f"-j{jobs}"]

        return self._execute_build_command(command, build_dir, timeout=600)

    def clean(self, build_dir: Path) -> BuildResult:
        """Run CMake clean."""
        build_dir = Path(build_dir).resolve()
        command = ["cmake", "--build", str(build_dir), "--target", "clean"]

        return self._execute_build_command(command, build_dir, timeout=300)


class MakeBuilder(BaseBuilder):
    """Make build system."""

    name = "make"
    config_file = "Makefile"

    def configure(self, build_dir: Path, **kwargs) -> BuildResult:
        """Make has no separate configure step."""
        logger.debug("Make has no configure step")
        return BuildResult(
            success=True,
            command=[],
            cwd=self.project_path,
            environment={},
            stdout="",
            stderr="",
            exit_code=0,
            duration=0.0,
            timestamp=datetime.utcnow(),
        )

    def build(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run make build."""
        jobs = kwargs.get("jobs", 4)
        command = ["make", f"-j{jobs}"]

        return self._execute_build_command(command, self.project_path, timeout=600)

    def clean(self, build_dir: Path) -> BuildResult:
        """Run make clean."""
        command = ["make", "clean"]
        return self._execute_build_command(command, self.project_path, timeout=300)


class AutotoolsBuilder(BaseBuilder):
    """Autotools build system."""

    name = "autotools"
    config_file = "configure.ac"

    def configure(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run Autotools configure."""
        build_dir = Path(build_dir).resolve()
        flags = kwargs.get("flags", [])

        # Check if configure script exists
        configure_script = self.project_path / "configure"
        if not configure_script.exists():
            logger.info("configure script not found, attempting to autoreconf")
            try:
                self._execute_build_command(
                    ["autoreconf", "-i"],
                    self.project_path,
                    timeout=300,
                )
            except BuildError:
                logger.warning("autoreconf failed, continuing with configure")

        command = [str(configure_script), f"--prefix={build_dir}"] + flags

        return self._execute_build_command(command, build_dir, timeout=300)

    def build(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run make build."""
        jobs = kwargs.get("jobs", 4)
        command = ["make", f"-j{jobs}"]

        return self._execute_build_command(command, build_dir, timeout=600)

    def clean(self, build_dir: Path) -> BuildResult:
        """Run make clean."""
        command = ["make", "clean"]
        return self._execute_build_command(command, build_dir, timeout=300)


class MesonBuilder(BaseBuilder):
    """Meson build system."""

    name = "meson"
    config_file = "meson.build"

    def configure(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run Meson configure."""
        build_dir = Path(build_dir).resolve()
        flags = kwargs.get("flags", [])

        command = ["meson", "setup", str(build_dir), str(self.project_path)] + flags

        return self._execute_build_command(command, self.project_path, timeout=300)

    def build(self, build_dir: Path, **kwargs) -> BuildResult:
        """Run Meson build."""
        build_dir = Path(build_dir).resolve()
        jobs = kwargs.get("jobs", 4)

        command = ["meson", "compile", "-C", str(build_dir), f"-j{jobs}"]

        return self._execute_build_command(command, build_dir, timeout=600)

    def clean(self, build_dir: Path) -> BuildResult:
        """Run Meson clean."""
        build_dir = Path(build_dir).resolve()
        command = ["meson", "compile", "-C", str(build_dir), "--clean"]

        return self._execute_build_command(command, build_dir, timeout=300)
