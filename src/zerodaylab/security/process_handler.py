"""Secure process execution handler."""

import os
import signal
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from zerodaylab.core.logger import get_logger
from zerodaylab.core.exceptions import SecurityError

logger = get_logger(__name__)


class ProcessHandler:
    """Secure process execution with timeout and resource limits."""

    @staticmethod
    def validate_command(command: List[str]) -> None:
        """Validate command arguments.

        Args:
            command: Command and arguments as list

        Raises:
            SecurityError: If command is invalid
        """
        if not command or not isinstance(command, list):
            raise SecurityError("Command must be a non-empty list")

        if not all(isinstance(arg, (str, Path)) for arg in command):
            raise SecurityError("All command arguments must be strings or Path objects")

        # Prevent shell injection by disallowing shell metacharacters in command[0]
        executable = str(command[0])
        if not Path(executable).exists() and not _is_in_path(executable):
            raise SecurityError(f"Executable not found: {executable}")

    @staticmethod
    def execute(
        command: List[str],
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        capture_output: bool = False,
    ) -> Tuple[int, str, str]:
        """Execute command safely.

        Args:
            command: Command and arguments as list
            cwd: Working directory
            env: Environment variables
            timeout: Timeout in seconds
            capture_output: Capture stdout/stderr

        Returns:
            Tuple of (exit_code, stdout, stderr)

        Raises:
            SecurityError: If command is invalid
        """
        ProcessHandler.validate_command(command)

        try:
            # Build subprocess arguments
            kwargs = {
                "cwd": cwd,
                "timeout": timeout,
            }

            if env:
                kwargs["env"] = env

            if capture_output:
                kwargs["capture_output"] = True
                kwargs["text"] = True
            else:
                kwargs["stdout"] = subprocess.DEVNULL
                kwargs["stderr"] = subprocess.DEVNULL

            logger.debug(f"Executing: {' '.join(str(arg) for arg in command)}")

            result = subprocess.run(command, **kwargs)

            stdout = result.stdout if capture_output else ""
            stderr = result.stderr if capture_output else ""

            return result.returncode, stdout, stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout after {timeout}s: {command[0]}")
            raise SecurityError(f"Command timeout after {timeout}s")
        except FileNotFoundError:
            logger.error(f"Executable not found: {command[0]}")
            raise SecurityError(f"Executable not found: {command[0]}")
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise SecurityError(f"Command execution failed: {e}")

    @staticmethod
    def execute_with_pipe(
        command: List[str],
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> subprocess.Popen:
        """Execute command and return Popen handle for streaming.

        Args:
            command: Command and arguments as list
            cwd: Working directory
            env: Environment variables
            timeout: Timeout in seconds

        Returns:
            Popen process handle

        Raises:
            SecurityError: If command is invalid
        """
        ProcessHandler.validate_command(command)

        try:
            logger.debug(f"Executing with pipe: {' '.join(str(arg) for arg in command)}")

            return subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                text=True,
            )
        except Exception as e:
            logger.error(f"Failed to start process: {e}")
            raise SecurityError(f"Failed to start process: {e}")

    @staticmethod
    def terminate_process(pid: int, force: bool = False) -> None:
        """Terminate a process.

        Args:
            pid: Process ID
            force: Use SIGKILL instead of SIGTERM
        """
        try:
            if force:
                os.kill(pid, signal.SIGKILL)
                logger.info(f"Killed process {pid}")
            else:
                os.kill(pid, signal.SIGTERM)
                logger.info(f"Terminated process {pid}")
        except ProcessLookupError:
            logger.debug(f"Process {pid} not found")
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")


def _is_in_path(executable: str) -> bool:
    """Check if executable is in PATH.

    Args:
        executable: Executable name

    Returns:
        True if found in PATH
    """
    for path in os.environ.get("PATH", "").split(os.pathsep):
        if Path(path, executable).exists():
            return True
    return False
