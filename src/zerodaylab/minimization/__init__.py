"""Crash minimization and input reduction."""

from pathlib import Path
from typing import Optional, List, Callable
import shutil

from zerodaylab.core.logger import get_logger
from zerodaylab.core.exceptions import CrashAnalysisError
from zerodaylab.security.process_handler import ProcessHandler

logger = get_logger(__name__)


class CrashMinimizer:
    """Minimize crash inputs to smallest reproducible case."""

    def __init__(self, target_binary: Path, timeout: int = 5):
        """Initialize crash minimizer.

        Args:
            target_binary: Path to target binary
            timeout: Timeout for binary execution in seconds
        """
        self.target_binary = Path(target_binary).resolve()
        self.timeout = timeout

        if not self.target_binary.exists():
            raise CrashAnalysisError(f"Target binary not found: {target_binary}")

    def minimize(
        self,
        crash_input: bytes,
        verification_callback: Optional[Callable[[bytes], bool]] = None,
    ) -> bytes:
        """Minimize a crash input.

        Args:
            crash_input: Original crash input
            verification_callback: Optional callback to verify crash is reproduced

        Returns:
            Minimized crash input
        """
        logger.info(f"Starting minimization of {len(crash_input)} bytes")

        minimized = bytearray(crash_input)

        # Try removing bytes from the end
        while len(minimized) > 1:
            # Try removing half
            test_size = max(1, len(minimized) // 2)
            test_input = minimized[:test_size]

            if verification_callback:
                if verification_callback(bytes(test_input)):
                    minimized = test_input
                    logger.debug(f"Reduced to {len(minimized)} bytes")
                    continue

            # Try removing individual bytes
            removed = False
            for i in range(len(minimized) - 1, 0, -1):
                test_input = minimized[:i] + minimized[i + 1 :]
                if verification_callback:
                    if verification_callback(bytes(test_input)):
                        minimized = test_input
                        removed = True
                        break

            if not removed:
                break

        logger.info(f"Minimized to {len(minimized)} bytes")
        return bytes(minimized)

    def minimize_binary_search(
        self,
        crash_input: bytes,
        verification_callback: Callable[[bytes], bool],
    ) -> bytes:
        """Minimize using binary search approach.

        Args:
            crash_input: Original crash input
            verification_callback: Callback to verify crash is reproduced

        Returns:
            Minimized crash input
        """
        logger.info(f"Binary search minimization of {len(crash_input)} bytes")

        minimized = bytearray(crash_input)
        changed = True

        while changed:
            changed = False
            mid = len(minimized) // 2

            # Try first half
            if verification_callback(bytes(minimized[:mid])):
                minimized = minimized[:mid]
                changed = True
                logger.debug(f"Reduced to {len(minimized)} bytes (first half)")
                continue

            # Try second half
            if verification_callback(bytes(minimized[mid:])):
                minimized = minimized[mid:]
                changed = True
                logger.debug(f"Reduced to {len(minimized)} bytes (second half)")
                continue

        logger.info(f"Binary search minimized to {len(minimized)} bytes")
        return bytes(minimized)
