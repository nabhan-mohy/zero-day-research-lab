"""Crash regression testing and verification."""

from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from zerodaylab.core.logger import get_logger
from zerodaylab.core.exceptions import CrashAnalysisError
from zerodaylab.security.process_handler import ProcessHandler

logger = get_logger(__name__)


@dataclass
class RegressionTestResult:
    """Result of regression test."""

    test_name: str
    crash_input_path: Path
    target_binary: Path
    reproduced: bool
    execution_time: float
    exit_code: int
    sanitizer_output: str = ""
    error_message: str = ""
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class RegressionTester:
    """Test crashes against target binaries to verify fixes."""

    def __init__(self, target_binary: Path, timeout: int = 5):
        """Initialize regression tester.

        Args:
            target_binary: Path to target binary
            timeout: Timeout for execution in seconds
        """
        self.target_binary = Path(target_binary).resolve()
        self.timeout = timeout

        if not self.target_binary.exists():
            raise CrashAnalysisError(f"Target binary not found: {target_binary}")

    def test_crash(
        self,
        crash_input_path: Path,
        test_name: str = "",
    ) -> RegressionTestResult:
        """Test if a crash still reproduces.

        Args:
            crash_input_path: Path to crash input file
            test_name: Name for this test

        Returns:
            RegressionTestResult
        """
        crash_input_path = Path(crash_input_path).resolve()

        if not crash_input_path.exists():
            raise CrashAnalysisError(f"Crash input not found: {crash_input_path}")

        if not test_name:
            test_name = crash_input_path.name

        logger.info(f"Running regression test: {test_name}")

        # Execute target with crash input
        try:
            exit_code, stdout, stderr = ProcessHandler.execute(
                [str(self.target_binary), str(crash_input_path)],
                capture_output=True,
                timeout=self.timeout,
            )

            # Determine if crash reproduced
            reproduced = exit_code != 0

            logger.debug(
                f"Test {test_name}: exit_code={exit_code}, "
                f"reproduced={reproduced}"
            )

            return RegressionTestResult(
                test_name=test_name,
                crash_input_path=crash_input_path,
                target_binary=self.target_binary,
                reproduced=reproduced,
                execution_time=0.0,  # Would need to measure in ProcessHandler
                exit_code=exit_code,
                sanitizer_output=stderr,
            )

        except Exception as e:
            logger.error(f"Test {test_name} failed: {e}")
            return RegressionTestResult(
                test_name=test_name,
                crash_input_path=crash_input_path,
                target_binary=self.target_binary,
                reproduced=False,
                execution_time=0.0,
                exit_code=-1,
                error_message=str(e),
            )

    def test_crashes(
        self,
        crash_dir: Path,
    ) -> List[RegressionTestResult]:
        """Test multiple crashes.

        Args:
            crash_dir: Directory containing crash files

        Returns:
            List of RegressionTestResult
        """
        crash_dir = Path(crash_dir).resolve()

        if not crash_dir.exists():
            logger.warning(f"Crash directory not found: {crash_dir}")
            return []

        results = []
        for crash_file in crash_dir.iterdir():
            if crash_file.is_file():
                try:
                    result = self.test_crash(crash_file)
                    results.append(result)
                except Exception as e:
                    logger.warning(f"Failed to test {crash_file}: {e}")

        logger.info(
            f"Tested {len(results)} crashes: "
            f"{sum(1 for r in results if r.reproduced)} reproduced"
        )

        return results

    def get_summary(
        self,
        results: List[RegressionTestResult],
    ) -> Dict:
        """Get summary of regression test results.

        Args:
            results: List of test results

        Returns:
            Summary dictionary
        """
        reproduced = sum(1 for r in results if r.reproduced)
        fixed = len(results) - reproduced

        return {
            "total_tests": len(results),
            "reproduced": reproduced,
            "fixed": fixed,
            "success_rate": fixed / len(results) if results else 0.0,
        }
