"""libFuzzer fuzzer plugin."""

from pathlib import Path
from typing import Dict, List, Optional, Any
import shutil
import subprocess
import json

from zerodaylab.fuzzing.plugins.base import FuzzerPlugin, FuzzerStatistics
from zerodaylab.core.logger import get_logger
from zerodaylab.security.process_handler import ProcessHandler
from zerodaylab.core.exceptions import FuzzerError

logger = get_logger(__name__)


class LibFuzzerPlugin(FuzzerPlugin):
    """libFuzzer fuzzer plugin."""

    name = "libfuzzer"
    version = "1.0.0"
    description = "libFuzzer fuzzing integration"

    def __init__(self):
        """Initialize libFuzzer plugin."""
        super().__init__()
        self.config = {}
        self.output_dir = None
        self.target_process = None

    def validate_environment(self) -> Dict[str, Any]:
        """Validate libFuzzer availability."""
        result = {
            "available": True,  # libFuzzer is built into targets
            "version": "LLVM",
            "path": None,
            "issues": [],
        }

        # Check if llvm-symbolizer is available
        symbolizer = shutil.which("llvm-symbolizer")
        if symbolizer:
            result["path"] = symbolizer
        else:
            result["issues"].append(
                "llvm-symbolizer not found (optional for better error messages)"
            )

        return result

    def prepare(
        self,
        target_binary: Path,
        corpus_dir: Path,
        output_dir: Path,
        **config,
    ) -> bool:
        """Prepare libFuzzer fuzzing."""
        target_binary = Path(target_binary).resolve()
        corpus_dir = Path(corpus_dir).resolve()
        output_dir = Path(output_dir).resolve()

        if not target_binary.exists():
            raise FuzzerError(f"Target binary not found: {target_binary}")

        if not corpus_dir.exists():
            corpus_dir.mkdir(parents=True, exist_ok=True)

        output_dir.mkdir(parents=True, exist_ok=True)

        self.config = {
            "target_binary": str(target_binary),
            "corpus_dir": str(corpus_dir),
            "output_dir": str(output_dir),
            **config,
        }
        self.output_dir = output_dir

        logger.info(f"libFuzzer prepared for {target_binary}")
        return True

    def start(self, workers: int = 1) -> bool:
        """Start libFuzzer fuzzing."""
        if not self.config:
            raise FuzzerError("Fuzzer not prepared")

        target_binary = self.config["target_binary"]
        corpus_dir = self.config["corpus_dir"]
        timeout = self.config.get("timeout", 5)
        max_len = self.config.get("max_len", 65536)
        max_total_time = self.config.get("max_total_time", 0)  # 0 = infinite

        # Build libFuzzer command
        command = [
            target_binary,
            corpus_dir,
            f"-timeout={timeout}",
            f"-max_len={max_len}",
        ]

        if max_total_time > 0:
            command.append(f"-max_total_time={max_total_time}")

        # Add artifact directory for crashes
        command.append(f"-artifact_prefix={self.output_dir}/artifacts/")

        try:
            logger.info(f"Starting libFuzzer with command: {' '.join(command)}")
            self._is_running = True
            # Note: In real implementation, we'd spawn the target process
            return True
        except Exception as e:
            logger.error(f"Failed to start libFuzzer: {e}")
            self._is_running = False
            return False

    def pause(self) -> bool:
        """Pause libFuzzer fuzzing."""
        if not self._is_running:
            return False
        self._is_running = False
        return True

    def resume(self) -> bool:
        """Resume libFuzzer fuzzing."""
        if self._is_running:
            return False
        self._is_running = True
        return True

    def stop(self) -> bool:
        """Stop libFuzzer fuzzing."""
        if not self._is_running:
            return False
        self._is_running = False
        return True

    def status(self) -> Dict[str, Any]:
        """Get libFuzzer status."""
        return {
            "running": self._is_running,
            "output_dir": str(self.output_dir) if self.output_dir else None,
            "config": self.config,
        }

    def collect_statistics(self) -> FuzzerStatistics:
        """Collect libFuzzer statistics."""
        # libFuzzer outputs stats to stdout/stderr
        # This would need to be captured during execution
        return FuzzerStatistics()

    def collect_crashes(self) -> List[Path]:
        """Collect crash files from libFuzzer."""
        crashes = []

        if not self.output_dir:
            return crashes

        # Look for artifacts directory
        artifacts_dir = self.output_dir / "artifacts"
        if artifacts_dir.exists():
            crashes = [f for f in artifacts_dir.iterdir() if f.is_file()]

        return crashes

    def collect_artifacts(self) -> Dict[str, List[Path]]:
        """Collect all libFuzzer artifacts."""
        artifacts = {
            "crashes": self.collect_crashes(),
            "corpus": [],
            "coverage": [],
        }

        if not self.output_dir:
            return artifacts

        # libFuzzer uses the input corpus directory directly
        corpus_dir = Path(self.config.get("corpus_dir", ""))
        if corpus_dir.exists():
            artifacts["corpus"] = [
                f for f in corpus_dir.iterdir() if f.is_file()
            ]

        # Look for coverage files (if coverage is enabled)
        coverage_dir = self.output_dir / "coverage"
        if coverage_dir.exists():
            artifacts["coverage"] = [
                f for f in coverage_dir.iterdir() if f.is_file()
            ]

        return artifacts

    def sync_corpus(self, external_corpus_dir: Path) -> bool:
        """Sync corpus with external directory."""
        corpus_dir = Path(self.config.get("corpus_dir", ""))
        if not corpus_dir.exists():
            return False

        external_corpus_dir = Path(external_corpus_dir).resolve()
        external_corpus_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Copy corpus files
            import shutil
            for f in corpus_dir.iterdir():
                if f.is_file():
                    shutil.copy2(f, external_corpus_dir / f.name)
            logger.info(f"Synced corpus to {external_corpus_dir}")
            return True
        except Exception as e:
            logger.error(f"Failed to sync corpus: {e}")
            return False

    def cleanup(self) -> bool:
        """Clean up libFuzzer environment."""
        self._is_running = False
        logger.info("libFuzzer cleanup completed")
        return True
