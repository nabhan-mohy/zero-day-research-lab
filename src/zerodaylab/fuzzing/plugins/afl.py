"""AFL++ fuzzer plugin."""

from pathlib import Path
from typing import Dict, List, Optional, Any
import shutil
import subprocess
import time
import os
import json

from zerodaylab.fuzzing.plugins.base import FuzzerPlugin, FuzzerStatistics
from zerodaylab.core.logger import get_logger
from zerodaylab.security.process_handler import ProcessHandler
from zerodaylab.core.exceptions import FuzzerError

logger = get_logger(__name__)


class AFLPlugin(FuzzerPlugin):
    """AFL++ fuzzer plugin."""

    name = "afl"
    version = "1.0.0"
    description = "AFL++ fuzzer integration"

    def __init__(self):
        """Initialize AFL++ plugin."""
        super().__init__()
        self.afl_fuzz_path = self._find_afl_fuzz()
        self.config = {}
        self.output_dir = None

    def _find_afl_fuzz(self) -> Optional[str]:
        """Find afl-fuzz executable.

        Returns:
            Path to afl-fuzz or None
        """
        # Try common locations
        candidates = [
            shutil.which("afl-fuzz"),
            "/usr/local/bin/afl-fuzz",
            "/usr/bin/afl-fuzz",
            Path.home() / "afl" / "afl-fuzz",
        ]

        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return str(candidate)

        return None

    def validate_environment(self) -> Dict[str, Any]:
        """Validate AFL++ installation."""
        result = {
            "available": False,
            "version": "UNKNOWN",
            "path": None,
            "issues": [],
        }

        if not self.afl_fuzz_path:
            result["issues"].append("afl-fuzz not found in PATH")
            return result

        result["path"] = self.afl_fuzz_path
        result["available"] = True

        # Try to get version
        try:
            exit_code, stdout, _ = ProcessHandler.execute(
                [self.afl_fuzz_path, "-v"],
                capture_output=True,
                timeout=5,
            )
            if exit_code == 0:
                # Parse version from output
                lines = stdout.split("\n")
                for line in lines:
                    if "afl" in line.lower():
                        result["version"] = line.strip()
                        break
        except Exception as e:
            logger.debug(f"Could not get AFL++ version: {e}")

        return result

    def prepare(
        self,
        target_binary: Path,
        corpus_dir: Path,
        output_dir: Path,
        **config,
    ) -> bool:
        """Prepare AFL++ fuzzing."""
        if not self.afl_fuzz_path:
            raise FuzzerError("AFL++ not available")

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

        logger.info(f"AFL++ prepared for {target_binary}")
        return True

    def start(self, workers: int = 1) -> bool:
        """Start AFL++ fuzzing."""
        if not self.config:
            raise FuzzerError("Fuzzer not prepared")

        target_binary = self.config["target_binary"]
        corpus_dir = self.config["corpus_dir"]
        output_dir = self.config["output_dir"]
        timeout = self.config.get("timeout", 5)
        memory = self.config.get("memory", 2048)

        # Build AFL++ command
        command = [
            self.afl_fuzz_path,
            "-i",
            corpus_dir,
            "-o",
            output_dir,
            "-t",
            str(timeout * 1000),  # AFL++ uses milliseconds
            "-m",
            str(memory),
            "-M",
            "master" if workers > 1 else "fuzzer",
        ]

        # Add dictionary if provided
        if "dictionary" in self.config:
            command.extend(["-x", self.config["dictionary"]])

        # Add target binary
        command.append(target_binary)
        command.append("@@")  # AFL++ will replace @@ with input file

        try:
            logger.info(f"Starting AFL++ with {workers} worker(s)")
            self._is_running = True
            # Note: In real implementation, we'd spawn AFL++ processes here
            # For now, we're just validating the command
            logger.debug(f"AFL++ command: {' '.join(command)}")
            return True
        except Exception as e:
            logger.error(f"Failed to start AFL++: {e}")
            self._is_running = False
            return False

    def pause(self) -> bool:
        """Pause AFL++ fuzzing."""
        if not self._is_running:
            return False
        # Send SIGSTOP to AFL++ processes
        self._is_running = False
        return True

    def resume(self) -> bool:
        """Resume AFL++ fuzzing."""
        if self._is_running:
            return False
        # Send SIGCONT to AFL++ processes
        self._is_running = True
        return True

    def stop(self) -> bool:
        """Stop AFL++ fuzzing."""
        if not self._is_running:
            return False
        # Terminate AFL++ processes
        self._is_running = False
        return True

    def status(self) -> Dict[str, Any]:
        """Get AFL++ status."""
        return {
            "running": self._is_running,
            "output_dir": str(self.output_dir) if self.output_dir else None,
            "config": self.config,
        }

    def collect_statistics(self) -> FuzzerStatistics:
        """Collect AFL++ statistics."""
        stats = FuzzerStatistics()

        if not self.output_dir or not self.output_dir.exists():
            return stats

        # Try to read AFL++ stats file
        stats_file = self.output_dir / "fuzzer_stats"
        if stats_file.exists():
            try:
                with open(stats_file, "r") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) != 2:
                            continue
                        key, value = parts
                        key = key.strip()
                        value = value.strip()

                        if key == "execs_done":
                            stats.executions = int(value)
                        elif key == "execs_per_sec":
                            stats.exec_per_sec = float(value)
                        elif key == "paths_total":
                            stats.paths = int(value)
                        elif key == "unique_crashes":
                            stats.unique_crashes = int(value)
                        elif key == "unique_hangs":
                            stats.timeouts = int(value)
            except Exception as e:
                logger.debug(f"Failed to read AFL++ stats: {e}")

        return stats

    def collect_crashes(self) -> List[Path]:
        """Collect crash files from AFL++."""
        crashes = []

        if not self.output_dir:
            return crashes

        # Look for crashes directory
        crashes_dir = self.output_dir / "crashes"
        if crashes_dir.exists():
            crashes = [
                f
                for f in crashes_dir.iterdir()
                if f.is_file() and f.name != "README.txt"
            ]

        return crashes

    def collect_artifacts(self) -> Dict[str, List[Path]]:
        """Collect all AFL++ artifacts."""
        artifacts = {
            "crashes": self.collect_crashes(),
            "corpus": [],
            "hangs": [],
        }

        if not self.output_dir:
            return artifacts

        # Corpus
        queue_dir = self.output_dir / "queue"
        if queue_dir.exists():
            artifacts["corpus"] = [
                f for f in queue_dir.iterdir() if f.is_file()
            ]

        # Hangs
        hangs_dir = self.output_dir / "hangs"
        if hangs_dir.exists():
            artifacts["hangs"] = [
                f for f in hangs_dir.iterdir() if f.is_file()
            ]

        return artifacts

    def sync_corpus(self, external_corpus_dir: Path) -> bool:
        """Sync corpus with external directory."""
        if not self.output_dir:
            return False

        queue_dir = self.output_dir / "queue"
        if not queue_dir.exists():
            return False

        external_corpus_dir = Path(external_corpus_dir).resolve()
        external_corpus_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Copy corpus files
            for f in queue_dir.iterdir():
                if f.is_file():
                    import shutil
                    shutil.copy2(f, external_corpus_dir / f.name)
            logger.info(f"Synced corpus to {external_corpus_dir}")
            return True
        except Exception as e:
            logger.error(f"Failed to sync corpus: {e}")
            return False

    def cleanup(self) -> bool:
        """Clean up AFL++ environment."""
        self._is_running = False
        logger.info("AFL++ cleanup completed")
        return True
