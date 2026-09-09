"""Base fuzzer plugin interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import json

from zerodaylab.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FuzzerStatistics:
    """Fuzzer runtime statistics."""

    executions: int = 0
    exec_per_sec: float = 0.0
    edges: int = 0
    new_edges: int = 0
    coverage_percent: float = 0.0
    paths: int = 0
    new_paths: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    timeouts: int = 0
    workers: int = 0
    uptime: float = 0.0
    corpus_size: int = 0

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "executions": self.executions,
            "exec_per_sec": self.exec_per_sec,
            "edges": self.edges,
            "new_edges": self.new_edges,
            "coverage_percent": self.coverage_percent,
            "paths": self.paths,
            "new_paths": self.new_paths,
            "crashes": self.crashes,
            "unique_crashes": self.unique_crashes,
            "timeouts": self.timeouts,
            "workers": self.workers,
            "uptime": self.uptime,
            "corpus_size": self.corpus_size,
        }


class FuzzerPlugin(ABC):
    """Abstract base class for fuzzer plugins."""

    name: str = "base"
    version: str = "1.0.0"
    description: str = "Base fuzzer plugin"

    def __init__(self):
        """Initialize fuzzer plugin."""
        self.logger = get_logger(f"FuzzerPlugin[{self.name}]")
        self._is_running = False
        self._worker_processes = {}

    @abstractmethod
    def validate_environment(self) -> Dict[str, Any]:
        """Validate that fuzzer is installed and configured.

        Returns:
            Dict with validation results:
            {
                "available": bool,
                "version": str,
                "path": str,
                "issues": [list of issues],
            }
        """
        pass

    @abstractmethod
    def prepare(
        self,
        target_binary: Path,
        corpus_dir: Path,
        output_dir: Path,
        **config,
    ) -> bool:
        """Prepare fuzzing environment.

        Args:
            target_binary: Path to target binary
            corpus_dir: Input corpus directory
            output_dir: Output directory
            **config: Additional configuration

        Returns:
            True if preparation successful
        """
        pass

    @abstractmethod
    def start(self, workers: int = 1) -> bool:
        """Start fuzzing.

        Args:
            workers: Number of workers

        Returns:
            True if started successfully
        """
        pass

    @abstractmethod
    def pause(self) -> bool:
        """Pause fuzzing.

        Returns:
            True if paused successfully
        """
        pass

    @abstractmethod
    def resume(self) -> bool:
        """Resume fuzzing.

        Returns:
            True if resumed successfully
        """
        pass

    @abstractmethod
    def stop(self) -> bool:
        """Stop fuzzing.

        Returns:
            True if stopped successfully
        """
        pass

    @abstractmethod
    def status(self) -> Dict[str, Any]:
        """Get fuzzer status.

        Returns:
            Dict with status information
        """
        pass

    @abstractmethod
    def collect_statistics(self) -> FuzzerStatistics:
        """Collect fuzzer statistics.

        Returns:
            FuzzerStatistics object
        """
        pass

    @abstractmethod
    def collect_crashes(self) -> List[Path]:
        """Collect crash artifacts.

        Returns:
            List of crash file paths
        """
        pass

    @abstractmethod
    def collect_artifacts(self) -> Dict[str, List[Path]]:
        """Collect all artifacts (corpus, crashes, coverage, etc).

        Returns:
            Dict with artifact categories
        """
        pass

    @abstractmethod
    def sync_corpus(self, external_corpus_dir: Path) -> bool:
        """Sync corpus with external directory.

        Args:
            external_corpus_dir: External corpus directory

        Returns:
            True if sync successful
        """
        pass

    @abstractmethod
    def cleanup(self) -> bool:
        """Clean up fuzzing environment.

        Returns:
            True if cleanup successful
        """
        pass

    def is_running(self) -> bool:
        """Check if fuzzer is running.

        Returns:
            True if fuzzer is running
        """
        return self._is_running

    def get_info(self) -> Dict[str, str]:
        """Get fuzzer information.

        Returns:
            Dict with name, version, description
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
        }
