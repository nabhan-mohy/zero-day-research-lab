"""Crash collection from fuzzer outputs."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
import subprocess

from zerodaylab.core.logger import get_logger
from zerodaylab.core.exceptions import CrashAnalysisError
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Crash

logger = get_logger(__name__)


@dataclass
class CrashArtifact:
    """A crash artifact with metadata."""

    file_path: Path
    input_sha256: str
    input_size: int
    signal: Optional[int] = None
    exit_code: Optional[int] = None
    sanitizer: Optional[str] = None
    sanitizer_output: str = ""
    stack_trace: str = ""
    stderr: str = ""
    stdout: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    worker_id: Optional[int] = None
    campaign_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "file_path": str(self.file_path),
            "input_sha256": self.input_sha256,
            "input_size": self.input_size,
            "signal": self.signal,
            "exit_code": self.exit_code,
            "sanitizer": self.sanitizer,
            "sanitizer_output": self.sanitizer_output,
            "stack_trace": self.stack_trace,
            "stderr": self.stderr,
            "stdout": self.stdout,
            "timestamp": self.timestamp.isoformat(),
            "worker_id": self.worker_id,
            "campaign_id": self.campaign_id,
        }


class CrashCollector:
    """Collect and analyze crashes from fuzzing campaigns."""

    def __init__(self, db_path: Path):
        """Initialize crash collector.

        Args:
            db_path: Path to database
        """
        self.db = DatabaseConnection(db_path)
        self.db.init_db()

    def collect_crash(
        self,
        crash_file: Path,
        campaign_id: int,
        worker_id: Optional[int] = None,
    ) -> CrashArtifact:
        """Collect a crash artifact.

        Args:
            crash_file: Path to crash input file
            campaign_id: Campaign ID
            worker_id: Optional worker ID

        Returns:
            CrashArtifact object
        """
        crash_file = Path(crash_file).resolve()

        if not crash_file.exists():
            raise CrashAnalysisError(f"Crash file not found: {crash_file}")

        # Read and hash crash input
        try:
            input_data = crash_file.read_bytes()
            input_sha256 = hashlib.sha256(input_data).hexdigest()
            input_size = len(input_data)
        except Exception as e:
            raise CrashAnalysisError(f"Failed to read crash file: {e}")

        logger.debug(f"Collected crash: {crash_file} (SHA256: {input_sha256})")

        artifact = CrashArtifact(
            file_path=crash_file,
            input_sha256=input_sha256,
            input_size=input_size,
            campaign_id=campaign_id,
            worker_id=worker_id,
        )

        return artifact

    def collect_from_directory(
        self,
        crash_dir: Path,
        campaign_id: int,
        worker_id: Optional[int] = None,
    ) -> List[CrashArtifact]:
        """Collect all crashes from a directory.

        Args:
            crash_dir: Directory containing crash files
            campaign_id: Campaign ID
            worker_id: Optional worker ID

        Returns:
            List of CrashArtifact objects
        """
        crash_dir = Path(crash_dir).resolve()

        if not crash_dir.exists():
            logger.warning(f"Crash directory not found: {crash_dir}")
            return []

        crashes = []
        for crash_file in crash_dir.iterdir():
            if crash_file.is_file():
                try:
                    artifact = self.collect_crash(crash_file, campaign_id, worker_id)
                    crashes.append(artifact)
                except Exception as e:
                    logger.warning(f"Failed to collect crash {crash_file}: {e}")

        logger.info(f"Collected {len(crashes)} crashes from {crash_dir}")
        return crashes

    def store_crash(
        self,
        artifact: CrashArtifact,
        original_path: Optional[Path] = None,
    ) -> Crash:
        """Store crash in database.

        Args:
            artifact: CrashArtifact to store
            original_path: Optional path to preserve original file

        Returns:
            Stored Crash object
        """
        session = self.db.get_session()
        try:
            crash = Crash(
                campaign_id=artifact.campaign_id,
                worker_id=artifact.worker_id,
                signal=artifact.signal,
                exit_code=artifact.exit_code,
                sanitizer=artifact.sanitizer,
                sanitizer_output=artifact.sanitizer_output,
                stack_trace=artifact.stack_trace,
                input_sha256=artifact.input_sha256,
                input_size=artifact.input_size,
                timestamp=artifact.timestamp,
            )
            session.add(crash)
            session.commit()

            logger.debug(f"Stored crash in database (ID: {crash.id})")
            return crash
        finally:
            session.close()

    def get_crash(self, crash_id: int) -> Optional[Crash]:
        """Get a crash by ID.

        Args:
            crash_id: Crash ID

        Returns:
            Crash object or None
        """
        session = self.db.get_session()
        try:
            return session.query(Crash).filter(Crash.id == crash_id).first()
        finally:
            session.close()

    def get_crashes_by_campaign(
        self,
        campaign_id: int,
    ) -> List[Crash]:
        """Get all crashes from a campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            List of Crash objects
        """
        session = self.db.get_session()
        try:
            return session.query(Crash).filter(Crash.campaign_id == campaign_id).all()
        finally:
            session.close()

    def get_crash_by_sha256(
        self,
        sha256: str,
    ) -> Optional[Crash]:
        """Get a crash by input SHA256.

        Args:
            sha256: SHA256 hash of input

        Returns:
            Crash object or None
        """
        session = self.db.get_session()
        try:
            return session.query(Crash).filter(Crash.input_sha256 == sha256).first()
        finally:
            session.close()
