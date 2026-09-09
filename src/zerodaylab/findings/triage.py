"""Crash triage and classification."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, List, Any
from datetime import datetime

from zerodaylab.core.logger import get_logger
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Crash, CrashFingerprint

logger = get_logger(__name__)


class TriageStatus(Enum):
    """Triage status."""

    NEW = "NEW"
    REVIEWING = "REVIEWING"
    DUPLICATE = "DUPLICATE"
    INVALID = "INVALID"
    TRIAGED = "TRIAGED"
    NEEDS_ANALYSIS = "NEEDS_ANALYSIS"


@dataclass
class TriageResult:
    """Result of crash triage."""

    crash_id: int
    status: TriageStatus
    is_duplicate: bool = False
    duplicate_of: Optional[int] = None
    is_exploitable: Optional[bool] = None
    reproducible: Optional[bool] = None
    requires_investigation: bool = False
    notes: str = ""
    triage_time: datetime = field(default_factory=datetime.utcnow)
    triaged_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "crash_id": self.crash_id,
            "status": self.status.value,
            "is_duplicate": self.is_duplicate,
            "duplicate_of": self.duplicate_of,
            "is_exploitable": self.is_exploitable,
            "reproducible": self.reproducible,
            "requires_investigation": self.requires_investigation,
            "notes": self.notes,
            "triage_time": self.triage_time.isoformat(),
            "triaged_by": self.triaged_by,
        }


class CrashTriage:
    """Triage crashes for analysis and exploitation potential."""

    def __init__(self, db_path):
        """Initialize crash triage.

        Args:
            db_path: Path to database
        """
        self.db = DatabaseConnection(db_path)
        self.db.init_db()

    def triage_crash(
        self,
        crash_id: int,
        triaged_by: Optional[str] = None,
    ) -> TriageResult:
        """Triage a single crash.

        Args:
            crash_id: Crash ID
            triaged_by: Name of person/system triaging

        Returns:
            TriageResult object
        """
        session = self.db.get_session()
        try:
            crash = session.query(Crash).filter(Crash.id == crash_id).first()
            if not crash:
                raise ValueError(f"Crash {crash_id} not found")

            # Determine if likely exploitable based on sanitizer type
            is_exploitable = self._assess_exploitability(crash)

            # Check if reproducible (crashes should be reproducible by definition)
            reproducible = crash.input_sha256 is not None

            # Determine if requires investigation
            requires_investigation = (
                crash.sanitizer in ["asan", "ubsan"]
                and is_exploitable
            )

            logger.info(
                f"Triaged crash {crash_id}: "
                f"exploitable={is_exploitable}, "
                f"reproducible={reproducible}"
            )

            return TriageResult(
                crash_id=crash_id,
                status=TriageStatus.TRIAGED,
                is_exploitable=is_exploitable,
                reproducible=reproducible,
                requires_investigation=requires_investigation,
                triaged_by=triaged_by,
            )
        finally:
            session.close()

    def check_for_duplicates(
        self,
        crash_id: int,
    ) -> Optional[int]:
        """Check if crash is a duplicate of an existing crash.

        Args:
            crash_id: Crash ID

        Returns:
            ID of duplicate crash or None
        """
        session = self.db.get_session()
        try:
            crash = session.query(Crash).filter(Crash.id == crash_id).first()
            if not crash or not crash.input_sha256:
                return None

            # Look for another crash with same input SHA256
            duplicate = (
                session.query(Crash)
                .filter(
                    Crash.input_sha256 == crash.input_sha256,
                    Crash.id != crash_id,
                )
                .first()
            )

            if duplicate:
                logger.debug(
                    f"Crash {crash_id} is duplicate of crash {duplicate.id}"
                )
                return duplicate.id

            return None
        finally:
            session.close()

    def _assess_exploitability(
        self,
        crash: Crash,
    ) -> bool:
        """Assess if crash is likely exploitable.

        Args:
            crash: Crash object

        Returns:
            True if likely exploitable
        """
        # Crashes that are likely exploitable
        exploitable_types = [
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "use-after-free",
            "double-free",
            "type-confusion",
        ]

        # Check sanitizer output for exploitable patterns
        if crash.sanitizer_output:
            for eType in exploitable_types:
                if eType in crash.sanitizer_output.lower():
                    return True

        # Default based on crash type
        return crash.sanitizer == "asan"

    def bulk_triage(
        self,
        crash_ids: List[int],
        triaged_by: Optional[str] = None,
    ) -> List[TriageResult]:
        """Triage multiple crashes.

        Args:
            crash_ids: List of crash IDs
            triaged_by: Name of person/system triaging

        Returns:
            List of TriageResult objects
        """
        results = []
        for crash_id in crash_ids:
            try:
                result = self.triage_crash(crash_id, triaged_by)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to triage crash {crash_id}: {e}")

        return results

    def get_triage_summary(self, campaign_id: int) -> Dict[str, Any]:
        """Get triage summary for a campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            Summary statistics
        """
        session = self.db.get_session()
        try:
            crashes = (
                session.query(Crash)
                .filter(Crash.campaign_id == campaign_id)
                .all()
            )

            total = len(crashes)
            exploitable = sum(
                1 for c in crashes
                if c.sanitizer == "asan" and c.input_sha256
            )
            unique = len(set(c.input_sha256 for c in crashes))

            return {
                "campaign_id": campaign_id,
                "total_crashes": total,
                "unique_crashes": unique,
                "exploitable": exploitable,
                "requires_review": sum(
                    1 for c in crashes if c.sanitizer == "ubsan"
                ),
            }
        finally:
            session.close()
