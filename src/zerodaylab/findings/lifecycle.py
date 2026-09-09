"""Finding lifecycle management."""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional, List, Any
from pathlib import Path

from zerodaylab.core.logger import get_logger
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Finding, CrashFingerprint

logger = get_logger(__name__)


class FindingStatus(Enum):
    """Finding lifecycle status."""

    NEW = "NEW"
    TRIAGED = "TRIAGED"
    REPRODUCED = "REPRODUCED"
    MINIMIZED = "MINIMIZED"
    VERIFIED = "VERIFIED"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    WONTFIX = "WONTFIX"
    ARCHIVED = "ARCHIVED"


@dataclass
class FindingRecord:
    """A finding record with metadata."""

    finding_id: int
    project_id: int
    status: FindingStatus
    severity: str
    confidence: str
    description: str = ""
    recommendation: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    assigned_to: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    proof_of_concept: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "project_id": self.project_id,
            "status": self.status.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "assigned_to": self.assigned_to,
            "tags": self.tags,
            "references": self.references,
            "proof_of_concept": str(self.proof_of_concept) if self.proof_of_concept else None,
        }


class FindingLifecycle:
    """Manage finding lifecycle."""

    def __init__(self, db_path: Path):
        """Initialize finding lifecycle manager.

        Args:
            db_path: Path to database
        """
        self.db = DatabaseConnection(db_path)
        self.db.init_db()

    def create_finding(
        self,
        project_id: int,
        fingerprint_id: int,
        severity: str,
        confidence: str,
        description: str = "",
    ) -> Finding:
        """Create a new finding.

        Args:
            project_id: Project ID
            fingerprint_id: Crash fingerprint ID
            severity: Severity level
            confidence: Confidence level
            description: Description

        Returns:
            Finding object
        """
        session = self.db.get_session()
        try:
            finding = Finding(
                project_id=project_id,
                fingerprint_id=fingerprint_id,
                status="NEW",
                severity=severity,
                confidence=confidence,
                description=description,
            )
            session.add(finding)
            session.commit()
            logger.info(f"Created finding {finding.id} for project {project_id}")
            return finding
        finally:
            session.close()

    def update_status(
        self,
        finding_id: int,
        new_status: FindingStatus,
    ) -> bool:
        """Update finding status.

        Args:
            finding_id: Finding ID
            new_status: New status

        Returns:
            True if updated
        """
        session = self.db.get_session()
        try:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise ValueError(f"Finding {finding_id} not found")

            finding.status = new_status.value
            finding.updated_at = datetime.utcnow()
            session.commit()
            logger.info(f"Updated finding {finding_id} status to {new_status.value}")
            return True
        finally:
            session.close()

    def assign_finding(
        self,
        finding_id: int,
        assigned_to: str,
    ) -> bool:
        """Assign finding to a person/team.

        Args:
            finding_id: Finding ID
            assigned_to: Person/team name

        Returns:
            True if assigned
        """
        session = self.db.get_session()
        try:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise ValueError(f"Finding {finding_id} not found")

            # This would require adding assigned_to to Finding model
            # For now, update status to ASSIGNED
            finding.status = "ASSIGNED"
            finding.updated_at = datetime.utcnow()
            session.commit()
            logger.info(f"Assigned finding {finding_id} to {assigned_to}")
            return True
        finally:
            session.close()

    def get_finding(
        self,
        finding_id: int,
    ) -> Optional[Finding]:
        """Get a finding by ID.

        Args:
            finding_id: Finding ID

        Returns:
            Finding object or None
        """
        session = self.db.get_session()
        try:
            return session.query(Finding).filter(Finding.id == finding_id).first()
        finally:
            session.close()

    def get_findings_by_status(
        self,
        status: FindingStatus,
        project_id: Optional[int] = None,
    ) -> List[Finding]:
        """Get findings by status.

        Args:
            status: Finding status
            project_id: Optional project filter

        Returns:
            List of Finding objects
        """
        session = self.db.get_session()
        try:
            query = session.query(Finding).filter(Finding.status == status.value)
            if project_id:
                query = query.filter(Finding.project_id == project_id)
            return query.all()
        finally:
            session.close()

    def get_project_findings(
        self,
        project_id: int,
    ) -> List[Finding]:
        """Get all findings for a project.

        Args:
            project_id: Project ID

        Returns:
            List of Finding objects
        """
        session = self.db.get_session()
        try:
            return session.query(Finding).filter(Finding.project_id == project_id).all()
        finally:
            session.close()

    def get_project_summary(
        self,
        project_id: int,
    ) -> Dict[str, Any]:
        """Get findings summary for a project.

        Args:
            project_id: Project ID

        Returns:
            Summary statistics
        """
        session = self.db.get_session()
        try:
            findings = (
                session.query(Finding)
                .filter(Finding.project_id == project_id)
                .all()
            )

            summary = {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in findings if f.severity == "HIGH"),
                "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in findings if f.severity == "LOW"),
                "by_status": {},
            }

            # Count by status
            for status in FindingStatus:
                count = sum(1 for f in findings if f.status == status.value)
                if count > 0:
                    summary["by_status"][status.value] = count

            return summary
        finally:
            session.close()
