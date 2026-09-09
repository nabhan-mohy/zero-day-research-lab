"""Vulnerability severity assessment."""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional, Any

from zerodaylab.core.logger import get_logger

logger = get_logger(__name__)


class SeverityLevel(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(Enum):
    """Confidence that vulnerability is real."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class SeverityAssessment:
    """Severity assessment of a vulnerability."""

    crash_id: int
    severity: SeverityLevel
    confidence: ConfidenceLevel
    cvss_score: Optional[float] = None
    impact: Optional[str] = None
    affected_components: Optional[str] = None
    exploitation_difficulty: Optional[str] = None  # easy, moderate, hard
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "crash_id": self.crash_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cvss_score": self.cvss_score,
            "impact": self.impact,
            "affected_components": self.affected_components,
            "exploitation_difficulty": self.exploitation_difficulty,
            "notes": self.notes,
        }


class SeverityAssessor:
    """Assess vulnerability severity."""

    def assess(
        self,
        error_type: str,
        sanitizer: Optional[str],
        is_reproducible: bool,
        memory_corruption: bool = False,
    ) -> SeverityAssessment:
        """Assess severity of a vulnerability.

        Args:
            error_type: Type of error (heap-buffer-overflow, etc.)
            sanitizer: Sanitizer that detected it (asan, ubsan, lsan)
            is_reproducible: Whether crash is reproducible
            memory_corruption: Whether it's memory corruption

        Returns:
            SeverityAssessment object
        """
        severity = self._assess_severity(
            error_type,
            sanitizer,
            memory_corruption,
        )
        confidence = self._assess_confidence(is_reproducible, sanitizer)
        exploitation_difficulty = self._assess_exploitation_difficulty(
            error_type
        )

        logger.debug(
            f"Assessed {error_type}: severity={severity.value}, "
            f"confidence={confidence.value}"
        )

        return SeverityAssessment(
            crash_id=-1,  # Will be set when stored
            severity=severity,
            confidence=confidence,
            exploitation_difficulty=exploitation_difficulty,
            impact=self._get_impact_description(error_type),
        )

    def _assess_severity(
        self,
        error_type: str,
        sanitizer: Optional[str],
        memory_corruption: bool,
    ) -> SeverityLevel:
        """Assess severity level."""
        # Critical vulnerabilities
        critical_types = [
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "use-after-free",
            "double-free",
            "type-confusion",
        ]

        if error_type in critical_types:
            return SeverityLevel.CRITICAL

        # High severity
        high_types = [
            "global-buffer-overflow",
            "invalid-free",
            "memory-leak",
        ]

        if error_type in high_types:
            return SeverityLevel.HIGH

        # Medium severity
        if sanitizer == "ubsan":
            return SeverityLevel.MEDIUM

        # Low severity
        if sanitizer == "lsan":
            return SeverityLevel.LOW

        return SeverityLevel.UNKNOWN

    def _assess_confidence(
        self,
        is_reproducible: bool,
        sanitizer: Optional[str],
    ) -> ConfidenceLevel:
        """Assess confidence level."""
        if not is_reproducible:
            return ConfidenceLevel.LOW

        if sanitizer == "asan":
            return ConfidenceLevel.CONFIRMED
        elif sanitizer == "ubsan":
            return ConfidenceLevel.HIGH
        elif sanitizer == "lsan":
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

    def _assess_exploitation_difficulty(
        self,
        error_type: str,
    ) -> str:
        """Assess exploitation difficulty."""
        easy_types = [
            "heap-buffer-overflow",
            "use-after-free",
            "stack-buffer-overflow",
        ]

        if error_type in easy_types:
            return "easy"

        if error_type in ["double-free", "type-confusion"]:
            return "moderate"

        return "hard"

    def _get_impact_description(self, error_type: str) -> str:
        """Get impact description for error type."""
        impacts = {
            "heap-buffer-overflow": "Heap memory corruption",
            "stack-buffer-overflow": "Stack memory corruption",
            "use-after-free": "Use of freed memory",
            "double-free": "Double free of memory",
            "type-confusion": "Type confusion",
            "memory-leak": "Memory leak",
            "division-by-zero": "Division by zero",
            "null-pointer-dereference": "Null pointer dereference",
        }
        return impacts.get(error_type, "Unknown impact")
