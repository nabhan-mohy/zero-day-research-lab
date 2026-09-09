"""Crash fingerprinting and deduplication."""

from dataclasses import dataclass
from typing import Optional, Dict, List
import hashlib
import re

from zerodaylab.core.logger import get_logger
from zerodaylab.crashes.parser import SanitiserReport

logger = get_logger(__name__)


@dataclass
class CrashFingerprint:
    """Crash fingerprint for deduplication."""

    fingerprint: str
    category: str  # crash category
    sanitizer: Optional[str] = None
    error_type: Optional[str] = None
    normalized_stack: Optional[str] = None
    fault_module: Optional[str] = None
    fault_function: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.category}:{self.fingerprint[:16]}"

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "fingerprint": self.fingerprint,
            "category": self.category,
            "sanitizer": self.sanitizer,
            "error_type": self.error_type,
            "normalized_stack": self.normalized_stack,
            "fault_module": self.fault_module,
            "fault_function": self.fault_function,
        }


class FingerprintGenerator:
    """Generate crash fingerprints for deduplication."""

    @staticmethod
    def generate(
        report: SanitiserReport,
        stack_trace: str = "",
    ) -> CrashFingerprint:
        """Generate fingerprint from crash report.

        Args:
            report: SanitiserReport object
            stack_trace: Stack trace text

        Returns:
            CrashFingerprint object
        """
        # Build fingerprint components
        components = []

        # Sanitizer type
        if report.sanitizer:
            components.append(f"san:{report.sanitizer}")

        # Error type
        if report.error_type:
            components.append(f"err:{report.error_type}")

        # Function name
        if report.function:
            components.append(f"func:{report.function}")

        # Module
        if report.module:
            components.append(f"mod:{report.module}")

        # Normalized stack trace
        normalized_stack = FingerprintGenerator._normalize_stack(stack_trace)
        if normalized_stack:
            components.append(f"stack:{normalized_stack}")

        # Create fingerprint
        fingerprint_text = "|".join(components)
        fingerprint_hash = hashlib.sha256(fingerprint_text.encode()).hexdigest()

        logger.debug(f"Generated fingerprint: {fingerprint_hash}")

        return CrashFingerprint(
            fingerprint=fingerprint_hash,
            category=report.error_type or "unknown",
            sanitizer=report.sanitizer,
            error_type=report.error_type,
            normalized_stack=normalized_stack,
            fault_function=report.function,
            fault_module=report.module,
        )

    @staticmethod
    def _normalize_stack(stack_trace: str) -> Optional[str]:
        """Normalize stack trace for fingerprinting.

        Removes addresses and line numbers to avoid false negatives.

        Args:
            stack_trace: Raw stack trace

        Returns:
            Normalized stack trace or None
        """
        if not stack_trace:
            return None

        lines = stack_trace.split("\n")
        normalized = []

        for line in lines[:5]:  # Top 5 frames
            # Extract function name and module
            # Pattern: #0 0x... in function_name module
            match = re.search(r"in\s+([^\s]+)\s+(.+)", line)
            if match:
                func = match.group(1)
                module = match.group(2).strip()
                # Remove addresses from module
                module = re.sub(r"0x[0-9a-f]+", "0xADDR", module)
                normalized.append(f"{func}:{module}")
            elif line.strip().startswith("#"):
                # Try to extract just function name
                parts = line.split()
                if len(parts) > 3:
                    normalized.append(parts[3])

        if normalized:
            return "|".join(normalized)
        return None

    @staticmethod
    def generate_raw_fingerprint(crash_input: bytes) -> str:
        """Generate fingerprint from raw crash input.

        Args:
            crash_input: Raw crash input bytes

        Returns:
            SHA256 hash of input
        """
        return hashlib.sha256(crash_input).hexdigest()


class CrashDeduplicator:
    """Deduplicate crashes based on fingerprints."""

    def __init__(self):
        """Initialize deduplicator."""
        self.fingerprint_map: Dict[str, List[int]] = {}  # fingerprint -> crash IDs

    def register_crash(
        self,
        crash_id: int,
        fingerprint: CrashFingerprint,
    ) -> bool:
        """Register a crash with its fingerprint.

        Args:
            crash_id: Crash ID
            fingerprint: CrashFingerprint

        Returns:
            True if new unique crash, False if duplicate
        """
        fp = fingerprint.fingerprint

        if fp not in self.fingerprint_map:
            self.fingerprint_map[fp] = []
            is_unique = True
        else:
            is_unique = False

        self.fingerprint_map[fp].append(crash_id)
        return is_unique

    def is_duplicate(self, fingerprint: CrashFingerprint) -> bool:
        """Check if fingerprint is a duplicate.

        Args:
            fingerprint: CrashFingerprint

        Returns:
            True if duplicate
        """
        return fingerprint.fingerprint in self.fingerprint_map

    def get_related_crashes(self, fingerprint: CrashFingerprint) -> List[int]:
        """Get all crash IDs with same fingerprint.

        Args:
            fingerprint: CrashFingerprint

        Returns:
            List of crash IDs
        """
        return self.fingerprint_map.get(fingerprint.fingerprint, [])
