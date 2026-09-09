"""Sanitizer output parsing and analysis."""

from dataclasses import dataclass
from typing import Dict, Optional, List, Tuple
import re

from zerodaylab.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SanitiserReport:
    """Parsed sanitizer report."""

    sanitizer: str  # asan, ubsan, lsan, msan
    error_type: str  # heap-buffer-overflow, use-after-free, etc.
    summary: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function: Optional[str] = None
    module: Optional[str] = None
    fault_address: Optional[str] = None
    allocation_size: Optional[int] = None
    access_size: Optional[int] = None
    access_type: Optional[str] = None
    shadow_bytes: Optional[str] = None
    registers: Dict[str, str] = None
    raw_output: str = ""

    def __post_init__(self):
        if self.registers is None:
            self.registers = {}

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "sanitizer": self.sanitizer,
            "error_type": self.error_type,
            "summary": self.summary,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "function": self.function,
            "module": self.module,
            "fault_address": self.fault_address,
            "allocation_size": self.allocation_size,
            "access_size": self.access_size,
            "access_type": self.access_type,
            "shadow_bytes": self.shadow_bytes,
            "registers": self.registers,
        }


class SanitizerParser:
    """Parse sanitizer output reports."""

    # ASAN error patterns
    ASAN_PATTERNS = {
        "heap-buffer-overflow": r"heap-buffer-overflow",
        "stack-buffer-overflow": r"stack-buffer-overflow",
        "global-buffer-overflow": r"global-buffer-overflow",
        "use-after-free": r"use-after-free",
        "double-free": r"double-free",
        "invalid-free": r"attempting double-free",
        "memory-leak": r"LeakSanitizer",
        "segmentation-fault": r"SEGV on unknown address",
    }

    # UBSAN patterns
    UBSAN_PATTERNS = {
        "division-by-zero": r"division by zero",
        "integer-overflow": r"signed integer overflow",
        "undefined-shift": r"shift exponent",
        "invalid-bool": r"load of value",
        "null-pointer-dereference": r"null pointer",
    }

    def parse(self, output: str) -> Optional[SanitiserReport]:
        """Parse sanitizer output.

        Args:
            output: Sanitizer output text

        Returns:
            Parsed SanitiserReport or None
        """
        if not output:
            return None

        # Detect sanitizer type
        if "AddressSanitizer" in output or "ASAN" in output:
            return self._parse_asan(output)
        elif "UndefinedBehaviorSanitizer" in output or "UBSAN" in output:
            return self._parse_ubsan(output)
        elif "LeakSanitizer" in output or "LSan" in output:
            return self._parse_lsan(output)
        elif "MemorySanitizer" in output or "MSan" in output:
            return self._parse_msan(output)

        logger.debug("Could not determine sanitizer type from output")
        return None

    def _parse_asan(self, output: str) -> Optional[SanitiserReport]:
        """Parse AddressSanitizer output."""
        # Detect error type
        error_type = "memory-error"
        for error_name, pattern in self.ASAN_PATTERNS.items():
            if re.search(pattern, output):
                error_type = error_name
                break

        # Extract location
        file_path, line_number, function = self._extract_location(output)

        # Extract addresses
        fault_address = self._extract_fault_address(output)
        allocation_size = self._extract_allocation_size(output)
        access_size = self._extract_access_size(output)

        # Extract access type
        access_type = "READ"
        if re.search(r"WRITE", output):
            access_type = "WRITE"

        summary = f"AddressSanitizer: {error_type}"
        if file_path:
            summary += f" in {function or 'unknown'}()"

        report = SanitiserReport(
            sanitizer="asan",
            error_type=error_type,
            summary=summary,
            file_path=file_path,
            line_number=line_number,
            function=function,
            fault_address=fault_address,
            allocation_size=allocation_size,
            access_size=access_size,
            access_type=access_type,
            raw_output=output,
        )

        return report

    def _parse_ubsan(self, output: str) -> Optional[SanitiserReport]:
        """Parse UndefinedBehaviorSanitizer output."""
        error_type = "undefined-behavior"
        for error_name, pattern in self.UBSAN_PATTERNS.items():
            if re.search(pattern, output):
                error_type = error_name
                break

        # Extract location
        file_path, line_number, function = self._extract_location(output)

        summary = f"UndefinedBehaviorSanitizer: {error_type}"
        if file_path:
            summary += f" at {file_path}:{line_number}"

        report = SanitiserReport(
            sanitizer="ubsan",
            error_type=error_type,
            summary=summary,
            file_path=file_path,
            line_number=line_number,
            function=function,
            raw_output=output,
        )

        return report

    def _parse_lsan(self, output: str) -> Optional[SanitiserReport]:
        """Parse LeakSanitizer output."""
        error_type = "memory-leak"

        # Extract location
        file_path, line_number, function = self._extract_location(output)

        summary = "LeakSanitizer: memory-leak"
        if file_path:
            summary += f" in {function}()"

        report = SanitiserReport(
            sanitizer="lsan",
            error_type=error_type,
            summary=summary,
            file_path=file_path,
            line_number=line_number,
            function=function,
            raw_output=output,
        )

        return report

    def _parse_msan(self, output: str) -> Optional[SanitiserReport]:
        """Parse MemorySanitizer output."""
        error_type = "uninitialized-memory-use"

        # Extract location
        file_path, line_number, function = self._extract_location(output)

        summary = "MemorySanitizer: use of uninitialized memory"
        if file_path:
            summary += f" at {file_path}:{line_number}"

        report = SanitiserReport(
            sanitizer="msan",
            error_type=error_type,
            summary=summary,
            file_path=file_path,
            line_number=line_number,
            function=function,
            raw_output=output,
        )

        return report

    def _extract_location(
        self,
        output: str,
    ) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        """Extract file, line number, and function from output."""
        # Pattern: /path/to/file.c:123:45 in function_name
        match = re.search(
            r"(/[^:]+):(\d+):(\d+)\s+in\s+([^\s]+)",
            output,
        )
        if match:
            return match.group(1), int(match.group(2)), match.group(4)

        # Alternative pattern: at /path/to/file.c:123
        match = re.search(r"at\s+([^:]+):(\d+)", output)
        if match:
            return match.group(1), int(match.group(2)), None

        return None, None, None

    def _extract_fault_address(self, output: str) -> Optional[str]:
        """Extract fault address from output."""
        # Pattern: address 0x7f123456 at pc
        match = re.search(r"address\s+(0x[0-9a-f]+)", output)
        if match:
            return match.group(1)
        return None

    def _extract_allocation_size(self, output: str) -> Optional[int]:
        """Extract allocation size from output."""
        # Pattern: allocated 32 bytes
        match = re.search(r"allocated\s+(\d+)\s+bytes", output)
        if match:
            return int(match.group(1))
        return None

    def _extract_access_size(self, output: str) -> Optional[int]:
        """Extract access size from output."""
        # Pattern: access 8 bytes
        match = re.search(r"access\s+(\d+)\s+bytes", output)
        if match:
            return int(match.group(1))
        return None

    def extract_stack_trace(self, output: str) -> str:
        """Extract stack trace from sanitizer output."""
        lines = output.split("\n")
        stack_trace = []
        in_stack = False

        for line in lines:
            if "stack trace:" in line.lower() or "call stack:" in line.lower():
                in_stack = True
                continue

            if in_stack:
                if line.strip().startswith("#"):
                    stack_trace.append(line)
                elif stack_trace and not line.strip():
                    break

        return "\n".join(stack_trace)
