"""Combine monitoring, parsing, and persistence into one operation.

The :class:`CrashDetector` is the boundary Phase 4 will build on: it takes a
target, an input, and a monitor configuration, runs the target, and produces a
:class:`~kmcs.core.models.Crash` domain entity populated **only** with facts
observed during execution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from kmcs.analysis.crash_monitor import (
    CrashMonitor,
    CrashObservation,
    MonitorConfig,
)
from kmcs.core import models
from kmcs.core.exceptions import KMCSException
from kmcs.database.database import Database
from kmcs.database.models import CrashRow
from kmcs.analysis.classifier import CrashClassifier
from kmcs.analysis.fingerprint import CrashFingerprinter
from kmcs.analysis.severity import SeverityAssessor


logger = logging.getLogger(__name__)

__all__ = [
    "DetectionError",
    "DetectionResult",
    "CrashDetector",
]

class CrashDetector:
    def __init__(
        self,
        *,
        monitor: CrashMonitor | None = None,
        database: Database | None = None,
        classifier: CrashClassifier | None = None,
        fingerprinter: CrashFingerprinter | None = None,
        severity_assessor: SeverityAssessor | None = None,
    ) -> None:
        self._monitor = monitor or CrashMonitor()
        self._database = database
        self._classifier = classifier or CrashClassifier()
        self._fingerprinter = fingerprinter or CrashFingerprinter()
        self._severity = severity_assessor or SeverityAssessor()

    # ... run_and_record unchanged ...

    def _build_crash(
        self,
        observation: CrashObservation,
        *,
        campaign_id: str | None,
        target_id: str | None,
    ) -> models.Crash:
        report = observation.report

        classification_result = self._classifier.classify(report)
        fingerprint = self._fingerprinter.fingerprint(report)
        severity_result = self._severity.assess(
            report, classification_result.classification
        )

        primary = report.primary_report
        sanitizer_kind = primary.sanitizer if primary is not None else None

        description = "Crash detected"
        if primary is not None and primary.error_type:
            description = f"{primary.sanitizer.value}: {primary.error_type}"
        elif report.signal_name is not None:
            description = f"terminated by {report.signal_name}"

        stderr_excerpt = report.stderr[-4096:] if report.stderr else None
        stdout_excerpt = report.stdout[-4096:] if report.stdout else None

        stack_trace: str | None = None
        if report.stack_frames:
            stack_trace = "\n".join(frame.raw for frame in report.stack_frames)

        return models.Crash(
            campaign_id=campaign_id,
            target_id=target_id,
            description=description,
            input_path=observation.input_path,
            evidence_path=observation.stderr_path,
            signal=report.signal_number,
            exit_code=report.exit_code,
            sanitizer=sanitizer_kind,
            classification=classification_result.classification,
            severity=severity_result.severity,
            fingerprint=fingerprint.value,
            stack_trace=stack_trace,
            source_location=report.source_location,
            stdout_excerpt=stdout_excerpt,
            stderr_excerpt=stderr_excerpt,
            metadata={
                "evidence_dir": str(observation.evidence_dir),
                "stdout_path": str(observation.stdout_path),
                "duration_seconds": observation.duration_seconds,
                "timed_out": observation.timed_out,
                "sanitizer_options": observation.environment,
                "classification_confidence": classification_result.confidence.value,
                "classification_evidence": list(classification_result.evidence),
                "severity_rationale": severity_result.rationale,
                "severity_factors": [
                    {"factor": k, "value": v} for k, v in severity_result.factors
                ],
                "fingerprint_canonical": fingerprint.canonical,
            },
        )


class DetectionError(KMCSException):
    exit_code = 41


@dataclass(slots=True)
class DetectionResult:
    observation: CrashObservation
    crash: models.Crash | None
    persisted: bool

    @property
    def crashed(self) -> bool:
        return self.observation.report.crashed


class CrashDetector:
    """Runs targets and, on a crash, persists a :class:`Crash` record."""

    def __init__(
        self,
        *,
        monitor: CrashMonitor | None = None,
        database: Database | None = None,
    ) -> None:
        self._monitor = monitor or CrashMonitor()
        self._database = database

    # ------------------------------------------------------------------ public

    def run_and_record(
        self,
        config: MonitorConfig,
        *,
        input_path: Path | None = None,
        input_bytes: bytes | None = None,
        campaign_id: str | None = None,
        target_id: str | None = None,
        persist: bool = True,
    ) -> DetectionResult:
        observation = self._monitor.run(
            config, input_path=input_path, input_bytes=input_bytes
        )

        if not observation.crashed:
            return DetectionResult(
                observation=observation, crash=None, persisted=False
            )

        crash = self._build_crash(observation, campaign_id=campaign_id, target_id=target_id)

        if persist and self._database is not None:
            with self._database.session() as session:
                session.add(CrashRow.from_domain(crash))
            logger.info(
                "Recorded crash %s (classification=%s, signal=%s)",
                crash.id,
                crash.classification.value,
                crash.signal,
            )
            return DetectionResult(observation=observation, crash=crash, persisted=True)

        return DetectionResult(observation=observation, crash=crash, persisted=False)

    # ------------------------------------------------------------------ internals

    @staticmethod
    def _build_crash(
        observation: CrashObservation,
        *,
        campaign_id: str | None,
        target_id: str | None,
    ) -> models.Crash:
        report = observation.report

        primary = report.primary_report
        sanitizer_kind = primary.sanitizer if primary is not None else None

        description = "Crash detected"
        if primary is not None and primary.error_type:
            description = f"{primary.sanitizer.value}: {primary.error_type}"
        elif report.signal_name is not None:
            description = f"terminated by {report.signal_name}"

        stderr_excerpt = report.stderr[-4096:] if report.stderr else None
        stdout_excerpt = report.stdout[-4096:] if report.stdout else None

        stack_trace: str | None = None
        if report.stack_frames:
            stack_trace = "\n".join(frame.raw for frame in report.stack_frames)

        return models.Crash(
            campaign_id=campaign_id,
            target_id=target_id,
            description=description,
            input_path=observation.input_path,
            evidence_path=observation.stderr_path,
            signal=report.signal_number,
            exit_code=report.exit_code,
            sanitizer=sanitizer_kind,
            classification=report.classification,
            stack_trace=stack_trace,
            source_location=report.source_location,
            stdout_excerpt=stdout_excerpt,
            stderr_excerpt=stderr_excerpt,
            metadata={
                "evidence_dir": str(observation.evidence_dir),
                "stdout_path": str(observation.stdout_path),
                "duration_seconds": observation.duration_seconds,
                "timed_out": observation.timed_out,
                "sanitizer_options": observation.environment,
            },
        )
