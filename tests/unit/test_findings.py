"""Tests for triage and severity assessment."""

import pytest
from pathlib import Path
from zerodaylab.findings.triage import CrashTriage, TriageStatus
from zerodaylab.findings.severity import SeverityAssessor, SeverityLevel, ConfidenceLevel
from zerodaylab.findings.lifecycle import FindingLifecycle, FindingStatus
from zerodaylab.crashes.collector import CrashCollector
from zerodaylab.core.config import Config


def test_severity_assessment():
    """Test severity assessment."""
    assessor = SeverityAssessor()

    # Test critical
    result = assessor.assess(
        "heap-buffer-overflow",
        "asan",
        True,
        memory_corruption=True,
    )
    assert result.severity == SeverityLevel.CRITICAL
    assert result.confidence == ConfidenceLevel.CONFIRMED

    # Test high
    result = assessor.assess(
        "global-buffer-overflow",
        "asan",
        True,
        memory_corruption=True,
    )
    assert result.severity == SeverityLevel.HIGH

    # Test medium
    result = assessor.assess(
        "division-by-zero",
        "ubsan",
        True,
        memory_corruption=False,
    )
    assert result.severity == SeverityLevel.MEDIUM


def test_severity_assessor_exploitation_difficulty():
    """Test exploitation difficulty assessment."""
    assessor = SeverityAssessor()

    # Easy
    result = assessor.assess(
        "heap-buffer-overflow",
        "asan",
        True,
    )
    assert result.exploitation_difficulty == "easy"

    # Moderate
    result = assessor.assess(
        "double-free",
        "asan",
        True,
    )
    assert result.exploitation_difficulty == "moderate"

    # Hard
    result = assessor.assess(
        "memory-leak",
        "lsan",
        True,
    )
    assert result.exploitation_difficulty == "hard"


def test_crash_triage(temp_workspace):
    """Test crash triage."""
    # Create test crash file
    crash_file = temp_workspace / "crash1"
    crash_file.write_bytes(b"crash data")

    # Collect crash
    collector = CrashCollector(Config().database_path)
    artifact = collector.collect_crash(crash_file, campaign_id=1)
    crash = collector.store_crash(artifact)

    # Triage crash
    triage = CrashTriage(Config().database_path)
    result = triage.triage_crash(crash.id)

    assert result.status == TriageStatus.TRIAGED
    assert result.crash_id == crash.id


def test_finding_lifecycle():
    """Test finding lifecycle."""
    lifecycle = FindingLifecycle(Config().database_path)

    # Create finding
    finding = lifecycle.create_finding(
        project_id=1,
        fingerprint_id=1,
        severity="HIGH",
        confidence="CONFIRMED",
        description="Test finding",
    )

    assert finding.id is not None
    assert finding.status == "NEW"

    # Update status
    lifecycle.update_status(finding.id, FindingStatus.TRIAGED)
    updated = lifecycle.get_finding(finding.id)
    assert updated.status == "TRIAGED"


def test_finding_project_summary():
    """Test finding project summary."""
    lifecycle = FindingLifecycle(Config().database_path)

    # Create multiple findings
    lifecycle.create_finding(
        project_id=1,
        fingerprint_id=1,
        severity="CRITICAL",
        confidence="CONFIRMED",
    )
    lifecycle.create_finding(
        project_id=1,
        fingerprint_id=2,
        severity="HIGH",
        confidence="HIGH",
    )

    summary = lifecycle.get_project_summary(1)
    assert summary["total_findings"] >= 2
    assert summary["critical"] >= 1
    assert summary["high"] >= 1
