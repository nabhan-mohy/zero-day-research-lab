"""Tests for crash collection and parsing."""

import pytest
from pathlib import Path
from zerodaylab.crashes.collector import CrashCollector, CrashArtifact
from zerodaylab.crashes.parser import SanitizerParser, SanitiserReport
from zerodaylab.crashes.fingerprint import FingerprintGenerator, CrashDeduplicator, CrashFingerprint
from zerodaylab.core.config import Config


def test_crash_artifact_creation():
    """Test creating crash artifact."""
    artifact = CrashArtifact(
        file_path=Path("/tmp/crash1"),
        input_sha256="abc123",
        input_size=1024,
        campaign_id=1,
    )
    assert artifact.input_sha256 == "abc123"
    assert artifact.campaign_id == 1


def test_crash_artifact_to_dict():
    """Test crash artifact to_dict."""
    artifact = CrashArtifact(
        file_path=Path("/tmp/crash1"),
        input_sha256="abc123",
        input_size=1024,
        campaign_id=1,
        signal=11,
    )
    d = artifact.to_dict()
    assert d["input_sha256"] == "abc123"
    assert d["signal"] == 11


def test_crash_collector_collect(temp_workspace):
    """Test crash collection."""
    # Create test crash file
    crash_file = temp_workspace / "crash1"
    crash_file.write_bytes(b"crash data")

    collector = CrashCollector(Config().database_path)
    artifact = collector.collect_crash(crash_file, campaign_id=1)

    assert artifact.input_sha256 is not None
    assert artifact.input_size == 10
    assert artifact.campaign_id == 1


def test_crash_collector_collect_from_directory(temp_workspace):
    """Test collecting crashes from directory."""
    crash_dir = temp_workspace / "crashes"
    crash_dir.mkdir()

    # Create multiple crash files
    for i in range(3):
        crash_file = crash_dir / f"crash{i}"
        crash_file.write_bytes(f"crash data {i}".encode())

    collector = CrashCollector(Config().database_path)
    artifacts = collector.collect_from_directory(crash_dir, campaign_id=1)

    assert len(artifacts) == 3
    for artifact in artifacts:
        assert artifact.campaign_id == 1


def test_sanitizer_parser_asan():
    """Test parsing AddressSanitizer output."""
    asan_output = """=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on unknown address
address 0x60300000eff0 at pc 0x50b2b9 bp 0x7ffc64c00a00 sp 0x7ffc64c00990
READ of size 4 at 0x60300000eff0 thread T0
    #0 0x50b2b8 in main /path/to/test.c:123 (binary+0x50b2b8)
    #1 0x7f1234567890 in __libc_start_main
"""

    parser = SanitizerParser()
    report = parser.parse(asan_output)

    assert report is not None
    assert report.sanitizer == "asan"
    assert report.error_type == "heap-buffer-overflow"
    assert report.access_type == "READ"


def test_sanitizer_parser_ubsan():
    """Test parsing UndefinedBehaviorSanitizer output."""
    ubsan_output = """runtime error: division by zero
    at /path/to/test.c:42:10 in
"""

    parser = SanitizerParser()
    report = parser.parse(ubsan_output)

    assert report is not None
    assert report.sanitizer == "ubsan"
    assert report.error_type == "division-by-zero"


def test_fingerprint_generation():
    """Test crash fingerprint generation."""
    report = SanitiserReport(
        sanitizer="asan",
        error_type="heap-buffer-overflow",
        summary="test",
        function="parse_input",
        module="libparser.so",
    )

    fingerprint = FingerprintGenerator.generate(report)
    assert fingerprint.sanitizer == "asan"
    assert fingerprint.error_type == "heap-buffer-overflow"
    assert len(fingerprint.fingerprint) == 64  # SHA256


def test_fingerprint_raw():
    """Test raw fingerprint generation."""
    data = b"crash input data"
    fp = FingerprintGenerator.generate_raw_fingerprint(data)
    assert len(fp) == 64  # SHA256

    # Same data should produce same fingerprint
    fp2 = FingerprintGenerator.generate_raw_fingerprint(data)
    assert fp == fp2


def test_crash_deduplicator():
    """Test crash deduplication."""
    dedup = CrashDeduplicator()

    # Create two crashes with same fingerprint
    fp1 = CrashFingerprint(
        fingerprint="abc123",
        category="heap-buffer-overflow",
        sanitizer="asan",
        error_type="heap-buffer-overflow",
    )

    # Register first crash (should be unique)
    is_unique1 = dedup.register_crash(1, fp1)
    assert is_unique1 is True

    # Register second crash with same fingerprint (should be duplicate)
    is_unique2 = dedup.register_crash(2, fp1)
    assert is_unique2 is False

    # Check duplicate detection
    assert dedup.is_duplicate(fp1) is True

    # Get related crashes
    related = dedup.get_related_crashes(fp1)
    assert len(related) == 2
    assert 1 in related
    assert 2 in related


def test_sanitizer_parser_extract_location():
    """Test extracting location from sanitizer output."""
    output = """AddressSanitizer: heap-buffer-overflow
    #0 0x50b2b8 in my_function /path/to/file.c:123:10 (binary+0x50b2b8)
"""
    parser = SanitizerParser()
    file_path, line_num, func = parser._extract_location(output)

    assert file_path == "/path/to/file.c"
    assert line_num == 123
    assert func == "my_function"
