"""Tests for security utilities."""

import pytest
from pathlib import Path
from zerodaylab.security.process_handler import ProcessHandler
from zerodaylab.security.path_validator import PathValidator
from zerodaylab.core.exceptions import SecurityError


def test_process_handler_validate_command():
    """Test command validation."""
    # Valid command
    ProcessHandler.validate_command(["echo", "hello"])

    # Invalid commands
    with pytest.raises(SecurityError):
        ProcessHandler.validate_command(None)

    with pytest.raises(SecurityError):
        ProcessHandler.validate_command([])

    with pytest.raises(SecurityError):
        ProcessHandler.validate_command(["nonexistent_command_xyz"])


def test_process_handler_execute(temp_workspace):
    """Test command execution."""
    exit_code, stdout, stderr = ProcessHandler.execute(
        ["echo", "test"],
        capture_output=True,
    )
    assert exit_code == 0
    assert "test" in stdout


def test_path_validator_read_path(temp_workspace):
    """Test read path validation."""
    validator = PathValidator()

    # Create a test file
    test_file = temp_workspace / "test.txt"
    test_file.write_text("test")

    # Valid path
    validated = validator.validate_read_path(test_file)
    assert validated.exists()

    # Non-existent path
    with pytest.raises(SecurityError):
        validator.validate_read_path(temp_workspace / "nonexistent.txt")


def test_path_validator_write_path(temp_workspace):
    """Test write path validation."""
    validator = PathValidator()
    write_path = temp_workspace / "subdir" / "test.txt"

    validated = validator.validate_write_path(write_path)
    assert validated.parent.exists()
