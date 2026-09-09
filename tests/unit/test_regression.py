"""Tests for regression testing."""

import pytest
from pathlib import Path
from zerodaylab.regression import RegressionTester, RegressionTestResult
from zerodaylab.core.exceptions import CrashAnalysisError


def test_regression_tester_initialization(temp_workspace):
    """Test regression tester initialization."""
    # Create dummy binary
    binary = temp_workspace / "binary"
    binary.write_text("#!/bin/bash\necho test")
    binary.chmod(0o755)

    tester = RegressionTester(binary)
    assert tester.target_binary == binary


def test_regression_tester_invalid_binary():
    """Test regression tester with invalid binary."""
    with pytest.raises(CrashAnalysisError):
        RegressionTester(Path("/nonexistent/binary"))


def test_regression_test_result():
    """Test regression test result."""
    result = RegressionTestResult(
        test_name="test1",
        crash_input_path=Path("/tmp/crash1"),
        target_binary=Path("/usr/bin/true"),
        reproduced=True,
        execution_time=0.5,
        exit_code=0,
    )

    assert result.test_name == "test1"
    assert result.reproduced is True
