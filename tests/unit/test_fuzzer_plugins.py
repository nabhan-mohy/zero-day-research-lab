"""Tests for fuzzer plugin architecture."""

import pytest
from zerodaylab.fuzzing.plugins.registry import FuzzerRegistry
from zerodaylab.fuzzing.plugins.afl import AFLPlugin
from zerodaylab.fuzzing.plugins.libfuzzer import LibFuzzerPlugin
from zerodaylab.fuzzing.executor import FuzzerExecutor
from zerodaylab.core.exceptions import FuzzerError


def test_fuzzer_registry_initialization():
    """Test fuzzer registry initialization."""
    registry = FuzzerRegistry()
    plugins = registry.list_plugins()
    assert isinstance(plugins, list)
    # Should have at least afl and libfuzzer registered
    assert len(plugins) >= 2


def test_afl_plugin_validation():
    """Test AFL++ plugin validation."""
    plugin = AFLPlugin()
    validation = plugin.validate_environment()
    assert isinstance(validation, dict)
    assert "available" in validation
    assert "version" in validation
    assert "issues" in validation


def test_libfuzzer_plugin_validation():
    """Test libFuzzer plugin validation."""
    plugin = LibFuzzerPlugin()
    validation = plugin.validate_environment()
    assert isinstance(validation, dict)
    assert "available" in validation
    assert "version" in validation


def test_get_available_fuzzer_plugins():
    """Test getting available fuzzer plugins."""
    registry = FuzzerRegistry()
    available = registry.get_available_plugins()
    assert isinstance(available, list)
    # At least libfuzzer should be available
    assert len(available) >= 1


def test_fuzzer_plugin_info():
    """Test getting fuzzer plugin info."""
    registry = FuzzerRegistry()
    # Get info for each registered plugin
    for plugin_name in registry.list_plugins():
        info = registry.get_plugin_info(plugin_name)
        if info:
            assert "name" in info
            assert "description" in info
            assert "available" in info


def test_afl_plugin_get_info():
    """Test AFL plugin get_info."""
    plugin = AFLPlugin()
    info = plugin.get_info()
    assert info["name"] == "afl"
    assert "version" in info
    assert "description" in info


def test_libfuzzer_plugin_get_info():
    """Test libFuzzer plugin get_info."""
    plugin = LibFuzzerPlugin()
    info = plugin.get_info()
    assert info["name"] == "libfuzzer"
    assert "version" in info
    assert "description" in info


def test_fuzzer_executor_initialization():
    """Test fuzzer executor initialization."""
    executor = FuzzerExecutor()
    assert executor.registry is not None


def test_fuzzer_executor_get_available_fuzzers():
    """Test getting available fuzzers from executor."""
    executor = FuzzerExecutor()
    available = executor.get_available_fuzzers()
    assert isinstance(available, list)


def test_fuzzer_executor_get_fuzzer_info():
    """Test getting fuzzer info from executor."""
    executor = FuzzerExecutor()
    fuzzers = executor.registry.list_plugins()
    if fuzzers:
        info = executor.get_fuzzer_info(fuzzers[0])
        assert info is not None


def test_fuzzer_executor_get_all_fuzzers_info():
    """Test getting all fuzzers info from executor."""
    executor = FuzzerExecutor()
    all_info = executor.get_all_fuzzers_info()
    assert isinstance(all_info, dict)
