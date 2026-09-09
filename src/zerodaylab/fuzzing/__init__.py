"""Fuzzer plugin architecture."""

from zerodaylab.fuzzing.plugins.base import FuzzerPlugin
from zerodaylab.fuzzing.plugins.registry import FuzzerRegistry
from zerodaylab.fuzzing.executor import FuzzerExecutor

__all__ = ["FuzzerPlugin", "FuzzerRegistry", "FuzzerExecutor"]
