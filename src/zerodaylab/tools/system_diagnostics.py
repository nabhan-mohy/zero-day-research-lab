"""System diagnostics and capability detection."""

import platform
import shutil
from pathlib import Path
from typing import Dict, List, Tuple
from zerodaylab.core.logger import get_logger
from zerodaylab.security.process_handler import ProcessHandler

logger = get_logger(__name__)


class SystemDiagnostics:
    """Run system diagnostics."""

    def run_all_checks(self) -> Dict[str, List[Tuple[str, str, str]]]:
        """Run all diagnostic checks.

        Returns:
            Dict of check results by category
        """
        return {
            "System": self._check_system(),
            "Python": self._check_python(),
            "Compilers": self._check_compilers(),
            "Fuzzing Tools": self._check_fuzzing_tools(),
            "Debuggers": self._check_debuggers(),
            "Container Tools": self._check_container_tools(),
        }

    def _check_system(self) -> List[Tuple[str, str, str]]:
        """Check system information."""
        results = []
        results.append(
            ("OS", "AVAILABLE", f"{platform.system()} {platform.release()}")
        )
        results.append(
            ("Architecture", "AVAILABLE", platform.machine())
        )
        results.append(
            ("Python", "AVAILABLE", platform.python_version())
        )
        return results

    def _check_python(self) -> List[Tuple[str, str, str]]:
        """Check Python dependencies."""
        results = []
        deps = {
            "PySide6": "PySide6",
            "SQLAlchemy": "sqlalchemy",
            "Click": "click",
            "Rich": "rich",
            "Pydantic": "pydantic",
        }

        for name, module in deps.items():
            try:
                __import__(module)
                results.append((name, "AVAILABLE", ""))
            except ImportError:
                results.append((name, "UNAVAILABLE", f"Install with: pip install {module}"))

        return results

    def _check_compilers(self) -> List[Tuple[str, str, str]]:
        """Check compiler availability."""
        results = []
        compilers = {"Clang": "clang", "Clang++": "clang++", "GCC": "gcc", "G++": "g++"}

        for name, exe in compilers.items():
            path = shutil.which(exe)
            if path:
                try:
                    _, stdout, _ = ProcessHandler.execute(
                        [exe, "--version"], capture_output=True, timeout=5
                    )
                    version = stdout.split("\n")[0] if stdout else "unknown"
                    results.append((name, "AVAILABLE", version))
                except Exception:
                    results.append((name, "AVAILABLE", "(version unknown)"))
            else:
                results.append((name, "UNAVAILABLE", f"Install {name} or add to PATH"))

        return results

    def _check_fuzzing_tools(self) -> List[Tuple[str, str, str]]:
        """Check fuzzing tool availability."""
        results = []
        tools = {"AFL++": "afl-fuzz", "libFuzzer": "llvm-symbolizer"}

        for name, exe in tools.items():
            path = shutil.which(exe)
            if path:
                results.append((name, "AVAILABLE", f"Found at {path}"))
            else:
                results.append((name, "UNAVAILABLE", f"Install {name} or add to PATH"))

        # Check LLVM components
        for component in ["llvm-symbolizer", "llvm-cov", "llvm-profdata"]:
            if shutil.which(component):
                results.append((component.capitalize(), "OPTIONAL", ""))

        return results

    def _check_debuggers(self) -> List[Tuple[str, str, str]]:
        """Check debugger availability."""
        results = []
        debuggers = {"GDB": "gdb", "LLDB": "lldb"}

        for name, exe in debuggers.items():
            path = shutil.which(exe)
            if path:
                results.append((name, "AVAILABLE", f"Found at {path}"))
            else:
                results.append((name, "OPTIONAL", f"Install {name} for debugging"))

        return results

    def _check_container_tools(self) -> List[Tuple[str, str, str]]:
        """Check container tools."""
        results = []
        tools = {"Docker": "docker", "Podman": "podman"}

        for name, exe in tools.items():
            path = shutil.which(exe)
            if path:
                results.append((name, "OPTIONAL", f"Found at {path}"))
            else:
                results.append((name, "OPTIONAL", f"Install {name} for sandboxing"))

        return results
