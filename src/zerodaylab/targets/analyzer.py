"""Target discovery and analysis."""

from pathlib import Path
from typing import Dict, List, Optional
import subprocess
from zerodaylab.core.logger import get_logger
from zerodaylab.core.exceptions import TargetError
from zerodaylab.security.process_handler import ProcessHandler

logger = get_logger(__name__)


class TargetAnalyzer:
    """Analyze targets for fuzzing opportunities."""

    def __init__(self):
        """Initialize target analyzer."""
        self.build_systems = self._detect_build_systems()
        self.symbols_cache = {}

    def analyze_directory(self, path: Path) -> Dict:
        """Analyze a directory for fuzzing targets.

        Args:
            path: Path to analyze

        Returns:
            Dictionary with analysis results
        """
        path = Path(path).resolve()
        if not path.exists():
            raise TargetError(f"Path does not exist: {path}")

        logger.info(f"Analyzing directory: {path}")

        results = {
            "path": str(path),
            "build_system": self._detect_build_system(path),
            "build_files": self._find_build_files(path),
            "source_files": self._find_source_files(path),
            "header_files": self._find_header_files(path),
            "binaries": self._find_binaries(path),
            "fuzzing_candidates": self._find_fuzzing_candidates(path),
            "existing_fuzz_targets": self._find_existing_fuzz_targets(path),
        }

        return results

    def _detect_build_systems(self) -> Dict[str, str]:
        """Detect available build systems.

        Returns:
            Dict of build systems and their paths
        """
        systems = {}
        build_tools = {
            "cmake": "cmake",
            "make": "make",
            "autotools": "autoconf",
            "meson": "meson",
            "bazel": "bazel",
            "cargo": "cargo",
        }

        for name, exe in build_tools.items():
            try:
                exit_code, _, _ = ProcessHandler.execute(
                    [exe, "--version"], capture_output=True, timeout=5
                )
                if exit_code == 0:
                    systems[name] = exe
                    logger.debug(f"Found build system: {name}")
            except Exception:
                pass

        return systems

    def _detect_build_system(self, path: Path) -> Optional[str]:
        """Detect the build system used by a project.

        Args:
            path: Project path

        Returns:
            Build system name or None
        """
        indicators = {
            "cmake": "CMakeLists.txt",
            "make": "Makefile",
            "autotools": "configure.ac",
            "meson": "meson.build",
            "bazel": "BUILD",
            "cargo": "Cargo.toml",
        }

        for system, indicator in indicators.items():
            if (path / indicator).exists():
                return system

        return None

    def _find_build_files(self, path: Path) -> List[str]:
        """Find build configuration files.

        Args:
            path: Project path

        Returns:
            List of build file paths
        """
        patterns = [
            "CMakeLists.txt",
            "Makefile",
            "configure.ac",
            "setup.py",
            "meson.build",
            "BUILD",
            "Cargo.toml",
        ]
        build_files = []
        for pattern in patterns:
            matches = list(path.glob(f"**/{pattern}"))
            build_files.extend(str(m) for m in matches)
        return build_files[:20]  # Limit results

    def _find_source_files(self, path: Path) -> List[str]:
        """Find C/C++ source files.

        Args:
            path: Project path

        Returns:
            List of source file paths
        """
        extensions = ["*.c", "*.cc", "*.cpp", "*.cxx", "*.c++"]
        files = []
        for ext in extensions:
            matches = list(path.glob(f"**/{ext}"))
            files.extend(str(m) for m in matches)
        return files[:50]  # Limit results

    def _find_header_files(self, path: Path) -> List[str]:
        """Find C/C++ header files.

        Args:
            path: Project path

        Returns:
            List of header file paths
        """
        extensions = ["*.h", "*.hpp", "*.hxx"]
        files = []
        for ext in extensions:
            matches = list(path.glob(f"**/{ext}"))
            files.extend(str(m) for m in matches)
        return files[:50]  # Limit results

    def _find_binaries(self, path: Path) -> List[str]:
        """Find executable binaries.

        Args:
            path: Project path

        Returns:
            List of binary paths
        """
        binaries = []
        # Look in common locations
        for location in ["bin", "build", "dist", "output", "."]:
            loc_path = path / location
            if loc_path.exists():
                for item in loc_path.iterdir():
                    if item.is_file() and self._is_executable(item):
                        binaries.append(str(item))
        return binaries[:20]  # Limit results

    def _find_fuzzing_candidates(self, path: Path) -> List[Dict]:
        """Find functions suitable for fuzzing.

        Args:
            path: Project path

        Returns:
            List of candidate functions
        """
        candidates = []

        # Look for parser-like APIs in headers
        parser_keywords = [
            "parse",
            "decode",
            "deserialize",
            "read",
            "process",
            "handle",
            "load",
        ]

        headers = self._find_header_files(path)
        for header_path in headers[:10]:  # Analyze first 10 headers
            try:
                with open(header_path, "r", errors="ignore") as f:
                    content = f.read()
                    for keyword in parser_keywords:
                        if keyword in content.lower():
                            candidates.append(
                                {
                                    "type": "api_candidate",
                                    "header": header_path,
                                    "keyword": keyword,
                                }
                            )
            except Exception as e:
                logger.debug(f"Failed to read {header_path}: {e}")

        return candidates[:20]  # Limit results

    def _find_existing_fuzz_targets(self, path: Path) -> List[str]:
        """Find existing fuzz targets.

        Args:
            path: Project path

        Returns:
            List of fuzz target paths
        """
        patterns = ["*fuzz*", "*test*", "*harness*"]
        targets = []
        source_extensions = ["*.c", "*.cc", "*.cpp"]

        for pattern in patterns:
            for ext in source_extensions:
                matches = list(path.glob(f"**/{pattern}{ext}"))
                for m in matches:
                    # Quick heuristic: fuzz target likely contains LLVMFuzzerTestOneInput
                    try:
                        content = m.read_text(errors="ignore")
                        if "LLVMFuzzerTestOneInput" in content or "main" in content:
                            targets.append(str(m))
                    except Exception:
                        pass

        return targets[:20]  # Limit results

    def _is_executable(self, path: Path) -> bool:
        """Check if a file is executable.

        Args:
            path: File path

        Returns:
            True if executable
        """
        import os
        return os.access(path, os.X_OK)

    def extract_symbols(self, binary_path: Path) -> Dict[str, List[str]]:
        """Extract symbols from a binary.

        Args:
            binary_path: Path to binary

        Returns:
            Dict with symbol information
        """
        if str(binary_path) in self.symbols_cache:
            return self.symbols_cache[str(binary_path)]

        binary_path = Path(binary_path).resolve()
        if not self._is_executable(binary_path):
            raise TargetError(f"Not an executable: {binary_path}")

        result = {
            "functions": [],
            "libraries": [],
            "exports": [],
        }

        # Try nm command
        try:
            exit_code, stdout, _ = ProcessHandler.execute(
                ["nm", str(binary_path)], capture_output=True, timeout=10
            )
            if exit_code == 0 and stdout:
                for line in stdout.split("\n"):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            result["functions"].append(parts[-1])
        except Exception as e:
            logger.debug(f"Failed to extract symbols with nm: {e}")

        self.symbols_cache[str(binary_path)] = result
        return result
