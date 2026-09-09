"""Instrumentation and sanitizer profiles."""

from dataclasses import dataclass
from typing import Dict, List, Optional
import shutil

from zerodaylab.core.logger import get_logger
from zerodaylab.security.process_handler import ProcessHandler

logger = get_logger(__name__)


@dataclass
class CompilerCapabilities:
    """Compiler capabilities."""

    asan: bool = False
    ubsan: bool = False
    lsan: bool = False
    msan: bool = False
    coverage: bool = False
    fortify: bool = False


class InstrumentationProfile:
    """Instrumentation profile for builds."""

    PROFILES = {
        "normal": {"flags": ["-O2", "-g"], "sanitizers": []},
        "asan": {"flags": ["-O1", "-g", "-fsanitize=address"], "sanitizers": ["asan"]},
        "ubsan": {"flags": ["-O1", "-g", "-fsanitize=undefined"], "sanitizers": ["ubsan"]},
        "asan_ubsan": {
            "flags": ["-O1", "-g", "-fsanitize=address,undefined"],
            "sanitizers": ["asan", "ubsan"],
        },
        "lsan": {
            "flags": ["-O1", "-g", "-fsanitize=leak"],
            "sanitizers": ["lsan"],
        },
        "msan": {
            "flags": ["-O1", "-g", "-fsanitize=memory", "-fsanitize-memory-track-origins"],
            "sanitizers": ["msan"],
        },
        "coverage": {
            "flags": ["-O0", "-g", "-fprofile-instr-generate", "-fcoverage-mapping"],
            "sanitizers": [],
        },
    }

    def __init__(self, profile_name: str = "normal"):
        """Initialize instrumentation profile.

        Args:
            profile_name: Name of profile (normal, asan, ubsan, etc.)
        """
        if profile_name not in self.PROFILES:
            raise ValueError(f"Unknown profile: {profile_name}")

        self.profile_name = profile_name
        self.profile = self.PROFILES[profile_name]
        self.compiler_capabilities = self._detect_compiler_capabilities()

    def _detect_compiler_capabilities(self) -> CompilerCapabilities:
        """Detect compiler capabilities."""
        caps = CompilerCapabilities()

        # Try clang
        if shutil.which("clang"):
            logger.debug("Found clang")
            # Clang supports all sanitizers
            caps.asan = True
            caps.ubsan = True
            caps.lsan = True
            caps.msan = True
            caps.coverage = True
            caps.fortify = True
        elif shutil.which("gcc"):
            logger.debug("Found gcc")
            # GCC supports most sanitizers
            caps.asan = True
            caps.ubsan = True
            caps.lsan = True
            caps.coverage = True
            caps.fortify = True
            # MSan is Clang-only
            caps.msan = False

        return caps

    def is_available(self) -> bool:
        """Check if profile is available.

        Returns:
            True if profile can be built
        """
        if self.profile_name == "normal":
            return True

        for sanitizer in self.profile["sanitizers"]:
            if sanitizer == "asan" and not self.compiler_capabilities.asan:
                logger.warning("ASan not available")
                return False
            elif sanitizer == "ubsan" and not self.compiler_capabilities.ubsan:
                logger.warning("UBSan not available")
                return False
            elif sanitizer == "lsan" and not self.compiler_capabilities.lsan:
                logger.warning("LSan not available")
                return False
            elif sanitizer == "msan" and not self.compiler_capabilities.msan:
                logger.warning("MSan not available")
                return False

        return True

    def get_compiler_flags(self) -> Dict[str, str]:
        """Get compiler flags for this profile.

        Returns:
            Dict with CC, CXX, CFLAGS, CXXFLAGS
        """
        flags = " ".join(self.profile["flags"])

        return {
            "CC": "clang" if shutil.which("clang") else "gcc",
            "CXX": "clang++" if shutil.which("clang++") else "g++",
            "CFLAGS": flags,
            "CXXFLAGS": flags,
            "LDFLAGS": flags,
        }

    def get_profile_info(self) -> Dict:
        """Get profile information.

        Returns:
            Dict with profile details
        """
        return {
            "name": self.profile_name,
            "flags": self.profile["flags"],
            "sanitizers": self.profile["sanitizers"],
            "available": self.is_available(),
            "compiler_capabilities": {
                "asan": self.compiler_capabilities.asan,
                "ubsan": self.compiler_capabilities.ubsan,
                "lsan": self.compiler_capabilities.lsan,
                "msan": self.compiler_capabilities.msan,
                "coverage": self.compiler_capabilities.coverage,
                "fortify": self.compiler_capabilities.fortify,
            },
        }


class InstrumentationLaboratory:
    """Instrumentation testing and configuration laboratory."""

    def __init__(self):
        """Initialize instrumentation laboratory."""
        self.profiles = {name: InstrumentationProfile(name) for name in InstrumentationProfile.PROFILES}

    def get_available_profiles(self) -> List[str]:
        """Get list of available profiles.

        Returns:
            List of available profile names
        """
        return [name for name, profile in self.profiles.items() if profile.is_available()]

    def get_profile_status(self) -> Dict:
        """Get status of all profiles.

        Returns:
            Dict with profile status
        """
        return {
            name: profile.get_profile_info()
            for name, profile in self.profiles.items()
        }
