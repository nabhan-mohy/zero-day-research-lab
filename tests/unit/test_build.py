"""Tests for build manager."""

import pytest
from pathlib import Path
from zerodaylab.build.manager import BuildManager
from zerodaylab.build.builders import CMakeBuilder, MakeBuilder
from zerodaylab.core.config import Config
from zerodaylab.core.exceptions import BuildError
from zerodaylab.projects.manager import ProjectManager
from zerodaylab.targets.manager import TargetManager
from zerodaylab.instrumentation import InstrumentationProfile, InstrumentationLaboratory


def test_build_system_detection(temp_workspace):
    """Test build system detection."""
    # Create CMakeLists.txt
    (temp_workspace / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\nproject(Test)"
    )

    manager = BuildManager()
    system = manager.detect_build_system(temp_workspace)
    assert system == "cmake"

    # Create Makefile
    makefile_dir = temp_workspace / "make_project"
    makefile_dir.mkdir()
    (makefile_dir / "Makefile").write_text("all:\n\techo test")

    system = manager.detect_build_system(makefile_dir)
    assert system == "make"


def test_cmake_builder(temp_workspace):
    """Test CMake builder detection."""
    (temp_workspace / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\nproject(Test)"
    )

    builder = CMakeBuilder(temp_workspace)
    assert builder.detect() is True
    assert builder.name == "cmake"


def test_make_builder(temp_workspace):
    """Test Make builder detection."""
    (temp_workspace / "Makefile").write_text("all:\n\techo test")

    builder = MakeBuilder(temp_workspace)
    assert builder.detect() is True
    assert builder.name == "make"


def test_instrumentation_profile_normal():
    """Test normal instrumentation profile."""
    profile = InstrumentationProfile("normal")
    assert profile.is_available()
    flags = profile.get_compiler_flags()
    assert "CC" in flags
    assert "CXX" in flags
    assert "CFLAGS" in flags


def test_instrumentation_profile_asan():
    """Test ASan instrumentation profile."""
    profile = InstrumentationProfile("asan")
    info = profile.get_profile_info()
    assert "asan" in info["sanitizers"]
    flags = profile.get_compiler_flags()
    assert "-fsanitize=address" in flags["CFLAGS"]


def test_instrumentation_laboratory():
    """Test instrumentation laboratory."""
    lab = InstrumentationLaboratory()
    available = lab.get_available_profiles()
    assert isinstance(available, list)
    assert "normal" in available
    
    status = lab.get_profile_status()
    assert "normal" in status
    assert status["normal"]["available"] is True


def test_build_target_with_instrumentation(temp_workspace):
    """Test building target with instrumentation."""
    # Create simple C source
    (temp_workspace / "test.c").write_text(
        "int main() { return 0; }"
    )
    (temp_workspace / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(Test)\n"
        "add_executable(test test.c)"
    )

    # Create project and target
    proj_manager = ProjectManager()
    proj = proj_manager.create_project("build_test")

    target_manager = TargetManager()
    target = target_manager.add_target(
        "build_test",
        "test_target",
        temp_workspace,
        "binary",
    )

    # Test build manager detection
    build_manager = BuildManager()
    builder = build_manager.get_builder(temp_workspace)
    assert builder is not None
    assert builder.name == "cmake"
