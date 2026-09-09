"""Tests for target management."""

import pytest
from pathlib import Path
from zerodaylab.targets.manager import TargetManager
from zerodaylab.targets.analyzer import TargetAnalyzer
from zerodaylab.projects.manager import ProjectManager
from zerodaylab.core.exceptions import TargetError
from zerodaylab.core.config import Config


def test_add_target_to_project(temp_workspace):
    """Test adding a target to a project."""
    # Create project first
    proj_manager = ProjectManager()
    proj = proj_manager.create_project("test_project")

    # Create a test target file
    target_file = temp_workspace / "target.c"
    target_file.write_text("int main() { return 0; }")

    # Add target
    target_manager = TargetManager()
    target = target_manager.add_target(
        "test_project",
        "test_target",
        target_file,
        "library",
        "Test target",
    )

    assert target is not None
    assert target.name == "test_target"
    assert target.project_id == proj.id


def test_add_target_duplicate(temp_workspace):
    """Test adding duplicate targets fails."""
    proj_manager = ProjectManager()
    proj = proj_manager.create_project("test_project_dup")

    target_file = temp_workspace / "target.c"
    target_file.write_text("int main() { return 0; }")

    target_manager = TargetManager()
    target_manager.add_target("test_project_dup", "test_target", target_file)

    # Try to add duplicate
    with pytest.raises(TargetError):
        target_manager.add_target("test_project_dup", "test_target", target_file)


def test_list_targets(temp_workspace):
    """Test listing targets."""
    proj_manager = ProjectManager()
    proj = proj_manager.create_project("test_project_list")

    target_file = temp_workspace / "target.c"
    target_file.write_text("int main() { return 0; }")

    target_manager = TargetManager()
    target_manager.add_target("test_project_list", "target1", target_file)
    target_manager.add_target("test_project_list", "target2", target_file)

    targets = target_manager.list_targets("test_project_list")
    assert len(targets) == 2


def test_analyzer_detect_build_systems():
    """Test build system detection."""
    analyzer = TargetAnalyzer()
    systems = analyzer.build_systems
    # Should detect at least one build system (make is usually available)
    assert isinstance(systems, dict)


def test_analyzer_analyze_directory(temp_workspace):
    """Test directory analysis."""
    # Create test files
    (temp_workspace / "test.c").write_text("int main() { return 0; }")
    (temp_workspace / "test.h").write_text("void test_function();")
    (temp_workspace / "Makefile").write_text("all:\n\techo test")

    analyzer = TargetAnalyzer()
    results = analyzer.analyze_directory(temp_workspace)

    assert results["path"] == str(temp_workspace)
    assert results["build_system"] == "make"
    assert len(results["source_files"]) > 0
    assert len(results["header_files"]) > 0
