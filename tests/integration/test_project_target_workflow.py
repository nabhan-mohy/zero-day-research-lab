"""Integration tests for project and target workflow."""

import pytest
from pathlib import Path
from zerodaylab.projects.manager import ProjectManager
from zerodaylab.targets.manager import TargetManager
from zerodaylab.targets.analyzer import TargetAnalyzer


def test_create_project_and_add_targets(temp_workspace):
    """Test creating a project and adding targets."""
    # Create project
    proj_manager = ProjectManager()
    project = proj_manager.create_project(
        "integration_test_project",
        "Integration test project",
    )
    assert project.name == "integration_test_project"

    # Create target files
    (temp_workspace / "library.c").write_text("void parse(char* data) { }")
    (temp_workspace / "library.h").write_text("void parse(char* data);")

    # Add targets
    target_manager = TargetManager()
    target1 = target_manager.add_target(
        "integration_test_project",
        "parser_lib",
        temp_workspace / "library.c",
        "library",
        "Parser library",
    )
    assert target1.name == "parser_lib"

    # List targets
    targets = target_manager.list_targets("integration_test_project")
    assert len(targets) == 1
    assert targets[0].name == "parser_lib"


def test_analyze_and_add_targets(temp_workspace):
    """Test analyzing and adding targets."""
    # Create test project structure
    src_dir = temp_workspace / "src"
    src_dir.mkdir()
    (src_dir / "parser.c").write_text("int parse_input(char* data) { return 0; }")
    (src_dir / "parser.h").write_text("int parse_input(char* data);")
    (temp_workspace / "Makefile").write_text("build:\n\techo Building")

    # Analyze directory
    analyzer = TargetAnalyzer()
    analysis = analyzer.analyze_directory(temp_workspace)

    assert analysis["build_system"] == "make"
    assert len(analysis["source_files"]) > 0
    assert len(analysis["header_files"]) > 0

    # Create project and add target
    proj_manager = ProjectManager()
    project = proj_manager.create_project("analysis_test")

    target_manager = TargetManager()
    target = target_manager.add_target(
        "analysis_test",
        "parser",
        src_dir / "parser.c",
        "library",
        "Parser target",
    )
    assert target is not None
