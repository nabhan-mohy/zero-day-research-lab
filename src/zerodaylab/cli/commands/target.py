"""Target management commands."""

import click
from pathlib import Path
from zerodaylab.core.logger import get_logger
from zerodaylab.targets.manager import TargetManager
from zerodaylab.targets.analyzer import TargetAnalyzer
import json

logger = get_logger(__name__)


@click.group()
def target():
    """Target management."""
    pass


@target.command()
@click.option("--project", prompt="Project name", help="Name of the project")
@click.option("--name", prompt="Target name", help="Name of the target")
@click.option("--path", prompt="Target path", type=click.Path(exists=True), help="Path to target")
@click.option(
    "--type",
    type=click.Choice(["library", "binary", "harness"]),
    default="library",
    help="Target type",
)
@click.option("--description", default="", help="Target description")
def add(project, name, path, type, description):
    """Add a target to a project."""
    try:
        manager = TargetManager()
        target_obj = manager.add_target(project, name, Path(path), type, description)
        click.echo(
            click.style(f"✓ Target '{name}' added to project '{project}'", fg="green", bold=True)
        )
        click.echo(f"  Target ID: {target_obj.id}")
        click.echo(f"  Type: {target_obj.type}")
        click.echo(f"  Path: {target_obj.path}")
    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red", bold=True))
        raise


@target.command()
@click.option("--project", prompt="Project name", help="Name of the project")
def list(project):
    """List targets in a project."""
    try:
        manager = TargetManager()
        targets = manager.list_targets(project)
        if not targets:
            click.echo(f"No targets in project '{project}'")
            return
        click.echo(click.style(f"Targets in project '{project}':", bold=True, fg="cyan"))
        for t in targets:
            click.echo(f"  {t.name} (ID: {t.id}, Type: {t.type})")
            if t.description:
                click.echo(f"    {t.description}")
    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red", bold=True))
        raise


@target.command()
@click.option("--project", prompt="Project name", help="Name of the project")
@click.option("--name", prompt="Target name", help="Name of the target")
def remove(project, name):
    """Remove a target from a project."""
    try:
        manager = TargetManager()
        manager.delete_target(project, name)
        click.echo(
            click.style(
                f"✓ Target '{name}' removed from project '{project}'",
                fg="green",
                bold=True,
            )
        )
    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red", bold=True))
        raise


@target.command()
@click.option("--path", prompt="Directory path", type=click.Path(exists=True), help="Path to analyze")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def analyze(path, output_json):
    """Analyze a directory for fuzzing targets."""
    try:
        analyzer = TargetAnalyzer()
        results = analyzer.analyze_directory(Path(path))

        if output_json:
            click.echo(json.dumps(results, indent=2, default=str))
        else:
            click.echo(click.style(f"Analysis of: {path}", bold=True, fg="cyan"))
            click.echo(f"  Build System: {results.get('build_system', 'unknown')}")
            click.echo(f"  Build Files: {len(results.get('build_files', []))}")
            click.echo(f"  Source Files: {len(results.get('source_files', []))}")
            click.echo(f"  Headers: {len(results.get('header_files', []))}")
            click.echo(f"  Binaries: {len(results.get('binaries', []))}")
            click.echo(f"  Fuzzing Candidates: {len(results.get('fuzzing_candidates', []))}")
            click.echo(f"  Existing Fuzz Targets: {len(results.get('existing_fuzz_targets', []))}")
    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red", bold=True))
        raise
