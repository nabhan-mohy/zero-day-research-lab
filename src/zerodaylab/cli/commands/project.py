"""Project management commands."""

import click
from pathlib import Path
from zerodaylab.core.logger import get_logger
from zerodaylab.projects.manager import ProjectManager

logger = get_logger(__name__)


@click.group()
def project():
    """Project management."""
    pass


@project.command()
@click.option("--name", prompt="Project name", help="Name of the project")
@click.option("--description", default="", help="Project description")
def create(name, description):
    """Create a new project."""
    try:
        manager = ProjectManager()
        proj = manager.create_project(name, description)
        click.echo(
            click.style(f"✓ Project '{name}' created successfully", fg="green", bold=True)
        )
        click.echo(f"  Project ID: {proj.id}")
    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red", bold=True))
        raise


@project.command()
@click.option("--name", prompt="Project name", help="Name of the project")
def info(name):
    """Get project information."""
    try:
        manager = ProjectManager()
        proj = manager.get_project(name)
        if proj:
            click.echo(click.style(f"Project: {proj.name}", bold=True, fg="cyan"))
            click.echo(f"  ID: {proj.id}")
            click.echo(f"  Description: {proj.description}")
            click.echo(f"  Created: {proj.created_at}")
        else:
            click.echo(click.style(f"Project '{name}' not found", fg="yellow"))
    except Exception as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red", bold=True))
        raise
