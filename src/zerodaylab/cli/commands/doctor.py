"""System diagnostics command."""

import click
import platform
import sys
import shutil
from pathlib import Path
from zerodaylab.core.logger import get_logger
from zerodaylab.tools.system_diagnostics import SystemDiagnostics

logger = get_logger(__name__)


@click.command()
def doctor():
    """Run system diagnostics."""
    diagnostics = SystemDiagnostics()
    results = diagnostics.run_all_checks()

    click.echo("\n" + "=" * 80)
    click.echo("ZERO-DAY RESEARCH LAB - SYSTEM DIAGNOSTICS")
    click.echo("=" * 80 + "\n")

    for category, checks in results.items():
        click.echo(click.style(f"{category.upper()}", bold=True, fg="cyan"))
        for check_name, status, message in checks:
            status_text = click.style(f"[{status}]", fg=_status_color(status), bold=True)
            click.echo(f"  {status_text} {check_name}")
            if message:
                click.echo(f"       {message}")
        click.echo()

    click.echo("=" * 80)
    click.echo()


def _status_color(status: str) -> str:
    """Get color for status."""
    colors = {
        "AVAILABLE": "green",
        "UNAVAILABLE": "red",
        "OPTIONAL": "yellow",
        "MISCONFIGURED": "red",
    }
    return colors.get(status, "white")
