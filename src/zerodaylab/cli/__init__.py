"""Command-line interface for Zero-Day Research Lab."""

import sys
import click
from zerodaylab.core.config import Config
from zerodaylab.core.logger import setup_logging, get_logger
from zerodaylab.cli.commands.doctor import doctor
from zerodaylab.cli.commands.project import project
from zerodaylab.cli.commands.target import target

logger = get_logger(__name__)


@click.group()
@click.version_option()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging")
def main(verbose):
    """Zero-Day Research Lab - Vulnerability Research and Fuzzing Platform."""
    config = Config()
    setup_logging(config, level="DEBUG" if verbose else "INFO")


main.add_command(doctor)
main.add_command(project)
main.add_command(target)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
