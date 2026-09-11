"""Application entry point and startup sequence.

Phase 1 startup is deliberately small and honest:

1. load configuration
2. install logging
3. create the data directories
4. open the database and apply migrations
5. run a real health check against that database
6. publish the startup events and report the outcome

Exit code 0 means every step succeeded.  Anything else means it did not, and the
reason is printed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kmcs import __version__
from kmcs.core.config import LOG_LEVELS, KMCSConfig, configure_logging
from kmcs.core.events import EventBus, EventType
from kmcs.core.exceptions import ConfigurationError, KMCSException
from kmcs.database.database import Database, DatabaseHealth

__all__ = ["StartupReport", "run_startup", "build_parser", "main"]


@dataclass(slots=True)
class StartupReport:
    """Everything the startup sequence learned, in a serialisable form."""

    version: str
    ok: bool
    config: KMCSConfig
    directories: dict[str, str] = field(default_factory=dict)
    database_url: str = ""
    schema_version: int = 0
    health: DatabaseHealth | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "ok": self.ok,
            "base_dir": str(self.config.base_dir),
            "database": {
                "url": self.database_url,
                "file": str(self.config.database_file)
                if self.config.database_url is None
                else None,
                "schema_version": self.schema_version,
            },
            "directories": dict(self.directories),
            "health": None if self.health is None else self.health.model_dump(),
            "errors": list(self.errors),
        }


def run_startup(
    config: KMCSConfig | None = None,
    *,
    bus: EventBus | None = None,
) -> StartupReport:
    """Execute the startup sequence and return a report.

    Raises :class:`~kmcs.core.exceptions.KMCSException` if a step fails in a way
    that prevents a meaningful report from being produced.
    """
    config = config or KMCSConfig.load()
    logger = configure_logging(config)
    bus = bus or EventBus()

    bus.emit(EventType.APPLICATION_STARTING, {"version": __version__}, source="main")
    logger.info("KMCS %s starting", __version__)
    logger.debug("Data directory: %s", config.base_dir)

    directories = config.ensure_directories()
    bus.emit(
        EventType.CONFIGURATION_LOADED,
        {"base_dir": str(config.base_dir)},
        source="main",
    )

    database = Database.from_config(config)
    try:
        schema_version = database.initialize()
        bus.emit(
            EventType.DATABASE_INITIALIZED,
            {"url": database.url, "schema_version": schema_version},
            source="main",
        )

        health = database.health_check()
        bus.emit(
            EventType.DATABASE_HEALTH_CHECKED,
            {"ok": health.ok, "messages": list(health.messages)},
            source="main",
        )

        errors: list[str] = []
        if health.ok:
            logger.info(
                "Database ready at schema version %d (%s)", schema_version, database.url
            )
        else:
            errors.extend(health.messages)
            logger.error("Database health check failed: %s", "; ".join(health.messages))

        report = StartupReport(
            version=__version__,
            ok=health.ok,
            config=config,
            directories={name: str(path) for name, path in directories.items()},
            database_url=database.url,
            schema_version=schema_version,
            health=health,
            errors=errors,
        )
    finally:
        database.dispose()

    bus.emit(EventType.APPLICATION_STARTED, {"ok": report.ok}, source="main")
    logger.info("Startup complete: %s", "READY" if report.ok else "DEGRADED")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kmcs",
        description=(
            "Keyless Memory-Corruption Scanner — a defensive fuzzing and "
            "memory-safety research platform."
        ),
    )
    parser.add_argument("--version", action="version", version=f"KMCS {__version__}")
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="Override the KMCS data directory.",
    )
    parser.add_argument(
        "--log-level",
        type=str.upper,
        choices=sorted(LOG_LEVELS),
        default=None,
        help="Override the logging level.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the startup report as JSON on stdout.",
    )
    return parser


def _print_report(report: StartupReport) -> None:
    status = "READY" if report.ok else "DEGRADED"
    lines = [
        f"KMCS {report.version} startup report",
        f"  status          : {status}",
        f"  data directory  : {report.config.base_dir}",
        f"  database        : {report.database_url}",
        f"  schema version  : {report.schema_version}",
    ]
    for name, path in report.directories.items():
        lines.append(f"  {name + ' dir':<16}: {path}")
    lines.append(
        f"  database health : {'OK' if report.health and report.health.ok else 'FAILED'}"
    )
    for message in report.errors:
        lines.append(f"  error           : {message}")
    print("\n".join(lines))


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    overrides: dict[str, Any] = {}
    if args.base_dir is not None:
        overrides["base_dir"] = args.base_dir
    if args.log_level is not None:
        overrides["log_level"] = args.log_level

    try:
        config = KMCSConfig.load(**overrides)
    except ConfigurationError as exc:
        print(f"kmcs: configuration error: {exc}", file=sys.stderr)
        return exc.exit_code

    try:
        report = run_startup(config)
    except KMCSException as exc:
        print(f"kmcs: startup failed: {exc}", file=sys.stderr)
        return exc.exit_code
    except OSError as exc:
        print(f"kmcs: startup failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        _print_report(report)

    return 0 if report.ok else 1
