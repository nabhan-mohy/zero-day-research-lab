"""Scheduler: parallelism, cancellation, and aggregation."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.campaigns.scheduler import CampaignScheduler, SchedulerConfig
from kmcs.core.models import FuzzerKind
from kmcs.database.database import Database, build_sqlite_url


def _write_executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture()
def demo(tmp_path: Path) -> tuple[Path, Path]:
    binary = _write_executable(tmp_path / "t", "#!/bin/sh\nkill -SEGV $$\n")
    corpus = tmp_path / "c"
    corpus.mkdir()
    (corpus / "seed").write_bytes(b"x")
    return binary, corpus


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX shell")
class TestScheduler:
    def test_prepare_creates_workers(self, tmp_path: Path, demo) -> None:
        binary, corpus = demo
        config = SchedulerConfig(
            campaign_id="c",
            target_binary=binary,
            corpus_dir=corpus,
            output_root=tmp_path / "out",
            fuzzer=FuzzerKind.AFLPP,
            workers=3,
        )
        scheduler = CampaignScheduler(config, detector=CrashDetector())
        scheduler.prepare()
        assert len(scheduler._workers) == 3  # noqa: SLF001 - test introspection

    def test_clear_output_root_is_honoured(self, tmp_path: Path, demo) -> None:
        binary, corpus = demo
        output = tmp_path / "out"
        output.mkdir()
        (output / "stale").write_text("old")

        config = SchedulerConfig(
            campaign_id="c",
            target_binary=binary,
            corpus_dir=corpus,
            output_root=output,
            fuzzer=FuzzerKind.AFLPP,
            workers=1,
            clear_output_root=True,
        )
        CampaignScheduler(config, detector=CrashDetector()).prepare()
        assert not (output / "stale").exists()

    def test_cancel_stops_workers(self, tmp_path: Path, demo) -> None:
        binary, corpus = demo
        config = SchedulerConfig(
            campaign_id="c",
            target_binary=binary,
            corpus_dir=corpus,
            output_root=tmp_path / "out",
            fuzzer=FuzzerKind.AFLPP,
            workers=2,
            poll_interval_seconds=0.05,
        )
        scheduler = CampaignScheduler(config, detector=CrashDetector())
        scheduler.prepare()

        result_holder: dict[str, object] = {}

        def run() -> None:
            result_holder["result"] = scheduler.run()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        time.sleep(0.3)
        scheduler.cancel()
        thread.join(timeout=15)
        assert not thread.is_alive()

        result = result_holder["result"]
        assert result.cancelled is True
        assert len(result.worker_results) == 2
