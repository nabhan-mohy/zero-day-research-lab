"""Campaign CRUD and finalisation."""

from __future__ import annotations

from pathlib import Path

import pytest

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.campaigns.manager import CampaignError, CampaignManager
from kmcs.core import models
from kmcs.core.config import KMCSConfig
from kmcs.database.database import Database, build_sqlite_url
from kmcs.database.models import CrashRow, FindingRow


@pytest.fixture()
def manager(tmp_path: Path) -> CampaignManager:
    db = Database(build_sqlite_url(tmp_path / "kmcs.sqlite3"))
    db.initialize()
    config = KMCSConfig(base_dir=tmp_path / "kmcs")
    config.ensure_directories()
    return CampaignManager(db, config, detector=CrashDetector(database=db))


def test_add_and_get(manager: CampaignManager) -> None:
    campaign = models.Campaign(name="c1", target_id="t1")
    manager.add(campaign)
    assert manager.get(campaign.id) is not None
    assert manager.get_by_name("c1").id == campaign.id


def test_duplicate_name_is_rejected(manager: CampaignManager) -> None:
    manager.add(models.Campaign(name="c1", target_id="t1"))
    with pytest.raises(CampaignError):
        manager.add(models.Campaign(name="c1", target_id="t2"))


def test_list_is_newest_first(manager: CampaignManager) -> None:
    manager.add(models.Campaign(name="first", target_id="t"))
    manager.add(models.Campaign(name="second", target_id="t"))
    names = [c.name for c in manager.list()]
    assert names == ["second", "first"]


def test_finalize_groups_crashes_into_findings(
    tmp_path: Path, manager: CampaignManager
) -> None:
    # Directly insert three crashes with two distinct fingerprints.
    db = manager._database  # noqa: SLF001 - test introspection
    campaign = models.Campaign(name="c", target_id="t")
    manager.add(campaign)

    crash_a = models.Crash(
        campaign_id=campaign.id,
        description="a",
        fingerprint="fp-a",
        classification=models.CrashClassification.HEAP_BUFFER_OVERFLOW,
        signal=11,
        stderr_excerpt="==1==ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0x1 in main /a.c:10",
        metadata={"timed_out": False},
    )
    crash_b = models.Crash(
        campaign_id=campaign.id,
        description="b",
        fingerprint="fp-a",
        classification=models.CrashClassification.HEAP_BUFFER_OVERFLOW,
        signal=11,
        stderr_excerpt="==1==ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0x1 in main /a.c:10",
        metadata={"timed_out": False},
    )
    crash_c = models.Crash(
        campaign_id=campaign.id,
        description="c",
        fingerprint="fp-b",
        classification=models.CrashClassification.SEGMENTATION_FAULT,
        signal=11,
        stderr_excerpt="",
        metadata={"timed_out": False},
    )

    with db.session() as session:
        for crash in (crash_a, crash_b, crash_c):
            session.add(CrashRow.from_domain(crash))

    result = manager.finalize(campaign.id)
    assert result.total_crashes == 3
    # The two identical ASan snippets should collapse.
    assert result.total_groups == 2

    with db.session() as session:
        from sqlalchemy import select

        findings = session.scalars(select(FindingRow)).all()
        assert len(findings) == 2
        crash_ids_across_findings = {cid for f in findings for cid in f.crash_ids}
        assert crash_ids_across_findings == {crash_a.id, crash_b.id, crash_c.id}
