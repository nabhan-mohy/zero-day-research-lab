"""Fuzzer executor and orchestration."""

from pathlib import Path
from typing import Dict, Optional, List, Any
from enum import Enum

from zerodaylab.core.logger import get_logger
from zerodaylab.core.config import Config
from zerodaylab.core.exceptions import FuzzerError
from zerodaylab.fuzzing.plugins.registry import FuzzerRegistry
from zerodaylab.fuzzing.plugins.base import FuzzerPlugin, FuzzerStatistics
from zerodaylab.database.connection import DatabaseConnection
from zerodaylab.database.models import Campaign, Worker

logger = get_logger(__name__)


class CampaignState(Enum):
    """Campaign states."""

    CREATED = "CREATED"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class WorkerState(Enum):
    """Worker states."""

    STARTING = "STARTING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    RECOVERING = "RECOVERING"


class FuzzerExecutor:
    """Execute and manage fuzzing campaigns."""

    def __init__(self, config: Config = None):
        """Initialize fuzzer executor.

        Args:
            config: Configuration object
        """
        if config is None:
            config = Config()
        self.config = config
        self.db = DatabaseConnection(config.database_path)
        self.db.init_db()
        self.registry = FuzzerRegistry()

    def create_campaign(
        self,
        project_id: int,
        target_id: int,
        name: str,
        fuzzer_name: str,
        **config,
    ) -> Campaign:
        """Create a fuzzing campaign.

        Args:
            project_id: Project ID
            target_id: Target ID
            name: Campaign name
            fuzzer_name: Fuzzer engine name (afl, libfuzzer)
            **config: Campaign configuration

        Returns:
            Campaign object
        """
        session = self.db.get_session()
        try:
            campaign = Campaign(
                project_id=project_id,
                target_id=target_id,
                name=name,
                engine=fuzzer_name,
                status="CREATED",
            )
            session.add(campaign)
            session.commit()
            logger.info(f"Created campaign: {name} with engine {fuzzer_name}")
            return campaign
        finally:
            session.close()

    def get_available_fuzzers(self) -> List[str]:
        """Get list of available fuzzers on this system.

        Returns:
            List of fuzzer names
        """
        return self.registry.get_available_plugins()

    def get_fuzzer_info(self, fuzzer_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a fuzzer.

        Args:
            fuzzer_name: Fuzzer name

        Returns:
            Dict with fuzzer information or None
        """
        return self.registry.get_plugin_info(fuzzer_name)

    def get_all_fuzzers_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all fuzzers.

        Returns:
            Dict mapping fuzzer names to info
        """
        return self.registry.get_all_plugins_info()

    def prepare_campaign(
        self,
        campaign_id: int,
        target_binary: Path,
        corpus_dir: Path,
        output_dir: Path,
        **config,
    ) -> bool:
        """Prepare a campaign for fuzzing.

        Args:
            campaign_id: Campaign ID
            target_binary: Path to target binary
            corpus_dir: Path to input corpus
            output_dir: Path for output artifacts
            **config: Campaign configuration

        Returns:
            True if preparation successful
        """
        session = self.db.get_session()
        try:
            campaign = session.query(Campaign).filter(Campaign.id == campaign_id).first()
            if not campaign:
                raise FuzzerError(f"Campaign {campaign_id} not found")

            fuzzer = self.registry.get(campaign.engine)
            if not fuzzer:
                raise FuzzerError(f"Fuzzer {campaign.engine} not available")

            # Validate fuzzer
            validation = fuzzer.validate_environment()
            if not validation.get("available", False):
                raise FuzzerError(
                    f"Fuzzer {campaign.engine} is not available: {validation.get('issues', [])}"
                )

            # Prepare fuzzer
            success = fuzzer.prepare(target_binary, corpus_dir, output_dir, **config)
            if not success:
                raise FuzzerError(f"Failed to prepare {campaign.engine}")

            campaign.status = "PREPARING"
            session.commit()

            logger.info(f"Prepared campaign {campaign_id}")
            return True

        finally:
            session.close()

    def start_campaign(self, campaign_id: int, workers: int = 1) -> bool:
        """Start a fuzzing campaign.

        Args:
            campaign_id: Campaign ID
            workers: Number of workers

        Returns:
            True if started successfully
        """
        session = self.db.get_session()
        try:
            campaign = session.query(Campaign).filter(Campaign.id == campaign_id).first()
            if not campaign:
                raise FuzzerError(f"Campaign {campaign_id} not found")

            fuzzer = self.registry.get(campaign.engine)
            if not fuzzer:
                raise FuzzerError(f"Fuzzer {campaign.engine} not available")

            success = fuzzer.start(workers=workers)
            if not success:
                raise FuzzerError(f"Failed to start {campaign.engine}")

            campaign.status = "RUNNING"
            session.commit()

            logger.info(f"Started campaign {campaign_id} with {workers} workers")
            return True

        finally:
            session.close()

    def pause_campaign(self, campaign_id: int) -> bool:
        """Pause a fuzzing campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            True if paused successfully
        """
        session = self.db.get_session()
        try:
            campaign = session.query(Campaign).filter(Campaign.id == campaign_id).first()
            if not campaign:
                raise FuzzerError(f"Campaign {campaign_id} not found")

            fuzzer = self.registry.get(campaign.engine)
            if not fuzzer:
                raise FuzzerError(f"Fuzzer {campaign.engine} not available")

            success = fuzzer.pause()
            if not success:
                raise FuzzerError(f"Failed to pause {campaign.engine}")

            campaign.status = "PAUSED"
            session.commit()

            logger.info(f"Paused campaign {campaign_id}")
            return True

        finally:
            session.close()

    def resume_campaign(self, campaign_id: int) -> bool:
        """Resume a fuzzing campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            True if resumed successfully
        """
        session = self.db.get_session()
        try:
            campaign = session.query(Campaign).filter(Campaign.id == campaign_id).first()
            if not campaign:
                raise FuzzerError(f"Campaign {campaign_id} not found")

            fuzzer = self.registry.get(campaign.engine)
            if not fuzzer:
                raise FuzzerError(f"Fuzzer {campaign.engine} not available")

            success = fuzzer.resume()
            if not success:
                raise FuzzerError(f"Failed to resume {campaign.engine}")

            campaign.status = "RUNNING"
            session.commit()

            logger.info(f"Resumed campaign {campaign_id}")
            return True

        finally:
            session.close()

    def stop_campaign(self, campaign_id: int) -> bool:
        """Stop a fuzzing campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            True if stopped successfully
        """
        session = self.db.get_session()
        try:
            campaign = session.query(Campaign).filter(Campaign.id == campaign_id).first()
            if not campaign:
                raise FuzzerError(f"Campaign {campaign_id} not found")

            fuzzer = self.registry.get(campaign.engine)
            if not fuzzer:
                raise FuzzerError(f"Fuzzer {campaign.engine} not available")

            success = fuzzer.stop()
            if not success:
                raise FuzzerError(f"Failed to stop {campaign.engine}")

            campaign.status = "STOPPED"
            session.commit()

            logger.info(f"Stopped campaign {campaign_id}")
            return True

        finally:
            session.close()

    def get_campaign_statistics(self, campaign_id: int) -> Dict[str, Any]:
        """Get campaign statistics.

        Args:
            campaign_id: Campaign ID

        Returns:
            Dict with campaign statistics
        """
        session = self.db.get_session()
        try:
            campaign = session.query(Campaign).filter(Campaign.id == campaign_id).first()
            if not campaign:
                raise FuzzerError(f"Campaign {campaign_id} not found")

            fuzzer = self.registry.get(campaign.engine)
            if not fuzzer:
                return {}

            stats = fuzzer.collect_statistics()
            return stats.to_dict() if stats else {}

        finally:
            session.close()
