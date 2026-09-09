"""Database connection and session management."""

from pathlib import Path
from sqlalchemy import create_engine, event, Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from zerodaylab.core.logger import get_logger
from zerodaylab.database.models import Base

logger = get_logger(__name__)


class DatabaseConnection:
    """SQLite database connection manager."""

    def __init__(self, database_path: Path):
        """Initialize database connection.

        Args:
            database_path: Path to SQLite database
        """
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        # Create SQLite engine with WAL mode for better concurrency
        connection_string = f"sqlite:///{self.database_path}"
        self.engine = create_engine(
            connection_string,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        # Enable foreign keys
        @event.listens_for(Engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )

        logger.info(f"Database initialized at {self.database_path}")

    def init_db(self) -> None:
        """Initialize database tables."""
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database tables created")

    def get_session(self) -> Session:
        """Get a database session.

        Returns:
            SQLAlchemy session
        """
        return self.SessionLocal()

    def close(self) -> None:
        """Close database connection."""
        self.engine.dispose()
        logger.info("Database connection closed")
