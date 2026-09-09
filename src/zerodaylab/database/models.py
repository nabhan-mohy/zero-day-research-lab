"""SQLAlchemy models for Zero-Day Research Lab."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Project(Base):
    """Project model."""

    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Target(Base):
    """Target model."""

    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    path = Column(Text, nullable=False)
    type = Column(String(50))  # library, binary, harness
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TargetBuild(Base):
    """Target build model."""

    __tablename__ = "target_builds"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    build_type = Column(String(50), nullable=False)  # normal, asan, ubsan, etc.
    path = Column(Text, nullable=False)
    compiler = Column(String(50))
    flags = Column(Text)
    success = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Campaign(Base):
    """Fuzzing campaign model."""

    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    engine = Column(String(50), nullable=False)  # afl, libfuzzer
    status = Column(String(50), default="CREATED")  # CREATED, RUNNING, PAUSED, STOPPED
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime)
    stopped_at = Column(DateTime)


class Worker(Base):
    """Worker process model."""

    __tablename__ = "workers"

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False, index=True)
    worker_id = Column(String(50), unique=True, nullable=False)
    pid = Column(Integer)
    status = Column(String(50), default="CREATED")
    executions = Column(Integer, default=0)
    exec_per_sec = Column(Float, default=0.0)
    coverage = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime)


class Crash(Base):
    """Crash model."""

    __tablename__ = "crashes"

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False, index=True)
    worker_id = Column(Integer, ForeignKey("workers.id"))
    signal = Column(Integer)
    exit_code = Column(Integer)
    sanitizer = Column(String(50))  # asan, ubsan, lsan, msan
    sanitizer_output = Column(Text)
    stack_trace = Column(Text)
    input_sha256 = Column(String(64), nullable=False, index=True)
    input_size = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)


class CrashFingerprint(Base):
    """Crash fingerprint model."""

    __tablename__ = "crash_fingerprints"

    id = Column(Integer, primary_key=True)
    crash_id = Column(Integer, ForeignKey("crashes.id"), nullable=False, index=True)
    fingerprint = Column(String(255), nullable=False, unique=True, index=True)
    category = Column(String(50))  # heap-buffer-overflow, use-after-free, etc.
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Finding(Base):
    """Vulnerability finding model."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    fingerprint_id = Column(Integer, ForeignKey("crash_fingerprints.id"), nullable=False)
    status = Column(String(50), default="NEW")  # NEW, TRIAGED, REPRODUCED, MINIMIZED
    severity = Column(String(50))  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(String(50))  # LOW, MEDIUM, HIGH, CONFIRMED
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Corpus(Base):
    """Corpus model."""

    __tablename__ = "corpus"

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False, index=True)
    input_sha256 = Column(String(64), nullable=False, unique=True, index=True)
    input_size = Column(Integer)
    coverage = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
