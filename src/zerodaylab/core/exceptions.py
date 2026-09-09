"""Custom exceptions for Zero-Day Research Lab."""


class ZeroDayLabError(Exception):
    """Base exception for Zero-Day Research Lab."""

    pass


class ConfigurationError(ZeroDayLabError):
    """Configuration-related error."""

    pass


class SecurityError(ZeroDayLabError):
    """Security-related error."""

    pass


class BuildError(ZeroDayLabError):
    """Build-related error."""

    pass


class TargetError(ZeroDayLabError):
    """Target-related error."""

    pass


class CampaignError(ZeroDayLabError):
    """Campaign-related error."""

    pass


class FuzzerError(ZeroDayLabError):
    """Fuzzer-related error."""

    pass


class WorkerError(ZeroDayLabError):
    """Worker-related error."""

    pass


class CrashAnalysisError(ZeroDayLabError):
    """Crash analysis error."""

    pass


class DatabaseError(ZeroDayLabError):
    """Database operation error."""

    pass
