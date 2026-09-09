"""Zero-Day Research Lab - Comprehensive vulnerability research platform."""

__version__ = "0.1.0"
__author__ = "Zero-Day Research Lab Contributors"
__license__ = "Apache-2.0"

from zerodaylab.core.config import Config
from zerodaylab.core.logger import setup_logging

__all__ = [
    "Config",
    "setup_logging",
]
