"""Fuzzer plugin registry and loader."""

from typing import Dict, Optional, List
from pathlib import Path
import importlib
import pkgutil

from zerodaylab.core.logger import get_logger
from zerodaylab.core.exceptions import ZeroDayLabError
from zerodaylab.fuzzing.plugins.base import FuzzerPlugin

logger = get_logger(__name__)


class FuzzerRegistry:
    """Registry for fuzzer plugins."""

    def __init__(self):
        """Initialize fuzzer registry."""
        self._plugins: Dict[str, type] = {}
        self._instances: Dict[str, FuzzerPlugin] = {}
        self._load_builtin_plugins()

    def _load_builtin_plugins(self):
        """Load built-in fuzzer plugins."""
        # Import and register built-in plugins
        try:
            from zerodaylab.fuzzing.plugins.afl import AFLPlugin
            self.register(AFLPlugin)
            logger.debug("Registered AFL++ plugin")
        except ImportError as e:
            logger.debug(f"Could not load AFL++ plugin: {e}")

        try:
            from zerodaylab.fuzzing.plugins.libfuzzer import LibFuzzerPlugin
            self.register(LibFuzzerPlugin)
            logger.debug("Registered libFuzzer plugin")
        except ImportError as e:
            logger.debug(f"Could not load libFuzzer plugin: {e}")

    def register(self, plugin_class: type) -> None:
        """Register a fuzzer plugin.

        Args:
            plugin_class: Plugin class (must inherit from FuzzerPlugin)

        Raises:
            ZeroDayLabError: If plugin class is invalid
        """
        if not issubclass(plugin_class, FuzzerPlugin):
            raise ZeroDayLabError(
                f"Plugin {plugin_class.__name__} must inherit from FuzzerPlugin"
            )

        name = plugin_class.name
        if name in self._plugins:
            logger.warning(f"Overwriting existing plugin: {name}")

        self._plugins[name] = plugin_class
        logger.info(f"Registered fuzzer plugin: {name}")

    def get(self, name: str) -> Optional[FuzzerPlugin]:
        """Get a fuzzer plugin instance.

        Args:
            name: Plugin name

        Returns:
            Plugin instance or None
        """
        if name not in self._plugins:
            return None

        # Return cached instance
        if name in self._instances:
            return self._instances[name]

        # Create new instance
        try:
            plugin_class = self._plugins[name]
            instance = plugin_class()
            self._instances[name] = instance
            logger.debug(f"Instantiated plugin: {name}")
            return instance
        except Exception as e:
            logger.error(f"Failed to instantiate plugin {name}: {e}")
            return None

    def list_plugins(self) -> List[str]:
        """List all registered plugins.

        Returns:
            List of plugin names
        """
        return list(self._plugins.keys())

    def get_available_plugins(self) -> List[str]:
        """Get list of available fuzzer plugins.

        Returns:
            List of plugin names that are available on this system
        """
        available = []
        for name in self._plugins:
            plugin = self.get(name)
            if plugin:
                validation = plugin.validate_environment()
                if validation.get("available", False):
                    available.append(name)
        return available

    def get_plugin_info(self, name: str) -> Optional[Dict]:
        """Get plugin information.

        Args:
            name: Plugin name

        Returns:
            Dict with plugin info or None
        """
        plugin = self.get(name)
        if not plugin:
            return None

        info = plugin.get_info()
        validation = plugin.validate_environment()
        info["available"] = validation.get("available", False)
        info["validation"] = validation

        return info

    def get_all_plugins_info(self) -> Dict[str, Dict]:
        """Get information for all plugins.

        Returns:
            Dict mapping plugin names to info
        """
        return {
            name: self.get_plugin_info(name)
            for name in self._plugins
        }
