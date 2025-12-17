"""
Configuration loader module - handles loading and validation
of YAML configuration files with caching and error handling.
"""

import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
from functools import lru_cache

from ids.utils.logger import setup_logger

logger = setup_logger(__name__)


class ConfigLoader:
    """Thread-safe configuration loader with caching and validation."""

    def __init__(self, config_dir: str = "config"):
        """
        Initialize ConfigLoader with configuration directory path.

        Args:
            config_dir: Path to configuration directory
        """
        self.config_dir = Path(config_dir).resolve()
        if not self.config_dir.exists():
            raise FileNotFoundError(f"Config directory not found: {self.config_dir}")

        logger.info(f"ConfigLoader initialized with directory: {self.config_dir}")

    # -----------------------------------
    # MAIN YAML LOADER (CACHED)
    # -----------------------------------
    @lru_cache(maxsize=10)
    def load_yaml(self, filename: str) -> Dict[str, Any]:
        """
        Load and cache YAML configuration file.

        Args:
            filename: Name of YAML file (e.g., 'main.yaml')

        Returns:
            Parsed configuration dictionary
        """
        file_path = self.config_dir / filename

        if not file_path.exists():
            logger.error(f"Configuration file not found: {file_path}")
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                config = yaml.safe_load(file) or {}
                logger.info(f"Successfully loaded configuration: {filename}")
                return config

        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {filename}: {e}")
            raise

        except Exception as e:
            logger.error(f"Unexpected error loading {filename}: {e}")
            raise

    # -----------------------------------
    # JSON LOADER
    # -----------------------------------
    def load_json(self, filename: str) -> Dict[str, Any]:
        """Load JSON configuration file."""
        file_path = self.config_dir / filename

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return json.load(file)
        except Exception as e:
            logger.error(f"Error loading JSON config {filename}: {e}")
            return {}

    # -----------------------------------
    # KEY ACCESSOR
    # -----------------------------------
    def get(self, section: str, default: Any = None) -> Any:
        """
        Get configuration section from main.yaml.

        Supports dot-notation access.
        """
        try:
            config = self.load_yaml("main.yaml")
            keys = section.split(".")

            value = config
            for key in keys:
                value = value[key]

            return value

        except (KeyError, TypeError):
            logger.warning(f"Config key not found: {section}")
            return default

        except Exception as e:
            logger.error(f"Error accessing config key {section}: {e}")
            return default

    # -----------------------------------
    # RELOAD SUPPORT
    # -----------------------------------
    def reload(self, filename: str) -> None:
        """Clear cache and reload specific configuration file."""
        self.load_yaml.cache_clear()
        logger.info(f"Configuration cache cleared for: {filename}")

    # -----------------------------------
    # ALIAS (FIXES .load() MISSING)
    # -----------------------------------
    def load(self, filename: str) -> Dict[str, Any]:
        """
        Alias for compatibility — supports:
        config_loader.load("main.yaml")
        """
        return self.load_yaml(filename)


# Global config loader instance
config_loader = ConfigLoader()


def get_config(section: str, default: Any = None) -> Any:
    """Convenience function to get config from global loader."""
    return config_loader.get(section, default)
