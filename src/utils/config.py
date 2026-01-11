"""Configuration management for the vulnerability prediction system."""

import os
from pathlib import Path
from typing import Any, Optional

import yaml


class Config:
    """Configuration manager that loads settings from YAML files."""

    _instance: Optional["Config"] = None
    _config: dict = {}

    def __new__(cls, config_path: Optional[str] = None) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config(config_path)
        return cls._instance

    def _load_config(self, config_path: Optional[str] = None) -> None:
        """Load configuration from YAML file."""
        if config_path is None:
            # Default config path
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "configs" / "config.yaml"

        config_path = Path(config_path)
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f) or {}
        else:
            self._config = {}

        # Override with environment variables
        self._apply_env_overrides()

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        # NVD API key from environment
        nvd_api_key = os.environ.get("NVD_API_KEY")
        if nvd_api_key:
            if "nvd" not in self._config:
                self._config["nvd"] = {}
            self._config["nvd"]["api_key"] = nvd_api_key

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.

        Args:
            key: Configuration key (e.g., "models.baseline.n_estimators")
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value using dot notation."""
        keys = key.split(".")
        config = self._config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    @property
    def data(self) -> dict:
        """Get data configuration."""
        return self._config.get("data", {})

    @property
    def models(self) -> dict:
        """Get models configuration."""
        return self._config.get("models", {})

    @property
    def training(self) -> dict:
        """Get training configuration."""
        return self._config.get("training", {})

    @property
    def features(self) -> dict:
        """Get feature extraction configuration."""
        return self._config.get("features", {})

    def to_dict(self) -> dict:
        """Return the full configuration as a dictionary."""
        return self._config.copy()

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (useful for testing)."""
        cls._instance = None
        cls._config = {}


def get_config(config_path: Optional[str] = None) -> Config:
    """Get the configuration singleton."""
    return Config(config_path)
