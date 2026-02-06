"""
Configuration management for XSSForge.

Supports YAML/JSON config files and CLI overrides.
"""

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class ScanSettings:
    """Scan behavior settings."""
    # Scan types
    scan_reflected: bool = True
    scan_dom: bool = True
    scan_stored: bool = False

    # Payload selection
    use_all_payloads: bool = False      # Use ALL PortSwigger cheatsheet payloads
    auto_trigger_only: bool = False      # Only payloads that don't need interaction
    max_payloads_per_context: int = 50   # Max payloads to test per context
    smart_selection: bool = True         # Use smart payload selection

    # Testing behavior
    follow_redirects: bool = True
    verify_execution: bool = False       # Use headless browser to verify
    stop_on_first: bool = False          # Stop after first finding per param


@dataclass
class NetworkSettings:
    """Network/HTTP settings."""
    timeout: float = 30.0
    delay_between_requests: float = 0.0
    max_concurrent: int = 10
    max_retries: int = 3
    verify_ssl: bool = False
    proxy: str | None = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@dataclass
class WAFSettings:
    """WAF handling settings."""
    detect_waf: bool = True
    bypass_mode: bool = True             # Attempt WAF bypasses
    aggressive_bypass: bool = False      # Try more bypass techniques


@dataclass
class OutputSettings:
    """Output/reporting settings."""
    format: str = "json"                 # json, html, markdown
    output_file: str | None = None
    verbose: bool = False
    quiet: bool = False                  # Minimal output
    color: bool = True


@dataclass
class XSSForgeConfig:
    """Complete XSSForge configuration."""
    scan: ScanSettings = field(default_factory=ScanSettings)
    network: NetworkSettings = field(default_factory=NetworkSettings)
    waf: WAFSettings = field(default_factory=WAFSettings)
    output: OutputSettings = field(default_factory=OutputSettings)

    # Custom headers and cookies
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    # Stored XSS specific
    stored_submit_url: str = ""
    stored_submit_param: str = ""
    stored_view_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "scan": asdict(self.scan),
            "network": asdict(self.network),
            "waf": asdict(self.waf),
            "output": asdict(self.output),
            "headers": self.headers,
            "cookies": self.cookies,
            "stored_submit_url": self.stored_submit_url,
            "stored_submit_param": self.stored_submit_param,
            "stored_view_urls": self.stored_view_urls,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "XSSForgeConfig":
        """Create config from dictionary."""
        config = cls()

        if "scan" in data:
            for key, value in data["scan"].items():
                if hasattr(config.scan, key):
                    setattr(config.scan, key, value)

        if "network" in data:
            for key, value in data["network"].items():
                if hasattr(config.network, key):
                    setattr(config.network, key, value)

        if "waf" in data:
            for key, value in data["waf"].items():
                if hasattr(config.waf, key):
                    setattr(config.waf, key, value)

        if "output" in data:
            for key, value in data["output"].items():
                if hasattr(config.output, key):
                    setattr(config.output, key, value)

        if "headers" in data:
            config.headers = data["headers"]

        if "cookies" in data:
            config.cookies = data["cookies"]

        if "stored_submit_url" in data:
            config.stored_submit_url = data["stored_submit_url"]

        if "stored_submit_param" in data:
            config.stored_submit_param = data["stored_submit_param"]

        if "stored_view_urls" in data:
            config.stored_view_urls = data["stored_view_urls"]

        return config

    @classmethod
    def from_file(cls, filepath: str | Path) -> "XSSForgeConfig":
        """Load config from JSON file."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")

        with open(filepath) as f:
            data = json.load(f)

        return cls.from_dict(data)

    def save(self, filepath: str | Path):
        """Save config to JSON file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def get_default_config_path(cls) -> Path:
        """Get default config file path."""
        return Path.home() / ".config" / "xssforge" / "config.json"

    @classmethod
    def load_or_create_default(cls) -> "XSSForgeConfig":
        """Load config from default path or create default."""
        config_path = cls.get_default_config_path()
        if config_path.exists():
            return cls.from_file(config_path)
        return cls()


def generate_example_config() -> str:
    """Generate example configuration JSON."""
    config = XSSForgeConfig()

    # Set some example values
    config.headers = {
        "Authorization": "Bearer YOUR_TOKEN",
        "X-Custom-Header": "value"
    }
    config.cookies = {
        "session": "YOUR_SESSION_COOKIE"
    }

    return json.dumps(config.to_dict(), indent=2)


# Preset configurations
PRESETS = {
    "quick": XSSForgeConfig(
        scan=ScanSettings(
            max_payloads_per_context=10,
            smart_selection=True,
            auto_trigger_only=True,
        ),
        network=NetworkSettings(timeout=15.0),
    ),
    "thorough": XSSForgeConfig(
        scan=ScanSettings(
            use_all_payloads=True,
            max_payloads_per_context=100,
            smart_selection=True,
        ),
        network=NetworkSettings(timeout=30.0),
        waf=WAFSettings(bypass_mode=True, aggressive_bypass=True),
    ),
    "stealth": XSSForgeConfig(
        scan=ScanSettings(
            auto_trigger_only=False,
            max_payloads_per_context=30,
        ),
        network=NetworkSettings(
            delay_between_requests=1.0,
            max_concurrent=3,
        ),
        waf=WAFSettings(bypass_mode=True),
    ),
    "aggressive": XSSForgeConfig(
        scan=ScanSettings(
            use_all_payloads=True,
            max_payloads_per_context=200,
            scan_reflected=True,
            scan_dom=True,
        ),
        network=NetworkSettings(
            timeout=60.0,
            max_concurrent=20,
        ),
        waf=WAFSettings(bypass_mode=True, aggressive_bypass=True),
    ),
}


def get_preset(name: str) -> XSSForgeConfig:
    """Get a preset configuration."""
    if name not in PRESETS:
        raise ValueError(f"Unknown preset: {name}. Available: {list(PRESETS.keys())}")
    return PRESETS[name]
