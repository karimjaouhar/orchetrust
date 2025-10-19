from dataclasses import dataclass
from pathlib import Path
import os
import yaml

DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "orchetrust.yaml",
    Path.home() / ".config" / "orchetrust" / "config.yaml",
]

@dataclass
class Config:
    slack_webhook_url: str | None = None
    scan_paths: list[str] = None

    @staticmethod
    def load() -> "Config":
        data = {}
        for p in DEFAULT_CONFIG_PATHS:
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                break
        # env overrides
        slack = os.getenv("ORCHETRUST_SLACK_WEBHOOK_URL", data.get("slack_webhook_url"))
        scan_paths = data.get("scan_paths") or []
        return Config(slack_webhook_url=slack, scan_paths=scan_paths)