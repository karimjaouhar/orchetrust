from dataclasses import dataclass
from pathlib import Path
import os
import yaml

DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "orchetrust.yaml",
    Path.home() / ".config" / "orchetrust" / "config.yaml",
]

def _default_db_path() -> str:
    base = Path.home() / ".orchetrust"
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "orchetrust.db")

@dataclass
class Config:
    slack_webhook_url: str | None = None
    scan_paths: list[str] = None
    db_path: str = _default_db_path()

    @staticmethod
    def load() -> "Config":
        data = {}
        for p in DEFAULT_CONFIG_PATHS:
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                break
        slack = os.getenv("ORCHETRUST_SLACK_WEBHOOK_URL", data.get("slack_webhook_url"))
        scan_paths = data.get("scan_paths") or []
        db_path = os.getenv("ORCHETRUST_DB_PATH", data.get("db_path") or _default_db_path())
        return Config(slack_webhook_url=slack, scan_paths=scan_paths, db_path=db_path)