from __future__ import annotations
import json
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

def send_slack(webhook_url: str, text: str, blocks: list[dict] | None = None, timeout: int = 10) -> tuple[bool, str]:
    """
    Post a message to a Slack webhook. Returns (ok, detail).
    Uses stdlib only to avoid extra dependencies.
    """
    payload = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            # Slack returns "ok" (200) on success; body may be empty
            return True, f"HTTP {resp.status}"
    except HTTPError as e:
        return False, f"HTTPError {e.code}: {e.read().decode('utf-8', 'ignore')}"
    except URLError as e:
        return False, f"URLError: {e.reason}"
    except Exception as e:
        return False, f"Error: {e}"