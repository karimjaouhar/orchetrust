import typer
from rich import print as rprint
from rich.table import Table
from .version import __version__
from .log import get_logger
from .config import Config
import json
from typing import Optional
from .discovery.filesystem import scan_filesystem
from pathlib import Path


app = typer.Typer(add_completion=False, help="OrcheTrust CLI")

@app.callback()
def main(ctx: typer.Context):
    """
    OrcheTrust - lightweight certificate lifecycle manager.
    """
    ctx.obj = {}
    ctx.obj["logger"] = get_logger()
    ctx.obj["config"] = Config.load()

@app.command()
def version():
    """Show version."""
    rprint(f"[bold green]OrcheTrust[/] v{__version__}")

@app.command()
def hello(name: str = typer.Argument("world")):
    """Say hello (smoke test)."""
    rprint(f"👋 Hello, {name}!")

@app.command()
def status():
    """Show basic status/state."""
    cfg: Config = Config.load()
    table = Table(title="OrcheTrust Status")
    table.add_column("Key")
    table.add_column("Value")
    table.add_row("Version", __version__)
    table.add_row("Slack Webhook", "set" if cfg.slack_webhook_url else "not set")
    table.add_row("Configured Scan Paths", ", ".join(cfg.scan_paths) if cfg.scan_paths else "(none)")
    rprint(table)

@app.command()
def scan(
path: list[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Path(s) to scan (comma-separated). Example: --path /etc/ssl,/etc/nginx",
    ),
    json_out: bool = typer.Option(False, "--json", help="Output JSON instead of a table."),
):
    """
    Scan local filesystem for certificates (.pem/.crt/.cer) and show expiry.
    """
    log = get_logger()
    cfg = Config.load()
    default_paths = cfg.scan_paths or [
        "/etc/ssl", "/etc/nginx", "/usr/local/etc/ssl", str(Path.home() / ".orchetrust" / "certs")
    ]
    paths = list(default_paths)
    if path:
        extra_paths = []
        for p in path:
            extra_paths += [x.strip() for x in p.split(",") if x.strip()]
        paths += extra_paths

    log.info(f"Scanning paths: {paths}")
    rows = scan_filesystem(paths)

    if json_out:
        typer.echo(json.dumps(rows, indent=2, default=str))
        raise typer.Exit()

    from rich.table import Table
    from rich import print as rprint

    table = Table(title="Discovered Certificates")
    for c in ["Source", "Path", "CN/SUBJECT", "Issuer", "Not After", "Days Left", "SANs"]:
        table.add_column(c, overflow="fold")

    for r in rows:
        table.add_row(
            r["source"],
            r["path"],
            r["subject"],
            r["issuer"],
            r["not_after"],
            str(r["days_left"]),
            ", ".join(r["sans"]) if r["sans"] else "-",
        )
    rprint(table)

if __name__ == "__main__":
    app()