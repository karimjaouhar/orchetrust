import typer
from rich import print as rprint
from rich.table import Table
from .version import __version__
from .log import get_logger
from .config import Config

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

if __name__ == "__main__":
    app()