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
import sqlite3
from .display.tables import print_certificates_table
from .storage.db import Inventory
from .notifications.slack import send_slack
from .util.timebox import iso_to_days_left


app = typer.Typer(add_completion=False, help="OrcheTrust CLI")

inventory_app = typer.Typer(help="Inventory commands")
app.add_typer(inventory_app, name="inventory")

alerts_app = typer.Typer(help="Alerting commands")
app.add_typer(alerts_app, name="alerts")

@app.callback()
def main(ctx: typer.Context):
    """
    OrcheTrust - lightweight certificate lifecycle manager.
    """
    ctx.obj = {}
    ctx.obj["logger"] = get_logger()
    ctx.obj["config"] = Config.load()

@inventory_app.command("list")
def inventory_list(
    source: Optional[str] = typer.Option(None, "--source", help='Filter by source, e.g. "filesystem"'),
    expiring_within: Optional[int] = typer.Option(None, "--expiring-within", help="Days until expiry threshold"),
    json_out: bool = typer.Option(False, "--json", help="Output JSON instead of table."),
):
    """List stored certificates in the inventory."""
    cfg = Config.load()
    inv = Inventory(cfg.db_path)
    rows = inv.list(source=source, expiring_within_days=expiring_within)
    inv.close()

    if json_out:
        typer.echo(json.dumps(rows, indent=2, default=str))
        raise typer.Exit()

    from rich.table import Table
    from rich import print as rprint

    table = Table(title="Inventory")
    for c in ["Source", "Location", "Subject", "Issuer", "Not After", "Days Left", "SANs", "First Seen", "Last Seen"]:
        table.add_column(c, overflow="fold")

    for r in rows:
        table.add_row(
            r.get("source") or "",
            r.get("location") or "",
            r.get("subject") or "",
            r.get("issuer") or "",
            r.get("not_after") or "",
            str(r.get("days_left") if r.get("days_left") is not None else ""),
            ", ".join(r.get("sans") or []),
            r.get("first_seen") or "",
            r.get("last_seen") or "",
        )
    rprint(table)

@inventory_app.command("purge")
def inventory_purge(
    source: Optional[str] = typer.Option(None, "--source", help='Purge only a source, e.g. "filesystem"'),
    yes: bool = typer.Option(False, "--yes", help="Do not prompt for confirmation."),
):
    """Delete inventory entries (all or by source)."""
    if not yes:
        typer.confirm(
            f"This will delete {'ALL entries' if not source else f'entries with source={source}'} from the inventory. Continue?",
            abort=True
        )
    cfg = Config.load()
    inv = Inventory(cfg.db_path)
    deleted = inv.purge(source=source)
    inv.close()
    typer.echo(f"Deleted {deleted} row(s).")

@alerts_app.command("run")
def alerts_run(
    threshold: int = typer.Option(30, "--threshold", "-t", help="Days until expiry to alert on."),
    source: Optional[str] = typer.Option(None, "--source", help='Filter by source, e.g. "filesystem"'),
    json_out: bool = typer.Option(False, "--json", help="Output JSON payload instead of text."),
    send: bool = typer.Option(False, "--send-slack", help="Send alerts to Slack using configured webhook."),
):
    """
    Generate alerts for certificates expiring within the next N days.
    """
    log = get_logger()
    cfg = Config.load()

    inv = Inventory(cfg.db_path)
    rows = inv.list(source=source, expiring_within_days=threshold)
    inv.close()

    # Ensure days_left is present
    for r in rows:
        if "days_left" not in r or r["days_left"] is None:
            r["days_left"] = iso_to_days_left(r.get("not_after"))

    # Sort by soonest expiry
    rows.sort(key=lambda r: (r["days_left"] if r["days_left"] is not None else 999999, r.get("not_after") or ""))

    if json_out:
        payload = {
            "threshold_days": threshold,
            "count": len(rows),
            "items": rows,
        }
        typer.echo(json.dumps(payload, indent=2, default=str))
        raise typer.Exit()

    # Human-friendly output
    from rich.table import Table
    from rich import print as rprint

    if not rows:
        rprint("[bold green]No certificates expiring within[/] "
               f"[bold]{threshold}[/] day(s){' for source '+source if source else ''}.")
    else:
        title = f"Certificates expiring within {threshold} day(s)"
        if source:
            title += f" (source={source})"
        table = Table(title=title)
        for c in ["Source", "Location", "Subject", "Issuer", "Not After", "Days Left", "SANs"]:
            table.add_column(c, overflow="fold")

        for r in rows:
            table.add_row(
                r.get("source") or "",
                r.get("location") or "",
                r.get("subject") or "",
                r.get("issuer") or "",
                r.get("not_after") or "",
                str(r.get("days_left") if r.get("days_left") is not None else ""),
                ", ".join(r.get("sans") or []),
            )
        rprint(table)

    # Optionally send to Slack
    if send:
        webhook = cfg.slack_webhook_url
        if not webhook:
            log.error("Slack webhook not configured. Set ORCHETRUST_SLACK_WEBHOOK_URL or slack_webhook_url in config.")
            raise typer.Exit(code=2)

        if not rows:
            text = f"✅ No certificates expiring within {threshold} day(s)."
            ok, detail = send_slack(webhook, text)
            log.info(f"Slack notify: {detail}" if ok else f"Slack notify failed: {detail}")
            raise typer.Exit()

        # Compose a concise Slack message (plain text keeps it simple)
        lines = [f"⚠️ {len(rows)} certificate(s) expiring within {threshold} day(s):"]
        for r in rows[:20]:  # cap to avoid giant messages
            loc = r.get("location") or r.get("path") or "(no location)"
            subj = r.get("subject") or "(no subject)"
            days = r.get("days_left")
            exp = r.get("not_after")
            lines.append(f"• [{days}d] {subj} — {loc} (exp {exp})")
        if len(rows) > 20:
            lines.append(f"...and {len(rows)-20} more")

        ok, detail = send_slack(webhook, "\n".join(lines))
        if ok:
            log.info(f"Slack notify: {detail}")
        else:
            log.error(f"Slack notify failed: {detail}")

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
    table.add_row("DB Path", cfg.db_path)
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
    write_db: bool = typer.Option(False, "--write-db", help="Persist results to inventory DB."),
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

    if write_db:
        inv = Inventory(cfg.db_path)
        count = inv.upsert_many(rows)
        inv.close()
        log.info(f"Wrote {count} records to inventory")

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
            r.get("path") or "",
            r.get("subject") or "",
            r.get("issuer") or "",
            r.get("not_after") or "",
            str(r.get("days_left") if r.get("days_left") is not None else ""),
            ", ".join(r.get("sans") or []) if r.get("sans") else "-",
        )
    rprint(table)
    
if __name__ == "__main__":
    app()