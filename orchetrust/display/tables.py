from rich.table import Table
from rich import print as rprint

def print_certificates_table(title: str, certificates: list[dict]) -> None:
    table = Table(title=title)
    for c in ["Source", "Path", "CN/SUBJECT", "Issuer", "Not After", "Days Left", "SANs"]:
        table.add_column(c, overflow="fold")

    for r in certificates:
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
    return None