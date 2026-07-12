"""
gateway.cli — `arc gateway ...` commands.

Mounted via the `arc.plugins.cli` entry point, same pattern as psqldb.cli
and redix.cli.
"""

from __future__ import annotations

import importlib
import os
import shutil
import warnings

import typer
from rich.console import Console
from rich.table import Table

from arc.runtime import find_project_root

app = typer.Typer(help="Commands for the gateway provider.")
console = Console()
err_console = Console(stderr=True, style="bold red")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    workers: int = typer.Option(1, "--workers"),
    reload: bool = typer.Option(False, "--reload", help="Restart on source changes (dev only)."),
    target: str = typer.Option(
        "gateway._asgi_entrypoint:app", "--app",
        help="Import target Granian loads fresh in every worker. The default "
             "just boots arc with no extra routes. Point this at your own "
             "module if it needs to register routes beyond arc.boot() alone "
             "— e.g. `myproject.entrypoint:app`, where that module does "
             "`import arc; arc.boot(); arc.gateway.add_route(...); "
             "app = arc.gateway`.",
    ),
) -> None:
    """Serve arc.gateway over HTTP using Granian. Each worker process boots
    arc independently, matching §3.6."""
    root = find_project_root()
    if root is None:
        err_console.print("Not inside an ARC project (no .arc/arc.toml found here or in any parent).")
        raise typer.Exit(code=1)
    if shutil.which("granian") is None:
        err_console.print(
            "`granian` was not found on PATH. It should already be a dependency "
            "of the gateway plugin — check `uv sync --all-packages` ran cleanly."
        )
        raise typer.Exit(code=1)

    argv = [
        "granian", "--interface", "asgi", target,
        "--host", host, "--port", str(port), "--workers", str(workers),
    ]
    if reload:
        argv.append("--reload")

    console.print(f"[dim]$ {' '.join(argv)}[/dim]")
    os.execvp("granian", argv)  # replace this process — real signal handling for a foreground server


@app.command()
def routes(
    app_module: str = typer.Option(
        None, "--app",
        help="Import this module first (e.g. `myproject.entrypoint`) if your "
             "application registers routes beyond arc.boot() alone — same "
             "convention as `serve --app`. Without it, only routes registered "
             "by arc.boot() itself are shown.",
    ),
) -> None:
    """List every route currently registered on arc.gateway."""
    root = find_project_root()
    if root is None:
        err_console.print("Not inside an ARC project.")
        raise typer.Exit(code=1)

    import arc

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", arc.ArcAdvisory)
        if app_module:
            importlib.import_module(app_module)  # expected to call arc.boot() itself
        else:
            arc.boot()

    table = Table()
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Summary")
    for route in arc.gateway.routes():
        table.add_row(route.method, route.path, route.summary or "-")
    console.print(table)