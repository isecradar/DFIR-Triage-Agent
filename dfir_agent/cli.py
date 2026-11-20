"""Command line entry point."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import threading
import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.table import Table

from . import __version__, collection, config
from .engine import Feed, Job, Scheduler, Status
from .modules import build_extract
from .monitor import ResourceMonitor
from .tools import ToolBox
from .ui import Dashboard, final_report, logo, resource_line


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="dfir-triage",
        description="DFIR Triage Agent - process one or many Velociraptor/KAPE triage collections concurrently.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  dfir-triage -i Collection-HOST-2026-10-19T15_47_49.zip -o /mnt/d/Cases/IR-001\n"
               "  dfir-triage -i /mnt/d/Evidence/ -o /mnt/d/Cases/IR-001 --workers 8      (all collections in folder)\n"
               "  dfir-triage -i D:\\Evidence\\a.zip -i D:\\Evidence\\b.zip -o D:\\Cases\\IR-001\n"
               "  dfir-triage --check-tools")
    p.add_argument("-i", "--input", action="append", default=[], metavar="PATH",
                   help="collection zip, unzipped collection folder, KAPE folder, or a folder containing many "
                        "collections (repeatable)")
    p.add_argument("-o", "--output", metavar="DIR", help="case output folder (one sub-folder per collection)")
    p.add_argument("-p", "--password", help="collection zip password (prompted if needed and not given). "
                                             "Visible to other users in the process list and saved in shell "
                                             "history - prefer --password-file or the prompt")
    p.add_argument("--password-file", metavar="FILE", help="file with candidate passwords, one per line")
    p.add_argument("-c", "--config", metavar="YAML", help="additional config file overriding config.yaml")
    p.add_argument("-w", "--workers", type=int, help="max concurrent tool processes (default: auto)")
    p.add_argument("--heavy", type=int, help="max concurrent memory-heavy tasks (default: 2)")
    p.add_argument("--work-dir", help="extract collections here instead of <output>/<host>/_extracted "
                                      "(use a WSL path such as ~/dta-work for faster I/O)")
    p.add_argument("--no-keep-extracted", action="store_true", help="delete extracted files after processing")
    p.add_argument("--skip", default="", help="comma separated modules to skip (e.g. chainsaw,regripper)")
    p.add_argument("--no-live", action="store_true", help="plain line output instead of the live dashboard")
    p.add_argument("--check-tools", action="store_true", help="show tool status and exit")
    p.add_argument("-V", "--version", action="version", version=f"DFIR Triage Agent {__version__}")
    return p.parse_args(argv)


def tools_table(tb: ToolBox) -> Table:
    t = Table(title="Tool status", box=box.ROUNDED, header_style="bold cyan", title_style="bold")
    for c in ("Tool", "Status", "Runtime / location", "Version"):
        t.add_column(c, overflow="fold")
    for name, st, where, ver in tb.check():
        style = {"ok": "green", "ready": "green", "disabled": "yellow"}.get(st, "bold red")
        t.add_row(escape(name), f"[{style}]{escape(st)}[/]", escape(where), escape(ver))
    return t


def resolve_passwords(items, args, cfg, console: Console) -> None:
    candidates: list[str] = []
    if args.password:
        candidates.append(args.password)
    if args.password_file:
        candidates += [l.strip() for l in Path(args.password_file).read_text().splitlines() if l.strip()]
    candidates += [str(x) for x in cfg["collection"].get("passwords", []) or []]
    candidates.append("infected")  # Velociraptor default
    for it in items:
        if not collection.needs_password(it):
            continue
        it.encrypted = True
        for pw in candidates:
            if collection.check_password(it, pw):
                it.password = pw
                break
        tries = 0
        while it.password is None and tries < 3 and sys.stdin.isatty():
            pw = getpass.getpass(f"  Password for {it.path.name}: ")
            if collection.check_password(it, pw):
                it.password = pw
                candidates.insert(0, pw)
            else:
                console.print("  [red]wrong password[/]")
                tries += 1
        if it.password is None:
            raise SystemExit(f"no valid password for {it.path}")


def main(argv=None) -> int:
    args = parse_args(argv)
    console = Console(highlight=False)
    cfg = config.load(args.config)
    g = cfg["general"]
    if args.workers:
        g["workers"] = args.workers
    if args.heavy:
        g["heavy_task_limit"] = args.heavy
    if args.work_dir:
        g["work_dir"] = args.work_dir
    if args.no_keep_extracted:
        g["keep_extracted"] = False
    for m in filter(None, (s.strip() for s in args.skip.split(","))):
        cfg["modules"].setdefault(m, {})["enabled"] = False
    tb = ToolBox(cfg)

    console.print(logo("Velociraptor / KAPE / UAC collections"))
    if args.check_tools:
        console.print(tools_table(tb))
        console.print(f"EZ tools folder: [cyan]{escape(str(tb.ez_dir))}[/]")
        return 0
    if not args.input or not args.output:
        console.print("[red]-i/--input and -o/--output are required[/] (see --help)")
        return 1
    try:
        items = collection.discover(args.input)
    except FileNotFoundError as e:
        console.print(f"[red]{escape(str(e))}[/]")
        return 1
    if not items:
        console.print("[red]No collections found in the given input(s).[/]")
        return 1
    # .NET + EZ tools are only needed for Windows collections (UAC/Linux processing is pure Python)
    if any(not it.kind.startswith("uac") for it in items) and (not tb.dotnet.exists() or not tb.ez_dir.is_dir()):
        console.print(tools_table(tb))
        console.print("[bold red]Core tools missing - run ./setup.sh and check tools.ez_dir in config.yaml[/]")
        return 1
    t = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
    for c in ("#", "Host", "Collected", "Type", "Source"):
        t.add_column(c)
    for n, it in enumerate(items, 1):
        t.add_row(str(n), f"[bold]{escape(it.host)}[/]", escape(it.stamp), it.kind, escape(str(it.path)))
    console.print(t)
    resolve_passwords(items, args, cfg, console)

    out_root = Path(collection.win_to_wsl(args.output)).expanduser().resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    feed = Feed()
    jobs = [Job(it, out_root, cfg, tb, feed) for it in items]
    for j in jobs:
        build_extract(j)
    sched = Scheduler(jobs, cfg)
    runner = threading.Thread(target=sched.run, daemon=True)
    monitor = ResourceMonitor(lambda: [t for j in jobs for t in j.task_list() if t.status == Status.RUNNING])
    monitor.start()
    t0 = time.monotonic()
    aborted = False
    live_ok = sys.stdout.isatty() and not args.no_live
    try:
        runner.start()
        if live_ok:
            with Live(Dashboard(sched, jobs, feed, console, monitor), console=console, refresh_per_second=8,
                      screen=True, transient=False):
                while runner.is_alive():
                    runner.join(0.25)
        else:
            seen, next_cpu = 0, time.monotonic() + 60
            while runner.is_alive():
                runner.join(0.5)
                seen, new = feed.since(seen)
                for ts, host, lvl, msg in new:
                    col = {"ok": "green", "warn": "yellow", "error": "red"}.get(lvl, "white")
                    # host/msg carry tool output and evidence names - never interpret them as markup
                    console.print(f"[grey50]{ts}[/] [bold]{escape(host)}[/] [{col}]{escape(msg)}[/]")
                if time.monotonic() >= next_cpu and monitor.last:
                    next_cpu = time.monotonic() + 60
                    console.print(f"[grey50]{time.strftime('%H:%M:%S')}[/] [cyan]{resource_line(monitor).plain.strip()}[/]")
    except KeyboardInterrupt:
        console.print("[bold red]Aborting - stopping running tools…[/]")
        aborted = True
        sched.cancel()
        runner.join(10)
    finally:
        monitor.stop()
        for j in jobs:
            if monitor.history:
                try:
                    monitor.write_csv(j.logs / "resource_usage.csv")
                except OSError:
                    pass
            j.log(monitor.summary())
            j.close()
    final_report(console, jobs, time.monotonic() - t0, monitor)
    failed = sum(1 for j in jobs for t in j.task_list() if t.status == Status.FAILED)
    if aborted:
        console.print("[bold red]Run aborted - outputs are incomplete.[/]")
        if runner.is_alive():
            # pure-Python tasks cannot be killed and ThreadPoolExecutor joins its workers at interpreter
            # exit, which would hang here; tool processes were already terminated by sched.cancel()
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(130)
        return 130
    if failed:
        console.print(f"[bold yellow]{failed} task(s) failed - see _logs/ in each output folder.[/]")
    else:
        console.print("[bold green]All tasks completed.[/]")
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
