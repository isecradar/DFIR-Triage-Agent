"""Rich terminal dashboard: logo, per-task progress (single host) or fleet overview (multi host)."""
from __future__ import annotations

import time

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import CATEGORIES
from .engine import Feed, Job, Scheduler, Status, Task
from .monitor import ResourceMonitor, fmt_bytes
from .tools import to_windows_path

LOGO = [
    "██████╗ ███████╗██╗██████╗ ",
    "██╔══██╗██╔════╝██║██╔══██╗",
    "██║  ██║█████╗  ██║██████╔╝",
    "██║  ██║██╔══╝  ██║██╔══██╗",
    "██████╔╝██║     ██║██║  ██║",
    "╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝",
]
# Blue palette: cyan #05B1E8 -> blue #007AC1 -> cobalt #0749A0
ACCENT_CYAN, ACCENT_BLUE, ACCENT_COBALT = "#05B1E8", "#007AC1", "#0749A0"
GRADIENT = [ACCENT_CYAN, "#04A0DB", "#028DCE", ACCENT_BLUE, "#0462B0", ACCENT_COBALT]
BORDER = ACCENT_BLUE

CAT_STYLE = {
    "info": "bright_white", "exec": "bright_red", "fileopen": "bright_yellow", "deleted": "orange3",
    "fs": "bright_cyan", "evtx": "bright_blue", "registry": "medium_purple1", "browser": "spring_green2",
    "account": "gold1", "network": "deep_sky_blue1", "usb": "plum1", "persist": "indian_red1",
    "remote": "light_salmon1", "live": "aquamarine1", "hunt": "red1", "apps": "light_steel_blue",
}
CAT_SHORT = {k: v.split("_", 1)[1].replace("_", " ") for k, v in CATEGORIES.items()}
CAT_SHORT.update({"exec": "Execution", "fileopen": "File/Folder Open", "usb": "USB Devices",
                  "fs": "File System", "info": "Case Info", "hunt": "Threat Hunting", "apps": "Applications",
                  "remote": "Remote Access", "live": "Live Response", "account": "Account Usage"})

ICON = {
    Status.PENDING: Text("·", style="grey50"),
    Status.DONE: Text("✔", style="bold green"),
    Status.WARN: Text("▲", style="bold yellow"),
    Status.SKIPPED: Text("⊘", style="grey58"),
    Status.FAILED: Text("✖", style="bold red"),
}


def fmt_time(s: float) -> str:
    s = int(s)
    return f"{s // 3600:d}:{s % 3600 // 60:02d}:{s % 60:02d}" if s >= 3600 else f"{s // 60:02d}:{s % 60:02d}"


def logo(subtitle: str = "") -> Table:
    left = Text()
    for line, col in zip(LOGO, GRADIENT):
        left.append(line + "\n", style=f"bold {col}")
    right = Text()
    right.append("\n")
    right.append("T R I A G E   A G E N T\n", style=f"bold {ACCENT_CYAN}")
    right.append(f"v{__version__} · Windows & Linux triage processing\n", style="grey62")
    right.append("EZ Tools · Hayabusa · Chainsaw · UAC\n", style="grey62")
    right.append(subtitle, style="bright_white")
    g = Table.grid(padding=(0, 3))
    g.add_column()
    g.add_column(vertical="top")
    g.add_row(left, right)
    return g


def cpu_text(cpu: float, running: bool = True) -> Text:
    if not running:
        return Text("")
    style = "red" if cpu >= 80 else "yellow" if cpu >= 50 else "green"
    return Text(f"{cpu:.0f}%", style=style)


def resource_line(mon: ResourceMonitor | None) -> Text:
    t = Text()
    if mon is None:
        return t
    s = mon.last
    if not mon.available:
        t.append(" CPU n/a (pip install psutil / ./setup.sh)", style="grey42")
    elif s:
        t.append(" CPU ", style="grey70")
        t.append_text(cpu_text(s.cpu))
        t.append(f" ({s.cpu * mon.ncpu / 100:.1f}/{mon.ncpu} cores) ", style="grey62")
        t.append(mon.sparkline(16), style=ACCENT_CYAN)
        t.append(f"  sys {s.sys_cpu:.0f}%", style="grey62")
        t.append(f"   RAM {fmt_bytes(s.rss)}", style="grey70")
    return t


class Dashboard:
    def __init__(self, sched: Scheduler, jobs: list[Job], feed: Feed, console: Console,
                 monitor: ResourceMonitor | None = None):
        self.sched, self.jobs, self.feed, self.console = sched, jobs, feed, console
        self.monitor = monitor
        self.spinners: dict[str, Spinner] = {}
        seen: dict[str, int] = {}
        self.names: dict[int, str] = {}
        for j in jobs:  # same host collected twice -> HOST#2
            seen[j.host] = seen.get(j.host, 0) + 1
            self.names[id(j)] = j.host if seen[j.host] == 1 else f"{j.host}#{seen[j.host]}"

    # --------------------------------------------------------------- pieces
    def _spinner(self, key: str) -> Spinner:
        if key not in self.spinners:
            self.spinners[key] = Spinner("dots", style="bold cyan")
        return self.spinners[key]

    def _icon(self, job: Job, t: Task):
        if t.status == Status.RUNNING:
            return self._spinner(f"{id(job)}/{t.key}")
        return ICON[t.status]

    @staticmethod
    def _bar(t: Task, width: int = 18):
        if t.status == Status.RUNNING:
            if t.progress is None:
                return ProgressBar(total=None, width=width, pulse=True, style="grey23", pulse_style="cyan")
            return ProgressBar(total=100, completed=t.progress * 100, width=width,
                               complete_style="cyan", finished_style="green")
        if t.status in (Status.DONE, Status.WARN):
            return ProgressBar(total=100, completed=100, width=width,
                               finished_style="green" if t.status == Status.DONE else "yellow")
        if t.status == Status.FAILED:
            return ProgressBar(total=100, completed=100, width=width, finished_style="red")
        return ProgressBar(total=100, completed=0, width=width, style="grey23")


    # --------------------------------------------------------------- single host
    def _single(self, job: Job, max_rows: int):
        tbl = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold grey70", pad_edge=False,
                    show_edge=False)
        tbl.add_column("", width=2)
        tbl.add_column("Category", width=16, no_wrap=True)
        tbl.add_column("Task", ratio=3, no_wrap=True, overflow="ellipsis")
        tbl.add_column("Tool", width=20, no_wrap=True, overflow="ellipsis")
        tbl.add_column("Progress", width=18)
        tbl.add_column("Time", width=6, justify="right")
        tbl.add_column("CPU", width=5, justify="right")
        tbl.add_column("Detail / Result", ratio=4, no_wrap=True, overflow="ellipsis")
        tasks = job.task_list()
        if len(tasks) > max_rows:  # keep running/failed visible, compress the rest
            run = [t for t in tasks if t.status in (Status.RUNNING, Status.FAILED)]
            pend = [t for t in tasks if t.status == Status.PENDING]
            fin = [t for t in tasks if t.status in (Status.DONE, Status.WARN, Status.SKIPPED)]
            room = max(0, max_rows - len(run) - 1)
            fin.sort(key=lambda t: t.ended or 0)  # most recently finished last
            keep_fin = fin[-max(0, room // 2):] if room // 2 else []
            keep_pend = pend[:max(0, room - len(keep_fin))]
            hidden = len(tasks) - len(run) - len(keep_fin) - len(keep_pend)
            tasks = [t for t in tasks if t in run or t in keep_fin or t in keep_pend]
        else:
            hidden = 0
        for t in tasks:
            detail = t.detail if t.status == Status.RUNNING else (t.message or t.detail)
            style = {"failed": "red", "warning": "yellow", "skipped": "grey50"}.get(t.status.value, "grey70")
            tbl.add_row(self._icon(job, t),
                        Text(CAT_SHORT.get(t.category, t.category), style=CAT_STYLE.get(t.category, "white")),
                        Text(t.name, style="bold white" if t.status == Status.RUNNING else
                             ("grey50" if t.status == Status.SKIPPED else "white")),
                        Text(t.tool, style="grey62"), self._bar(t),
                        Text(fmt_time(t.elapsed) if t.started else "", style="grey62"),
                        cpu_text(t.cpu, t.status == Status.RUNNING and bool(t.procs)),
                        Text(detail, style=style))
        if hidden:
            tbl.add_row("", "", Text(f"… +{hidden} tasks", style="italic grey50"), "", "", "", "",
                        Text("completed/queued tasks hidden - enlarge the window to see all", style="italic grey50"))
        return Panel(Group(job_header(job), tbl),
                     title=f"[bold bright_white]🖥  {escape(job.host)}[/]  [grey58]{escape(job.item.stamp)}[/]",
                     border_style=BORDER, box=box.ROUNDED, padding=(0, 1))

    # --------------------------------------------------------------- multi host
    def _fleet(self, max_rows: int):
        ov = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold grey70", show_edge=False)
        ov.add_column("Host", width=22, no_wrap=True, overflow="ellipsis")
        ov.add_column("Stage", width=12, no_wrap=True)
        ov.add_column("Progress", width=26)
        ov.add_column("%", width=6, justify="right")
        ov.add_column("Tasks", width=16, no_wrap=True)
        ov.add_column("Running now", ratio=1, no_wrap=True, overflow="ellipsis")
        ov.add_column("Elapsed", width=8, justify="right")
        for j in self.jobs:
            p = j.progress()
            running = [t for t in j.task_list() if t.status == Status.RUNNING]
            ov.add_row(Text(self.names[id(j)], style="bold bright_white"),
                       Text(j.stage, style=_stage_style(j.stage)),
                       ProgressBar(total=100, completed=p * 100, width=26, complete_style=ACCENT_BLUE,
                                   finished_style="bold green"),
                       Text(f"{p * 100:.0f}%", style="bold"), status_counts(j),
                       Text(", ".join(t.name for t in running) or "-", style="cyan"),
                       Text(fmt_time((j.ended or time.monotonic()) - j.started), style="grey62"))
        act = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold grey70", show_edge=False)
        act.add_column("", width=2)
        act.add_column("Host", width=18, no_wrap=True, overflow="ellipsis")
        act.add_column("Category", width=16, no_wrap=True)
        act.add_column("Task", ratio=2, no_wrap=True, overflow="ellipsis")
        act.add_column("Tool", width=18, no_wrap=True)
        act.add_column("Progress", width=18)
        act.add_column("Time", width=6, justify="right")
        act.add_column("CPU", width=5, justify="right")
        act.add_column("Detail", ratio=3, no_wrap=True, overflow="ellipsis")
        rows = [(j, t) for j in self.jobs for t in j.task_list() if t.status == Status.RUNNING]
        for j, t in rows[:max(3, max_rows - len(self.jobs) - 4)]:
            act.add_row(self._icon(j, t), Text(self.names[id(j)], style="bright_white"),
                        Text(CAT_SHORT.get(t.category, t.category), style=CAT_STYLE.get(t.category, "white")),
                        t.name, Text(t.tool, style="grey62"), self._bar(t),
                        Text(fmt_time(t.elapsed), style="grey62"), cpu_text(t.cpu, bool(t.procs)),
                        Text(t.detail, style="grey70"))
        return Group(
            Panel(ov, title=f"[bold bright_white]Collections ({len(self.jobs)})[/]", border_style=BORDER,
                  box=box.ROUNDED, padding=(0, 1)),
            Panel(act if rows else Align.center(Text("waiting for tasks…", style="grey50")),
                  title="[bold bright_white]Active tasks[/]", border_style=ACCENT_CYAN, box=box.ROUNDED,
                  padding=(0, 1)))

    # --------------------------------------------------------------- feed + status
    def _footer(self, n: int):
        lines = Text()
        for ts, host, lvl, msg in self.feed.tail(n):
            st = {"ok": "green", "warn": "yellow", "error": "bold red", "skip": "grey50"}.get(lvl, "grey70")
            ic = {"ok": "✔", "warn": "▲", "error": "✖", "skip": "⊘"}.get(lvl, "•")
            lines.append(f"{ts} ", style="grey42")
            if len(self.jobs) > 1:
                lines.append(f"{host:<16.16} ", style="bright_white")
            lines.append(f"{ic} {msg}\n", style=st)
        s = self.sched
        stat = Text()
        stat.append(f" workers {s.total_running}/{s.workers}", style="cyan")
        stat.append(f"   heavy {s.running['heavy']}/{s.limits['heavy']}", style="magenta")
        stat.append(f"   extract {s.running['extract']}/{s.limits['extract']}", style="blue")
        stat.append(f"   elapsed {fmt_time(time.monotonic() - s.started)}", style="grey70")
        stat.append("   Ctrl+C to abort", style="grey42")
        return Group(Rule(style="grey30"), lines if lines else Text(""), stat)

    def __rich__(self):
        h, w = self.console.size.height, self.console.size.width
        feed_n = 5 if h >= 40 else 3
        sub = f"{len(self.jobs)} collection(s) · {self.sched.workers} workers"
        if h < 36 or w < 100:  # small window: one-line title instead of the big logo
            head = Text.assemble(("▌DFIR ", f"bold {GRADIENT[0]}"), ("TRIAGE AGENT ", f"bold {GRADIENT[-1]}"),
                                 (f"v{__version__} · {sub}", "grey62"))
            avail = h - feed_n - 12 - (2 if w < 100 else 0)  # job header wraps on narrow terminals
        else:
            head = logo(sub)
            avail = h - len(LOGO) - feed_n - 12
        res = resource_line(self.monitor)
        if res:
            avail -= 1
        body = self._single(self.jobs[0], max(4, avail)) if len(self.jobs) == 1 else self._fleet(max(4, avail))
        return Group(head, *([res] if res else []), body, self._footer(feed_n))


def status_counts(job: Job) -> Text:
    c = job.counts()
    t = Text()
    t.append(f"✔{c['done']} ", style="green")
    if c["warning"]:
        t.append(f"▲{c['warning']} ", style="yellow")
    if c["failed"]:
        t.append(f"✖{c['failed']} ", style="bold red")
    t.append(f"⊘{c['skipped']}", style="grey58")
    return t


def job_header(job: Job) -> Table:
    g = Table.grid(padding=(0, 2), expand=True)
    g.add_column(ratio=1)
    g.add_column(width=34)
    g.add_column(justify="right")
    p = job.progress()
    bar = ProgressBar(total=100, completed=p * 100, width=32,
                      complete_style=ACCENT_BLUE, finished_style="bold green")
    ts = job.task_list()
    done = sum(1 for t in ts if t.status.terminal)
    right = Text(f"{p * 100:5.1f}%  {done}/{len(ts)} tasks  ", style="bold")
    right.append_text(status_counts(job))
    right.append(f"   ⏱ {fmt_time((job.ended or time.monotonic()) - job.started)}", style="grey70")
    si = job.sysinfo
    os_s = f"{si.get('ProductName', '')} {si.get('DisplayVersion', '')}".strip() or job.item.kind
    g.add_row(Text.assemble(("● ", _stage_style(job.stage)), (job.stage, _stage_style(job.stage)),
                            ("  " + os_s, "grey70")), bar, right)
    return g


def _stage_style(stage: str) -> str:
    return {"Queued": "grey58", "Extracting": "bold blue", "Processing": "bold cyan", "Completed": "bold green",
            "Completed with errors": "bold yellow"}.get(stage, "white")


# =================================================================== final report
def final_report(console: Console, jobs: list[Job], elapsed: float,
                 monitor: ResourceMonitor | None = None) -> None:
    console.print(logo(f"Run finished in {fmt_time(elapsed)}"))
    if monitor is not None:
        console.print(f"   [grey70]{monitor.summary()}[/]")
    for j in jobs:
        tbl = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold grey70", show_edge=False)
        tbl.add_column("", width=2)
        tbl.add_column("Category", width=16, no_wrap=True)
        tbl.add_column("Task", ratio=2, no_wrap=True, overflow="ellipsis")
        tbl.add_column("Tool", width=20, no_wrap=True)
        tbl.add_column("Time", width=6, justify="right")
        tbl.add_column("Result", ratio=3, overflow="fold")
        for t in j.task_list():
            st = {"failed": "red", "warning": "yellow", "skipped": "grey50"}.get(t.status.value, "grey85")
            tbl.add_row(ICON.get(t.status, Text("?")),
                        Text(CAT_SHORT.get(t.category, t.category), style=CAT_STYLE.get(t.category, "white")),
                        t.name, Text(t.tool, style="grey62"), fmt_time(t.elapsed), Text(t.message, style=st))
        console.print(Panel(Group(job_header(j), tbl),
                            title=f"[bold bright_white]🖥  {escape(j.host)}[/]", border_style=BORDER,
                            box=box.ROUNDED))
        win = to_windows_path(j.out) if str(j.out).startswith("/mnt/") else ""
        out = escape(str(j.out))
        console.print(f"   [bold]Output:[/] [link=file://{out}]{out}[/link]" + (f"   [cyan]{escape(win)}[/]" if win else ""))
        console.print(f"   [grey62]Logs  : {escape(str(j.logs))}[/]\n")
