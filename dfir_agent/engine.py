"""Task model, per-collection job state and the concurrent scheduler."""
from __future__ import annotations

import collections
import datetime as dt
import os
import re
import signal
import subprocess
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from .collection import InputItem, Layout
from .config import CATEGORIES
from .tools import ToolBox

ANSI_RX = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
TS_PREFIX_RX = re.compile(r"^\d{14,20}_")
GUID_SUFFIX_RX = re.compile(r"_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\.\w+$)", re.I)


class Status(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    WARN = "warning"
    SKIPPED = "skipped"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in (Status.DONE, Status.WARN, Status.SKIPPED, Status.FAILED)


class SkipTask(Exception):
    """Raised by a task action when the artifact/tool is not available."""


class TaskWarning(Exception):
    """Raised by a task action when it completed with partial results."""


@dataclass
class Task:
    key: str
    name: str
    tool: str
    category: str
    action: Callable[["Job", "Task"], str | None]
    deps: list[str] = field(default_factory=list)
    pool: str = "normal"            # normal | heavy | extract
    soft_deps: bool = False         # run even if dependencies failed/skipped
    status: Status = Status.PENDING
    progress: float | None = None   # 0..1, None = indeterminate
    detail: str = ""
    message: str = ""
    started: float | None = None
    ended: float | None = None
    procs: set = field(default_factory=set)  # running tool processes (CPU attribution)
    cpu: float = 0.0                         # % of the machine used by this task's tools (ResourceMonitor)

    @property
    def elapsed(self) -> float:
        if not self.started:
            return 0.0
        return (self.ended or time.monotonic()) - self.started


class Feed:
    """Thread-safe recent event feed for the dashboard."""

    def __init__(self, size: int = 200):
        self.items: collections.deque = collections.deque(maxlen=size)
        self.lock = threading.Lock()
        self.count = 0  # total events ever added (the deque only keeps the last `size`)

    def add(self, host: str, level: str, msg: str) -> None:
        with self.lock:
            self.items.append((time.strftime("%H:%M:%S"), host, level, msg))
            self.count += 1

    def tail(self, n: int) -> list:
        with self.lock:
            return list(self.items)[-n:]

    def since(self, seen: int) -> tuple[int, list]:
        """Events added after the first `seen` ones -> (new seen count, events still buffered)."""
        with self.lock:
            new = min(self.count - seen, len(self.items))
            return self.count, (list(self.items)[-new:] if new > 0 else [])


class Job:
    """All state for one collection."""

    def __init__(self, item: InputItem, out_root: Path, cfg: dict, tb: ToolBox, feed: Feed):
        self.item, self.cfg, self.tb, self.feed = item, cfg, tb, feed
        self.host = item.host
        self.out = out_root / item.label
        self.out.mkdir(parents=True, exist_ok=True)
        self.logs = self.out / "_logs"
        self.logs.mkdir(exist_ok=True)
        wd = cfg["general"].get("work_dir")
        self.work = (Path(os.path.expanduser(wd)) / item.label) if wd else self.out / "_extracted"
        self.layout: Layout | None = None
        self.sysinfo: dict = {}
        self.tasks: dict[str, Task] = {}
        self.order: list[str] = []
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.ended: float | None = None
        self.stage = "Queued"
        self.procs: set[subprocess.Popen] = set()
        self.cancelled = threading.Event()  # set by Scheduler.cancel(): no new tool processes
        self._log_fh = open(self.logs / "processing.log", "a", encoding="utf-8")

    # ------------------------------------------------------------ tasks
    def add(self, *tasks: Task) -> None:
        with self.lock:
            for t in tasks:
                if t.key in self.tasks:
                    raise ValueError(f"duplicate task key {t.key}")
                self.tasks[t.key] = t
                self.order.append(t.key)

    def task_list(self) -> list[Task]:
        with self.lock:
            return [self.tasks[k] for k in self.order]

    @property
    def done(self) -> bool:
        ts = self.task_list()
        return bool(ts) and all(t.status.terminal for t in ts) and self.stage != "Extracting"

    def counts(self) -> dict[str, int]:
        c = collections.Counter(t.status for t in self.task_list())
        return {s.value: c.get(s, 0) for s in Status}

    def progress(self) -> float:
        ts = self.task_list()
        if not ts:
            return 0.0
        score = 0.0
        for t in ts:
            if t.status.terminal:
                score += 1
            elif t.status == Status.RUNNING and t.progress is not None:
                score += t.progress
        return score / len(ts)

    # ------------------------------------------------------------ paths
    def cat_dir(self, cat: str) -> Path:
        d = self.out / CATEGORIES[cat]
        d.mkdir(parents=True, exist_ok=True)
        return d

    def name(self, stem: str, ext: str = "csv") -> str:
        return f"{self.host}_{stem}.{ext}"

    @property
    def files(self) -> Path:
        return self.layout.files

    @property
    def sysdrive(self) -> Path | None:
        if self.layout and self.layout.system_drive:
            return self.layout.drives.get(self.layout.system_drive)
        return None

    # ------------------------------------------------------------ logging
    def log(self, msg: str, level: str = "info", feed: bool = False) -> None:
        line = f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [{level.upper():5}] {msg}"
        with self.lock:
            if not self._log_fh.closed:  # tasks still unwinding after an abort may log after close()
                self._log_fh.write(line + "\n")
                self._log_fh.flush()
        if feed:
            self.feed.add(self.host, level, msg)

    def close(self) -> None:
        with self.lock:
            try:
                self._log_fh.close()
            except OSError:
                pass

    # ------------------------------------------------------------ subprocess
    def run(self, task: Task, cmd: list[str], cwd: Path | None = None, log_name: str | None = None,
            progress_rx: str | None = None, total: int | None = None, ok_codes: tuple | None = (0,),
            stdout_file: Path | None = None) -> tuple[int, list[str]]:
        """Run a tool, stream its output to a per-task log, update live detail/progress.

        Returns (returncode, last output lines). Raises RuntimeError for unexpected exit codes.
        """
        logf = self.logs / f"{log_name or task.key}.log"
        prx = re.compile(progress_rx) if progress_rx else None
        hits = 0
        tail: collections.deque = collections.deque(maxlen=40)
        if self.cancelled.is_set():
            raise RuntimeError("cancelled")
        self.log(f"[{task.key}] exec: {' '.join(_q(c) for c in cmd)}")
        with open(logf, "a", encoding="utf-8", errors="replace") as lf:
            lf.write(f"\n### {dt.datetime.now().isoformat(timespec='seconds')}  cwd={cwd or os.getcwd()}\n")
            lf.write("### " + " ".join(_q(c) for c in cmd) + "\n\n")
            lf.flush()
            out_fh = open(stdout_file, "w", encoding="utf-8", errors="replace") if stdout_file else None
            try:
                p = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None, env=self.tb.env(),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT if not out_fh else subprocess.PIPE,
                                     text=True, encoding="utf-8", errors="replace", bufsize=1,
                                     start_new_session=True)
            except OSError as e:
                if out_fh:
                    out_fh.close()
                raise RuntimeError(f"cannot start {cmd[0]}: {e}") from e
            with self.lock:
                self.procs.add(p)
                late = self.cancelled.is_set()  # cancel() ran between the check above and Popen
            task.procs.add(p)
            if late:
                _terminate(p)
            err_thread = None
            if out_fh:  # stdout is data (e.g. RegRipper report) -> stderr goes to the log
                def _pump_err():
                    for l in p.stderr:
                        lf.write(l)
                err_thread = threading.Thread(target=_pump_err, daemon=True)
                err_thread.start()
            try:
                for line in p.stdout:
                    if out_fh:
                        out_fh.write(line)
                        continue
                    lf.write(line)
                    clean = ANSI_RX.sub("", line).strip()
                    if clean:
                        tail.append(clean)
                        task.detail = clean[:160]
                        if prx and total and prx.search(clean):
                            hits += 1
                            task.progress = min(hits / total, 0.99)
                p.wait()
            finally:
                with self.lock:
                    self.procs.discard(p)
                task.procs.discard(p)
                if err_thread:
                    err_thread.join(timeout=5)
                if out_fh:
                    out_fh.close()
            lf.write(f"\n### exit code {p.returncode}\n")
        if ok_codes is not None and p.returncode not in ok_codes:
            raise RuntimeError(f"{task.tool} exited with code {p.returncode}: {tail[-1] if tail else ''}")
        return p.returncode, list(tail)

    def kill_all(self) -> None:
        with self.lock:
            self.cancelled.set()
            procs = list(self.procs)
        for p in procs:
            _terminate(p)

    # ------------------------------------------------------------ helpers
    def tidy_outputs(self, folder: Path, stem: str, before: set[Path] | None = None) -> list[Path]:
        """Rename timestamp-prefixed EZ outputs to <HOST>_<stem>_<rest>.csv."""
        out = []
        for p in sorted(folder.iterdir()):
            if not p.is_file() or (before is not None and p in before):
                continue
            n = GUID_SUFFIX_RX.sub("", TS_PREFIX_RX.sub("", p.name))
            if n != p.name or not n.startswith(self.host):
                target = folder / f"{self.host}_{stem}_{n}" if not n.lower().startswith(stem.lower()) \
                    else folder / f"{self.host}_{n}"
                i = 1
                base = target
                while target.exists():  # several sources can map to one name (e.g. browser profiles)
                    i += 1
                    target = base.with_name(f"{base.stem}_{i}{base.suffix}")
                p.rename(target)
                p = target
            out.append(p)
        return out


def _terminate(p: subprocess.Popen) -> None:
    """SIGTERM the tool's whole process group (it was started with start_new_session=True)."""
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass


def _q(s: str) -> str:
    return f'"{s}"' if (" " in s or not s) else s


# =============================================================================== scheduler
class Scheduler:
    def __init__(self, jobs: list[Job], cfg: dict):
        g = cfg["general"]
        cpu = os.cpu_count() or 4
        self.jobs = jobs
        self.workers = g.get("workers") or max(2, min(cpu, 8))
        self.limits = {"heavy": max(1, int(g.get("heavy_task_limit", 2))),
                       "extract": max(1, int(g.get("extract_limit", 2))),
                       "normal": self.workers}
        self.running: collections.Counter = collections.Counter()
        self.total_running = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.started = time.monotonic()
        self.finished: float | None = None

    def _ready(self, job: Job, t: Task) -> bool | str:
        """True = runnable, False = wait, str = skip reason."""
        for d in t.deps:
            dt_ = job.tasks.get(d)
            if dt_ is None:
                continue
            if not dt_.status.terminal:
                return False
            if dt_.status in (Status.FAILED, Status.SKIPPED) and not t.soft_deps:
                return f"dependency '{dt_.name}' {dt_.status.value}"
        return True

    def _exec(self, job: Job, t: Task) -> None:
        t.status, t.started = Status.RUNNING, time.monotonic()
        job.log(f"[{t.key}] start {t.name} ({t.tool})")
        try:
            msg = t.action(job, t)
            t.status, t.message = Status.DONE, msg or ""
        except SkipTask as e:
            t.status, t.message = Status.SKIPPED, str(e)
        except TaskWarning as e:
            t.status, t.message = Status.WARN, str(e)
        except Exception as e:  # noqa: BLE001 - any tool failure must not stop the run
            t.status, t.message = Status.FAILED, str(e)[:300]
            job.log(f"[{t.key}] FAILED: {e}\n{traceback.format_exc()}", "error")
        finally:
            t.ended = time.monotonic()
            t.progress = 1.0 if t.status in (Status.DONE, Status.WARN) else t.progress
            lvl = {"done": "ok", "warning": "warn", "skipped": "skip", "failed": "error"}[t.status.value]
            job.log(f"[{t.key}] {t.status.value} in {t.elapsed:.1f}s {t.message}", lvl)
            if t.status != Status.SKIPPED:
                self.jobs[0].feed.add(job.host, lvl, f"{t.name} ({t.tool}) {t.status.value} "
                                                     f"in {t.elapsed:.0f}s - {t.message}")
            with self.lock:
                self.running[t.pool] -= 1
                self.total_running -= 1

    def run(self) -> None:
        with ThreadPoolExecutor(max_workers=self.workers + self.limits["extract"]) as pool:
            while not self.stop.is_set():
                pending_any = False
                candidates: list[tuple[int, Job, Task]] = []
                for job in self.jobs:
                    for t in job.task_list():
                        if t.status != Status.PENDING:
                            continue
                        pending_any = True
                        r = self._ready(job, t)
                        if r is True:
                            prio = {"extract": 0, "heavy": 1, "normal": 2}[t.pool]
                            candidates.append((prio, job, t))
                        elif isinstance(r, str):
                            t.status, t.message = Status.SKIPPED, r
                            t.started = t.ended = time.monotonic()
                            job.log(f"[{t.key}] skipped: {r}", "skip")
                candidates.sort(key=lambda c: c[0])
                for _, job, t in candidates:
                    with self.lock:
                        if self.running[t.pool] >= self.limits[t.pool]:
                            continue
                        if t.pool != "extract" and self.total_running >= self.workers + self.running["extract"]:
                            break
                        self.running[t.pool] += 1
                        self.total_running += 1
                        t.status = Status.RUNNING
                    pool.submit(self._exec, job, t)
                for job in self.jobs:
                    if job.ended is None and job.done:
                        job.ended = time.monotonic()
                        job.stage = "Completed" if not job.counts()["failed"] else "Completed with errors"
                with self.lock:
                    busy = self.total_running
                if not pending_any and busy == 0:
                    break
                time.sleep(0.15)
        self.finished = time.monotonic()

    def cancel(self) -> None:
        self.stop.set()
        for j in self.jobs:
            j.kill_all()
            for t in j.task_list():
                if not t.status.terminal:
                    t.status, t.message = Status.FAILED, "cancelled"
