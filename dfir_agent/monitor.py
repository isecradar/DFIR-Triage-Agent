"""CPU / memory usage of the agent and every tool process it started (whole process tree).

Sampled by a background thread once per interval. Tools started through WSL interop (.exe) run on the
Windows side and are not visible to Linux - their CPU time is not included.
"""
from __future__ import annotations

import collections
import csv
import os
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

try:
    import psutil
except ImportError:  # installed by setup.sh (requirements.txt)
    psutil = None

SPARK = "▁▂▃▄▅▆▇█"


def fmt_bytes(n: float) -> str:
    return f"{n / 1024 ** 3:.1f} GB" if n >= 1024 ** 3 else f"{n / 1024 ** 2:.0f} MB"


class Sample:
    __slots__ = ("ts", "cpu", "sys_cpu", "rss", "procs")

    def __init__(self, ts, cpu, sys_cpu, rss, procs):
        self.ts, self.cpu, self.sys_cpu, self.rss, self.procs = ts, cpu, sys_cpu, rss, procs


class ResourceMonitor(threading.Thread):
    """cpu = agent + tools in % of the whole machine (100 = all cores busy); cores = same in cores."""

    def __init__(self, running_tasks: Callable[[], Iterable] | None = None, interval: float = 1.0):
        super().__init__(daemon=True, name="resource-monitor")
        self.running_tasks = running_tasks or (lambda: [])
        self.interval = interval
        self.ncpu = os.cpu_count() or 1
        self.history: list[Sample] = []
        self.recent: collections.deque = collections.deque(maxlen=40)
        self.peak_cpu = self.peak_rss = 0.0
        self._procs: dict[int, "psutil.Process"] = {}
        self._halt = threading.Event()
        self.available = psutil is not None
        if self.available:
            self.me = psutil.Process()
            psutil.cpu_percent(None)

    # ------------------------------------------------------------ sampling
    def _proc(self, pid: int):
        p = self._procs.get(pid)
        if p is None:
            p = psutil.Process(pid)
            p.cpu_percent(None)  # first call only primes the counter
            self._procs[pid] = p
        return p

    def _sample(self) -> None:
        cpu_of: dict[int, float] = {}
        rss = 0
        try:
            tree = [self.me] + self.me.children(recursive=True)
        except psutil.Error:
            tree = [self.me]
        for c in tree:
            try:
                p = self._proc(c.pid)
                cpu_of[c.pid] = p.cpu_percent(None)
                rss += p.memory_info().rss
            except psutil.Error:
                continue
        for pid in set(self._procs) - set(cpu_of):  # exited
            del self._procs[pid]
        total = sum(cpu_of.values())
        s = Sample(time.time(), total / self.ncpu, psutil.cpu_percent(None), rss, len(cpu_of))
        self.history.append(s)
        self.recent.append(s.cpu)
        self.peak_cpu, self.peak_rss = max(self.peak_cpu, s.cpu), max(self.peak_rss, rss)
        for t in self.running_tasks():  # per task: its tool processes and their children
            pc = 0.0
            for p in list(getattr(t, "procs", ())):
                try:
                    pids = [p.pid] + [c.pid for c in psutil.Process(p.pid).children(recursive=True)]
                except psutil.Error:
                    continue
                pc += sum(cpu_of.get(x, 0.0) for x in pids)
            t.cpu = pc / self.ncpu

    def run(self) -> None:
        if not self.available:
            return
        while not self._halt.wait(self.interval):
            try:
                self._sample()
            except Exception:  # noqa: BLE001 - monitoring must never break processing
                pass

    def stop(self) -> None:
        self._halt.set()

    # ------------------------------------------------------------ reporting
    @property
    def last(self) -> Sample | None:
        return self.history[-1] if self.history else None

    @property
    def avg_cpu(self) -> float:
        return sum(s.cpu for s in self.history) / len(self.history) if self.history else 0.0

    def sparkline(self, width: int = 24) -> str:
        vals = list(self.recent)[-width:]
        return "".join(SPARK[min(len(SPARK) - 1, int(v / 100 * len(SPARK)))] for v in vals)

    def summary(self) -> str:
        if not self.available:
            return "CPU monitor unavailable (psutil missing - run ./setup.sh)"
        if not self.history:
            return "no CPU samples"
        return (f"CPU (agent + tools) avg {self.avg_cpu:.0f}% / peak {self.peak_cpu:.0f}% of {self.ncpu} cores, "
                f"peak memory {fmt_bytes(self.peak_rss)}")

    def write_csv(self, path: Path) -> None:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["Timestamp", "AgentCpuPercent", "AgentCores", "SystemCpuPercent", "AgentRssMB", "Processes"])
            for s in self.history:
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.ts)), f"{s.cpu:.1f}",
                            f"{s.cpu * self.ncpu / 100:.2f}", f"{s.sys_cpu:.1f}", s.rss // 1024 ** 2, s.procs])
