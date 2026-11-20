"""Locating external tools and building their command lines.

EZ tools are .NET 10 assemblies: they run on Linux with `dotnet <tool>.dll`. Tools that need
Windows-only ESE libraries (SrumECmd, SumECmd) run through WSL interop (`<tool>.exe` with
Windows paths) using the host's .NET 10 runtime.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

EZ_TOOLS = ["AmcacheParser", "AppCompatCacheParser", "PECmd", "RecentFileCacheParser", "SrumECmd",
            "SumECmd", "LECmd", "JLECmd", "SBECmd", "WxTCmd", "RBCmd", "MFTECmd", "EvtxECmd",
            "RECmd", "SQLECmd"]


class ToolBox:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        t = cfg["tools"]
        self.home = Path(t["dta_home"])
        self.tools = self.home / "tools"
        self.windows_only = {n.lower() for n in t.get("ez_windows_only", [])}
        self.dotnet = self.tools / "dotnet" / "dotnet"
        self.versions = self._load("versions.json")
        self.setup_env = self._load("env.json")
        # EZ folder: config value when it holds the tools, else what setup resolved/downloaded
        self.ez_dir = Path(t["ez_dir"])
        if not (self.ez_dir / "PECmd.dll").exists() and self.setup_env.get("ez_dir"):
            self.ez_dir = Path(self.setup_env["ez_dir"])
        wd = self.setup_env.get("win_dotnet", "")
        self.win_dotnet = Path(wd) if wd and Path(wd).exists() else None

    def _load(self, name: str) -> dict:
        try:
            return json.loads((self.home / name).read_text())
        except (OSError, ValueError):
            return {}

    # ---------------------------------------------------------------- EZ tools
    @lru_cache(maxsize=None)
    def ez_file(self, name: str, ext: str) -> Path | None:
        """Case-insensitive search for <name>.<ext> in ez_dir (depth <= 2)."""
        target = f"{name}.{ext}".lower()
        if not self.ez_dir.is_dir():
            return None
        for depth_glob in ("*", "*/*"):
            for p in self.ez_dir.glob(depth_glob):
                if p.name.lower() == target and p.is_file():
                    return p
        return None

    def ez_runs_on_windows(self, name: str) -> bool:
        return name.lower() in self.windows_only

    def ez_cmd(self, name: str) -> list[str] | None:
        if self.ez_runs_on_windows(name):
            dll = self.ez_file(name, "dll")
            if dll and self.win_dotnet:  # Windows dotnet.exe (installed or private copy from setup)
                return [str(self.win_dotnet), to_windows_path(dll)]
            exe = self.ez_file(name, "exe")
            return [str(exe)] if exe else None
        dll = self.ez_file(name, "dll")
        return [str(self.dotnet), str(dll)] if dll and self.dotnet.exists() else None

    @lru_cache(maxsize=None)
    def ez_supports(self, name: str, option: str) -> bool:
        """True when the installed tool version lists `option` in its --help (options change between releases)."""
        base = self.ez_cmd(name)
        if not base:
            return False
        r = subprocess.run(base + ["--help"], capture_output=True, text=True, errors="replace",
                           cwd="/tmp", env=self.env())
        return option in (r.stdout + r.stderr)

    @lru_cache(maxsize=None)
    def win_scratch_root(self) -> Path | None:
        """%LOCALAPPDATA%\\Temp\\DFIR-Triage-Agent as a WSL path: Windows-local NTFS for ESE databases
        (ESE recovery/repair fails with JET_errDiskIO on \\\\wsl.localhost paths)."""
        r = subprocess.run(["cmd.exe", "/c", "echo %LOCALAPPDATA%"], capture_output=True, text=True, cwd="/mnt/c")
        la = r.stdout.strip()
        if r.returncode or not la or "%" in la:
            return None
        p = Path(subprocess.run(["wslpath", "-u", la], capture_output=True, text=True).stdout.strip())
        return p / "Temp" / "DFIR-Triage-Agent" if p.is_dir() else None

    def ez_home(self, name: str) -> Path | None:
        f = self.ez_file(name, "dll")
        return f.parent if f else None

    # ---------------------------------------------------------------- others
    @property
    def hayabusa(self) -> Path:
        return self.tools / "hayabusa" / "hayabusa"

    @property
    def chainsaw(self) -> Path:
        return self.tools / "chainsaw" / "chainsaw"

    @property
    def sigma_rules(self) -> Path:
        return self.tools / "sigma" / "rules"

    @property
    def chopchopgo(self) -> Path:
        return self.tools / "chopchopgo" / "ChopChopGo"

    @property
    def chopchopgo_rules(self) -> Path:
        return self.tools / "chopchopgo" / "rules" / "linux" / "builtin"

    @property
    def zircolite(self) -> Path:
        return self.tools / "zircolite" / "Zircolite"

    @property
    def zircolite_rules(self) -> Path:
        return self.tools / "zircolite" / "rules" / "rules_linux.json"

    @property
    def bmc_tools(self) -> Path:
        return self.tools / "bmc-tools" / "bmc-tools.py"

    @property
    def regripper(self) -> Path:
        return self.tools / "regripper" / "rip.pl"

    @property
    def perl5lib(self) -> Path:
        return self.tools / "perl5" / "lib" / "perl5"

    @property
    def mactime(self) -> str | None:
        return shutil.which("mactime")

    @property
    def esentutl(self) -> str | None:
        p = Path("/mnt/c/Windows/System32/esentutl.exe")
        return str(p) if p.exists() else None

    def thor_binary(self) -> Path | None:
        d = self.tools / "thor"
        for n in ("thor-linux-64", "thor-lite-linux-64", "thor64", "thor-lite"):
            if (d / n).is_file():
                return d / n
        return None

    def thor_custom_rules(self) -> list[Path]:
        d = self.tools / "thor" / "custom-signatures" / "yara"
        return [p for p in d.glob("*") if p.suffix.lower() in (".yar", ".yara")] if d.is_dir() else []

    # ---------------------------------------------------------------- env
    def env(self) -> dict:
        e = dict(os.environ)
        e.update({
            "DOTNET_ROOT": str(self.dotnet.parent),
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_gcServer": "0",           # workstation GC keeps parallel tools lean on RAM
            "DOTNET_NOLOGO": "1",
            "PERL5LIB": str(self.perl5lib),
        })
        return e

    # ---------------------------------------------------------------- report
    def check(self) -> list[tuple[str, str, str, str]]:
        """Rows: (tool, status, runtime/location, version)."""
        rows = []
        py = self.setup_env.get("python", "")
        rows.append(("Python environment", "ok" if py else "unknown",
                     f"{self.setup_env.get('python_mode', '?')}: {py}", ""))
        net = self.versions.get("dotnet-runtime", {}).get("version", "")
        rows.append((".NET runtime (WSL)", "ok" if self.dotnet.exists() else "missing", str(self.dotnet), net))
        rows.append((".NET runtime (Windows)", "ok" if self.win_dotnet else "missing",
                     str(self.win_dotnet or "needed for SrumECmd/SumECmd"), ""))
        for n in EZ_TOOLS:
            if self.ez_runs_on_windows(n):
                f = self.ez_file(n, "dll") if self.win_dotnet else self.ez_file(n, "exe")
                rt = "Windows interop"
            else:
                f = self.ez_file(n, "dll")
                rt = "dotnet (Linux)"
            rows.append((n, "ok" if f else "missing", rt, _file_version(f) if f else ""))
        for name, path in (("Hayabusa", self.hayabusa), ("Chainsaw", self.chainsaw),
                           ("Sigma rules", self.sigma_rules), ("ChopChopGo", self.chopchopgo),
                           ("Zircolite", self.zircolite), ("bmc-tools", self.bmc_tools),
                           ("RegRipper", self.regripper)):
            key = name.lower().replace(" rules", "")
            rows.append((name, "ok" if path.exists() else "missing", str(path),
                         self.versions.get(key, {}).get("version", "")))
        for name, mods, use in (("RDP reconstruction", ("numpy", "PIL"), "numpy + Pillow"),
                                ("CPU monitor", ("psutil",), "psutil")):
            miss = [m for m in mods if importlib.util.find_spec(m) is None]
            rows.append((name, "missing" if miss else "ok", use + (" - run ./setup.sh" if miss else ""), ""))
        rows.append(("mactime (sleuthkit)", "ok" if self.mactime else "fallback", self.mactime or
                     "not installed - built-in Python timeline used", ""))
        rows.append(("esentutl (Windows)", "ok" if self.esentutl else "missing", self.esentutl or "", "SRUM/SUM repair"))
        thor = self.thor_binary()
        rows.append(("THOR", "ready" if thor and self.thor_custom_rules() else "disabled",
                     str(thor) if thor else "not installed", f"{len(self.thor_custom_rules())} custom YARA files"))
        return rows


def _file_version(p: Path) -> str:
    """FileVersion from the PE resources of <tool>.dll/.exe (cheap scan, no deps)."""
    try:
        data = p.read_bytes()
    except OSError:
        return ""
    key = "FileVersion".encode("utf-16-le") + b"\x00\x00"
    i = data.find(key)
    while i >= 0:
        # skip e.g. "BinFileVersion" (assembly metadata) - the VERSIONINFO key is not preceded by a letter
        if i < 2 or not chr(data[i - 2]).isalpha():
            j = i + len(key)
            while j < len(data) - 1 and data[j:j + 2] == b"\x00\x00":
                j += 2
            end = data.find(b"\x00\x00", j)
            if end < 0:  # unterminated value at the end of the file
                end = len(data)
            v = data[j:end + 1].decode("utf-16-le", "ignore").strip("\x00 ")
            if v[:1].isdigit():
                return v[:20]
        i = data.find(key, i + 2)
    return ""


def to_windows_path(p: Path | str) -> str:
    """Translate a WSL path for Windows interop tools."""
    r = subprocess.run(["wslpath", "-w", str(p)], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else str(p)
