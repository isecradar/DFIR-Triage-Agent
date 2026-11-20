#!/usr/bin/env python3
"""DFIR Triage Agent - installer / updater (Python standard library only).

Prepares a fresh WSL machine or updates an existing installation:
  * Python environment: reuse the current interpreter when it already has every library,
    otherwise create an isolated venv (pip bootstrapped from bootstrap.pypa.io if Ubuntu lacks ensurepip);
    libraries from requirements.txt (incl. numpy/Pillow for RDP cache reconstruction, psutil for CPU monitoring)
  * .NET 10 runtime for Linux (EZ tools) and for Windows (ESE tools via WSL interop) - SHA-512 verified
  * Eric Zimmerman tools - analyst folder if complete, otherwise downloaded from the official site;
    Authenticode signature (ZimTech LLC) verified for every binary
  * Hayabusa, Chainsaw, Sigma - GitHub release assets, SHA-256 digest verified
  * ChopChopGo, Zircolite (Sigma for Linux collections) - GitHub release assets, SHA-256 digest verified
  * bmc-tools, RegRipper 4.0 - pinned GitHub commits; Parse::Win32Registry - CPAN SHA-256 verified
  * optional system packages (sleuthkit, perl) via apt - always asks first

Usage: ./setup.sh [options]      (or: python3 installer.py [options])
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
UA = f"DFIR-Triage-Agent-setup/1.1 (python {platform.python_version()})"
PY_LIBS = {"rich": "rich", "pyzipper": "pyzipper", "Registry": "python-registry", "yaml": "PyYAML",
           "numpy": "numpy", "PIL": "Pillow", "psutil": "psutil"}  # numpy/Pillow: RDP cache reconstruction
EZ_TOOLS = ["AmcacheParser", "AppCompatCacheParser", "PECmd", "RecentFileCacheParser", "SrumECmd", "SumECmd",
            "LECmd", "JLECmd", "SBECmd", "WxTCmd", "RBCmd", "MFTECmd", "EvtxECmd", "RECmd", "SQLECmd"]
EZ_URL = "https://download.ericzimmermanstools.com/net/{}.zip"
EZ_SIGNER = "ZimTech LLC"
DOTNET_META = "https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json"
CPAN_DIR = "https://cpan.metacpan.org/authors/id/J/JM/JMACFARLA/"
PWR = "Parse-Win32Registry-1.1.tar.gz"


# =============================================================================== console
class C:
    on = sys.stdout.isatty()
    R, B, G, Y, RED, M, D = ("\033[0m", "\033[1;36m", "\033[1;32m", "\033[1;33m", "\033[1;31m", "\033[1;35m", "\033[2m") \
        if on else ("",) * 7


GRADIENT = ["#05B1E8", "#04A0DB", "#028DCE", "#007AC1", "#0462B0", "#0749A0"]  # same gradient as the dashboard


def banner():
    cols = [f"\033[1;38;2;{int(h[1:3], 16)};{int(h[3:5], 16)};{int(h[5:7], 16)}m" for h in GRADIENT] \
        if C.on else [""] * 6
    art = ["██████╗ ███████╗██╗██████╗ ", "██╔══██╗██╔════╝██║██╔══██╗", "██║  ██║█████╗  ██║██████╔╝",
           "██║  ██║██╔══╝  ██║██╔══██╗", "██████╔╝██║     ██║██║  ██║", "╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝"]
    side = ["", f"{cols[0]}T R I A G E   A G E N T{C.R}", f"{C.D}installer / updater{C.R}", "", "", ""]
    for a, c, s in zip(art, cols, side):
        print(f" {c}{a}{C.R}   {s}")
    print()


def step(m): print(f"{C.B}==>{C.R} {C.M}{m}{C.R}")
def ok(m): print(f"    {C.G}[OK]{C.R} {m}")
def info(m): print(f"    {C.D}{m}{C.R}")
def warn(m): print(f"    {C.Y}[WARN]{C.R} {m}")
def fail(m): print(f"    {C.RED}[FAIL]{C.R} {m}")


class SetupError(Exception):
    pass


# =============================================================================== helpers
def run(cmd, **kw) -> subprocess.CompletedProcess:
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    try:
        return subprocess.run(cmd, **kw)
    except (FileNotFoundError, PermissionError, OSError) as e:
        return subprocess.CompletedProcess(cmd, 127, "", str(e))


def http(url: str, dest: Path | None = None, accept: str | None = None):
    headers = {"User-Agent": UA}
    if accept:
        headers["Accept"] = accept
    if "api.github.com" in url and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
                if dest is None:
                    return r.read()
                total = int(r.headers.get("Content-Length") or 0)
                done, t0 = 0, time.monotonic()
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, "wb") as fh:
                    while True:
                        b = r.read(1 << 20)
                        if not b:
                            break
                        fh.write(b)
                        done += len(b)
                        if C.on and total > 5 << 20:
                            print(f"\r    {C.D}downloading {dest.name}: {done * 100 // total:3d}% "
                                  f"({done >> 20}/{total >> 20} MB){C.R}", end="", flush=True)
                if C.on and total > 5 << 20:
                    print("\r" + " " * 90 + "\r", end="")
                return dest
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
            if isinstance(e, urllib.error.HTTPError) and e.code in (401, 403, 404):
                break
            time.sleep(2 * (attempt + 1))
    raise SetupError(f"download failed: {url} ({last})")


def digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def verify(path: Path, expected: str, algo: str = "sha256") -> None:
    if not expected:
        raise SetupError(f"no published {algo} for {path.name} - refusing unverified download")
    got = digest(path, algo)
    if got.lower() != expected.lower():
        path.unlink(missing_ok=True)
        raise SetupError(f"{algo.upper()} mismatch for {path.name}: got {got[:16]}…, expected {expected[:16]}…")
    ok(f"{algo.upper()} verified {path.name} ({got[:16]}…)")


def gh_json(path: str):
    return json.loads(http(f"https://api.github.com/{path}", accept="application/vnd.github+json"))


def gh_asset(repo: str, rx: str) -> tuple[str, str, str]:
    rel = gh_json(f"repos/{repo}/releases/latest")
    for a in rel.get("assets", []):
        if re.search(rx, a["name"]):
            return rel["tag_name"], a["browser_download_url"], (a.get("digest") or "").replace("sha256:", "")
    raise SetupError(f"no asset matching {rx} in {repo} {rel.get('tag_name')}")


def safe_extract_zip(zf: Path, dest: Path, strip_top: bool = False) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(zf) as z:
        for info in z.infolist():
            name = info.filename
            if strip_top:
                name = name.split("/", 1)[1] if "/" in name else ""
            if not name:
                continue
            target = (dest / name).resolve()
            if root not in target.parents and target != root:  # zip-slip guard
                raise SetupError(f"unsafe path in {zf.name}: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as s, open(target, "wb") as d:
                shutil.copyfileobj(s, d)
            mode = (info.external_attr >> 16) & 0o777
            if mode & 0o111:
                target.chmod(0o755)


def safe_extract_tar(tgz: Path, dest: Path) -> None:
    """Extract a downloaded tar archive without path traversal (tar-slip): Python's 'data' filter where
    available (3.12+, backported to 3.8.17+/3.9.17+/3.10.12+/3.11.4+), else an explicit check of every
    member name and link target."""
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz) as t:
        if hasattr(tarfile, "data_filter"):
            try:
                t.extractall(dest, filter="data")
            except tarfile.FilterError as e:
                raise SetupError(f"unsafe member in {tgz.name}: {e}") from e
            return
        root = dest.resolve()
        for m in t.getmembers():
            target = (dest / m.name).resolve()
            link = (target.parent / m.linkname).resolve() if (m.issym() or m.islnk()) else target
            if m.name.startswith("/") or root not in (target, *target.parents) or root not in (link, *link.parents):
                raise SetupError(f"unsafe path in {tgz.name}: {m.name}")
            if m.isdev():
                raise SetupError(f"device file in {tgz.name}: {m.name}")
        t.extractall(dest)


def ask(question: str, default: bool, args) -> bool:
    if args.yes or not sys.stdin.isatty():
        return default
    a = input(f"    {C.Y}?{C.R} {question} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not a else a.startswith("y")


def windows_interop() -> bool:
    return run(["cmd.exe", "/c", "ver"], cwd="/mnt/c" if Path("/mnt/c").is_dir() else None).returncode == 0


def win_cmd(command: str) -> str:
    return run(["cmd.exe", "/c", command], cwd="/mnt/c").stdout.strip()


def wslpath(p: str, to_windows: bool = False) -> str:
    r = run(["wslpath", "-w" if to_windows else "-u", p])
    return r.stdout.strip() if r.returncode == 0 else p


def authenticode(paths: list[Path]) -> dict[str, tuple[str, str]]:
    """Authenticode status + signer subject for each file, via Windows PowerShell (WSL interop)."""
    if not paths:
        return {}
    wins = [wslpath(str(p), to_windows=True) for p in paths]
    arr = ",".join("'" + w.replace("'", "''") + "'" for w in wins)
    ps = (f"$ErrorActionPreference='SilentlyContinue'; foreach($p in @({arr})) {{ $s=Get-AuthenticodeSignature "
          f"-LiteralPath $p; '{{0}}|{{1}}|{{2}}' -f $p,$s.Status,$s.SignerCertificate.Subject }}")
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    r = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc], cwd="/mnt/c")
    res = {}
    for line in r.stdout.splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) == 3:
            res[parts[0].lower()] = (parts[1], parts[2])
    return {str(p): res.get(w.lower(), ("Unknown", "")) for p, w in zip(paths, wins)}


def find_ci(base: Path, name: str, depth: int = 2) -> Path | None:
    name = name.lower()
    pats = ["*", "*/*", "*/*/*"][:depth + 1]
    for g in pats:
        for p in base.glob(g):
            if p.name.lower() == name and p.is_file():
                return p
    return None


def config_ez_dir() -> Path:
    """tools.ez_dir from config.yaml (read without PyYAML)."""
    cfg = HERE / "config.yaml"
    val = "../Eric Zimmerman Tools/net"
    if cfg.is_file():
        m = re.search(r'^\s*ez_dir:\s*["\']?([^"\'#\n]+?)["\']?\s*(#.*)?$', cfg.read_text(encoding="utf-8"), re.M)
        if m:
            val = m.group(1).strip()
    p = Path(os.path.expanduser(val))
    return p if p.is_absolute() else (HERE / p).resolve()


# =============================================================================== installer
class Installer:
    def __init__(self, args):
        self.a = args
        self.home = Path(os.path.expanduser(os.environ.get("DTA_HOME", "~/.dfir-triage-agent")))
        self.tools = self.home / "tools"
        self.dl = self.home / "downloads"
        for d in (self.tools, self.dl):
            d.mkdir(parents=True, exist_ok=True)
        self.vfile = self.home / "versions.json"
        self.efile = self.home / "env.json"
        self.versions = self._load(self.vfile)
        self.env = self._load(self.efile)
        self.facts: dict = {}
        self.problems: list[str] = []

    @staticmethod
    def _load(p: Path) -> dict:
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            return {}

    def record(self, name, version, source, checksum="-"):
        self.versions[name] = {"version": version, "source": source, "checksum": checksum,
                               "installed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    def save(self):
        self.vfile.write_text(json.dumps(self.versions, indent=2))
        self.efile.write_text(json.dumps(self.env, indent=2))

    def guarded(self, name, fn, required=False):
        try:
            fn()
        except SetupError as e:
            fail(str(e))
            self.problems.append(f"{name}: {e}")
            if required:
                raise

    # --------------------------------------------------------------- 1. system check
    def check_system(self):
        step("System check")
        f = self.facts
        f["python"] = sys.version_info >= (3, 8)
        f["ensurepip"] = run([sys.executable, "-c", "import ensurepip, venv"]).returncode == 0
        f["pip"] = run([sys.executable, "-m", "pip", "--version"]).returncode == 0
        f["perl"] = shutil.which("perl") is not None
        f["mactime"] = shutil.which("mactime") is not None
        f["apt"] = shutil.which("apt-get") is not None
        f["sudo"] = shutil.which("sudo") is not None
        f["interop"] = windows_interop()
        f["wsl"] = "microsoft" in platform.release().lower() or Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
        osr = {}
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                k, _, v = line.partition("=")
                osr[k] = v.strip('"')
        except OSError:
            pass
        rows = [
            ("OS", osr.get("PRETTY_NAME", platform.platform()), True),
            ("Python", f"{platform.python_version()} ({sys.executable})", f["python"]),
            ("pip / venv", f"pip={'yes' if f['pip'] else 'no'}  venv={'yes' if f['ensurepip'] else 'no (bootstrap via get-pip)'}", True),
            ("perl (RegRipper)", "yes" if f["perl"] else "missing", f["perl"]),
            ("mactime (sleuthkit)", "yes" if f["mactime"] else "missing (built-in Python fallback used)", True),
            ("WSL / Windows interop", f"wsl={'yes' if f['wsl'] else 'no'}  interop={'yes' if f['interop'] else 'no'}", f["interop"]),
            ("apt / sudo", f"apt={'yes' if f['apt'] else 'no'}  sudo={'yes' if f['sudo'] else 'no'}", True),
            ("Disk free (DTA_HOME)", f"{shutil.disk_usage(self.home).free >> 30} GB", shutil.disk_usage(self.home).free > 5 << 30),
        ]
        for k, v, good in rows:
            print(f"    {(C.G + '✔') if good else (C.Y + '!')}{C.R} {k:<24} {v}")
        if not f["python"]:
            raise SetupError("Python 3.8+ required")
        if not f["interop"]:
            warn("Windows interop unavailable: SrumECmd/SumECmd and EZ signature checks need it "
                 "(enable [interop] in /etc/wsl.conf)")

    # --------------------------------------------------------------- 2. system packages
    def system_packages(self):
        step("Optional system packages")
        want = []
        if not self.facts["mactime"]:
            want.append("sleuthkit")
        if not self.facts["perl"]:
            want.append("perl")
        if not want:
            ok("nothing missing")
            return
        if self.a.no_system_packages or not (self.facts["apt"] and self.facts["sudo"]):
            warn(f"not installing {', '.join(want)} (fallbacks will be used)")
            return
        if not ask(f"Install {', '.join(want)} with 'sudo apt-get install' (asks for your password)?", True, self.a):
            warn("skipped by user - fallbacks will be used")
            return
        r1 = run(["sudo", "apt-get", "update", "-qq"], capture_output=False)
        r2 = run(["sudo", "apt-get", "install", "-y", "-qq", *want], capture_output=False)
        if r1.returncode or r2.returncode:
            warn("apt installation failed - fallbacks will be used")
        else:
            ok(f"installed {', '.join(want)}")
            self.facts["mactime"] = shutil.which("mactime") is not None
            self.facts["perl"] = shutil.which("perl") is not None

    # --------------------------------------------------------------- 3. python env
    def _missing_libs(self, py: str) -> list[str]:
        code = ("import importlib.util,sys;"
                f"print(','.join(m for m in {list(PY_LIBS)!r} if importlib.util.find_spec(m) is None))")
        r = run([py, "-c", code])
        if r.returncode:
            return list(PY_LIBS.values())
        return [PY_LIBS[m] for m in r.stdout.strip().split(",") if m]

    def _get_pip(self, py: str, user: bool):
        gp = self.dl / "get-pip.py"
        http("https://bootstrap.pypa.io/get-pip.py", gp)
        r = run([py, str(gp), "-q"] + (["--user"] if user else []))
        if r.returncode:
            raise SetupError(f"pip bootstrap failed: {r.stderr.strip()[-300:]}")
        ok("pip bootstrapped from bootstrap.pypa.io")

    def _pip_install(self, py: str, user: bool):
        if run([py, "-m", "pip", "--version"]).returncode:
            self._get_pip(py, user)
        cmd = [py, "-m", "pip", "install", "-q", "--upgrade", "-r", str(HERE / "requirements.txt")]
        if user:
            cmd.insert(4, "--user")
        r = run(cmd)
        if r.returncode:
            if "externally-managed" in r.stderr:
                raise SetupError("this Python is 'externally managed' (PEP 668) - use --python venv")
            raise SetupError(f"pip install failed: {r.stderr.strip()[-400:]}")

    def python_env(self):
        step("Python environment")
        mode = self.a.python
        venv_dir = self.home / "venv"
        venv_py = venv_dir / "bin" / "python"
        if mode == "auto":
            if venv_py.exists() and not self._missing_libs(str(venv_py)) and not self.a.force:
                mode = "venv"
            elif not self._missing_libs(sys.executable):
                mode = "current"
                info("all required libraries already present in the current Python - reusing it")
            else:
                mode = "venv"
                info(f"current Python lacks {', '.join(self._missing_libs(sys.executable))} - using an isolated venv")
        if mode == "current":
            py = sys.executable
            if self._missing_libs(py):
                self._pip_install(py, user=True)
        else:
            if self.a.force and venv_dir.exists():
                shutil.rmtree(venv_dir)
            if not venv_py.exists():
                r = run([sys.executable, "-m", "venv", str(venv_dir)])
                if r.returncode:  # Ubuntu without python3-venv: create bare venv + bootstrap pip
                    shutil.rmtree(venv_dir, ignore_errors=True)
                    r = run([sys.executable, "-m", "venv", "--without-pip", str(venv_dir)])
                    if r.returncode:
                        raise SetupError(f"cannot create venv: {r.stderr.strip()[-300:]}")
                    self._get_pip(str(venv_py), user=False)
            py = str(venv_py)
            self._pip_install(py, user=False)
        miss = self._missing_libs(py)
        if miss:
            raise SetupError(f"libraries still missing in {py}: {', '.join(miss)}")
        self.env.update({"python": py, "python_mode": mode})
        libs = run([py, "-c", "import importlib.metadata as m;print(', '.join(f'{p} {m.version(p)}' for p in "
                               f"{list(PY_LIBS.values())!r}))"]).stdout.strip()
        ok(f"{mode} interpreter {py}")
        info(libs)

    # --------------------------------------------------------------- 4/5. .NET
    def _dotnet_release(self) -> tuple[str, dict]:
        meta = json.loads(http(DOTNET_META))
        latest = meta["latest-runtime"]
        rel = next(x for x in meta["releases"] if x.get("runtime", {}).get("version") == latest)
        return latest, {f["name"]: f for f in rel["runtime"]["files"]}

    def dotnet_linux(self):
        step(".NET 10 runtime for Linux (Eric Zimmerman tools)")
        dn = self.tools / "dotnet" / "dotnet"
        latest, files = self._dotnet_release()
        have = run([str(dn), "--list-runtimes"]).stdout if dn.exists() else ""
        if f"Microsoft.NETCore.App {latest}" in have and not self.a.force:
            ok(f".NET {latest} already installed")
        else:
            f = files["dotnet-runtime-linux-x64.tar.gz"]
            tgz = http(f["url"], self.dl / "dotnet-linux.tar.gz")
            verify(tgz, f["hash"], "sha512")
            shutil.rmtree(dn.parent, ignore_errors=True)
            dn.parent.mkdir(parents=True)
            safe_extract_tar(tgz, dn.parent)
            tgz.unlink()
            if f"Microsoft.NETCore.App {latest}" not in run([str(dn), "--list-runtimes"]).stdout:
                raise SetupError(".NET runtime does not start")
            ok(f".NET {latest} installed to {dn.parent}")
        self.env["dotnet"] = str(dn)
        self.record("dotnet-runtime", latest, "builds.dotnet.microsoft.com (release metadata, SHA-512)")

    def dotnet_windows(self):
        step(".NET 10 runtime for Windows (SrumECmd / SumECmd via WSL interop)")
        if not self.facts["interop"]:
            warn("no Windows interop - ESE tools (SRUM, SUM) will be skipped")
            self.env["win_dotnet"] = ""
            return
        latest, files = self._dotnet_release()
        glob_rt = win_cmd("dotnet --list-runtimes 2>nul")
        if re.search(r"Microsoft\.NETCore\.App 10\.", glob_rt):
            exe = win_cmd("where dotnet 2>nul").splitlines()[0]
            self.env["win_dotnet"] = wslpath(exe)
            ok(f"using installed Windows .NET ({re.findall(r'NETCore.App (10[.0-9]+)', glob_rt)[-1]})")
            return
        local = win_cmd("echo %LOCALAPPDATA%")
        target = Path(wslpath(local)) / "DFIR-Triage-Agent" / "dotnet"
        exe = target / "dotnet.exe"
        if exe.exists() and latest in run([str(exe), "--list-runtimes"], cwd="/mnt/c").stdout and not self.a.force:
            ok(f"private Windows .NET {latest} present")
        else:
            info("no Windows .NET 10 found - installing a private copy (no admin rights needed)")
            f = files["dotnet-runtime-win-x64.zip"]
            z = http(f["url"], self.dl / "dotnet-win.zip")
            verify(z, f["hash"], "sha512")
            shutil.rmtree(target, ignore_errors=True)
            safe_extract_zip(z, target)
            z.unlink()
            ok(f"Windows .NET {latest} installed to {local}\\DFIR-Triage-Agent\\dotnet")
        self.env["win_dotnet"] = str(exe)

    # --------------------------------------------------------------- 6. EZ tools
    def _ez_missing(self, d: Path) -> list[str]:
        if not d.is_dir():
            return list(EZ_TOOLS)
        return [t for t in EZ_TOOLS if not find_ci(d, f"{t}.dll")]

    def _ez_verify(self, d: Path, tools: list[str]) -> list[str]:
        """Return tools whose binaries are not validly signed by ZimTech LLC."""
        files = [find_ci(d, f"{t}.dll") for t in tools]
        files = [f for f in files if f]
        res = authenticode(files)
        bad = []
        for f in files:
            status, subject = res.get(str(f), ("Unknown", ""))
            if status != "Valid" or EZ_SIGNER not in subject:
                bad.append(f"{f.stem} ({status} {subject[:40]})")
        return bad

    def ez_tools(self):
        step("Eric Zimmerman tools")
        local = config_ez_dir()
        own = self.tools / "EZ"
        miss_local = self._ez_missing(local)
        if not miss_local and not self.a.update_ez:
            info(f"analyst-provided folder: {local}")
            if self.facts["interop"]:
                bad = self._ez_verify(local, EZ_TOOLS)
                if bad:
                    raise SetupError("signature check failed: " + ", ".join(bad))
                ok(f"all {len(EZ_TOOLS)} tools present, Authenticode signed by {EZ_SIGNER}")
            else:
                warn("cannot verify signatures without Windows interop - trusting analyst folder")
            self.env["ez_dir"] = str(local)
            self.record("ez-tools", "analyst-provided", str(local))
            return
        if miss_local and local.is_dir():
            warn(f"analyst folder {local} incomplete (missing: {', '.join(miss_local)})")
        need = EZ_TOOLS if self.a.update_ez else self._ez_missing(own)
        if need:
            if not self.facts["interop"] and not self.a.allow_unverified:
                raise SetupError("EZ download needs Windows interop for signature verification "
                                 "(or pass --allow-unverified)")
            info(f"downloading {len(need)} tool(s) from download.ericzimmermanstools.com")
            for t in need:
                z = http(EZ_URL.format(t), self.dl / f"{t}.zip")
                staging = self.dl / f"ez_{t}"
                shutil.rmtree(staging, ignore_errors=True)
                safe_extract_zip(z, staging)
                if self.facts["interop"]:
                    bad = self._ez_verify(staging, [t])
                    if bad:
                        shutil.rmtree(staging, ignore_errors=True)
                        raise SetupError(f"{t}: signature check failed ({', '.join(bad)}) - not installed")
                for item in staging.iterdir():  # merge into tools/EZ (some zips have a sub-folder)
                    dst = own / item.name
                    if dst.exists():
                        shutil.rmtree(dst) if dst.is_dir() else dst.unlink()
                    own.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(item), dst)
                shutil.rmtree(staging, ignore_errors=True)
                z.unlink()
                ok(f"{t} installed" + (" (signature: ZimTech LLC, Valid)" if self.facts["interop"] else " (UNVERIFIED)"))
        else:
            ok(f"all tools already present in {own}")
        self.env["ez_dir"] = str(own)
        self.record("ez-tools", time.strftime("%Y-%m"), "https://download.ericzimmermanstools.com/net/",
                    "Authenticode: ZimTech LLC")

    # --------------------------------------------------------------- 7. GitHub release tools
    def hayabusa(self):
        step("Hayabusa (Yamato-Security)")
        tag, url, sha = gh_asset("Yamato-Security/hayabusa", r"^hayabusa-[0-9.]+-lin-x64-musl\.zip$")
        d = self.tools / "hayabusa"
        cur = (d / ".tag").read_text().strip() if (d / ".tag").exists() else ""
        if cur != tag or self.a.force or run([str(d / "hayabusa"), "help"]).returncode:
            z = http(url, self.dl / "hayabusa.zip")
            verify(z, sha)
            shutil.rmtree(d, ignore_errors=True)
            safe_extract_zip(z, d)
            binp = next(p for p in d.iterdir() if p.name.startswith("hayabusa-") and p.name.endswith("lin-x64-musl"))
            binp.rename(d / "hayabusa")
            (d / "hayabusa").chmod(0o755)
            (d / ".tag").write_text(tag)
            z.unlink()
        r = run([str(d / "hayabusa"), "update-rules", "-q"], cwd=d)
        ok(f"Hayabusa {tag}" + (", rules updated" if r.returncode == 0 else " (rule update failed - bundled rules)"))
        self.record("hayabusa", tag, url, sha)

    def chainsaw(self):
        step("Chainsaw (WithSecureOpenSource) + SigmaHQ rules")
        tag, url, sha = gh_asset("WithSecureOpenSource/chainsaw", r"^chainsaw_all_platforms\+rules\.zip$")
        d = self.tools / "chainsaw"
        cur = (d / ".tag").read_text().strip() if (d / ".tag").exists() else ""
        if cur != tag or self.a.force or not (d / "chainsaw").exists():
            z = http(url, self.dl / "chainsaw.zip")
            verify(z, sha)
            x = self.dl / "chainsaw_x"
            shutil.rmtree(x, ignore_errors=True)
            safe_extract_zip(z, x)
            binp = next(x.rglob("chainsaw_x86_64-unknown-linux-gnu"))
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir(parents=True)
            shutil.copy2(binp, d / "chainsaw")
            (d / "chainsaw").chmod(0o755)
            for sub in ("rules", "mappings"):
                shutil.copytree(binp.parent / sub, d / sub)
            (d / ".tag").write_text(tag)
            shutil.rmtree(x, ignore_errors=True)
            z.unlink()
        if run([str(d / "chainsaw"), "--version"]).returncode:
            warn("chainsaw binary does not start on this system (glibc too old?)")
        ok(f"Chainsaw {tag}")
        self.record("chainsaw", tag, url, sha)
        tag, url, sha = gh_asset("SigmaHQ/sigma", r"^sigma_core\.zip$")
        d = self.tools / "sigma"
        cur = (d / ".tag").read_text().strip() if (d / ".tag").exists() else ""
        if cur != tag or self.a.force or not (d / "rules").is_dir():
            z = http(url, self.dl / "sigma_core.zip")
            verify(z, sha)
            shutil.rmtree(d, ignore_errors=True)
            safe_extract_zip(z, d)
            (d / ".tag").write_text(tag)
            z.unlink()
        ok(f"Sigma rules {tag}")
        self.record("sigma", tag, url, sha)

    # Linux counterparts of Hayabusa/Chainsaw: Sigma hunting on UAC / Linux collections
    def chopchopgo(self):
        step("ChopChopGo (M00NLIG7) - Sigma for Linux syslog / journald")
        tag, url, sha = gh_asset("M00NLIG7/ChopChopGo", r"^ChopChopGo-v?[0-9.]+-linux-amd64\.zip$")
        d = self.tools / "chopchopgo"
        cur = (d / ".tag").read_text().strip() if (d / ".tag").exists() else ""
        if cur != tag or self.a.force or not (d / "ChopChopGo").exists():
            z = http(url, self.dl / "chopchopgo.zip")
            verify(z, sha)
            shutil.rmtree(d, ignore_errors=True)
            safe_extract_zip(z, d)
            (d / "ChopChopGo").chmod(0o755)
            (d / ".tag").write_text(tag)
            z.unlink()
        if run([str(d / "ChopChopGo"), "-h"], cwd=d).returncode not in (0, 2):  # Go flag: -h exits 0 or 2
            warn("ChopChopGo binary does not start on this system")
        n = sum(1 for _ in (d / "rules" / "linux" / "builtin").rglob("*.yml"))
        ok(f"ChopChopGo {tag} ({n} bundled syslog/journald Sigma rules)")
        self.record("chopchopgo", tag, url, sha)

    def zircolite(self):
        step("Zircolite (wagga40) - Sigma for auditd / Sysmon for Linux")
        tag, url, sha = gh_asset("wagga40/Zircolite", r"^Zircolite-[0-9.]+-linux-x64\.zip$")
        d = self.tools / "zircolite"
        cur = (d / ".tag").read_text().strip() if (d / ".tag").exists() else ""
        if cur != tag or self.a.force or not (d / "Zircolite").exists():
            z = http(url, self.dl / "zircolite.zip")
            verify(z, sha)
            shutil.rmtree(d, ignore_errors=True)
            safe_extract_zip(z, d, strip_top=True)  # Zircolite-<ver>-linux-x64/... (self-contained build)
            (d / "Zircolite").chmod(0o755)
            (d / ".tag").write_text(tag)
            z.unlink()
        if run([str(d / "Zircolite"), "-h"], cwd=d).returncode:
            warn("Zircolite binary does not start on this system (glibc too old?)")
        rules = d / "rules" / "rules_linux.json"
        ok(f"Zircolite {tag}" + ("" if rules.is_file() else " - rules_linux.json missing"))
        self.record("zircolite", tag, url, sha)

    # --------------------------------------------------------------- 8. GitHub source tools
    def _gh_source(self, repo: str, dest: Path) -> str:
        info_ = gh_json(f"repos/{repo}")
        sha = gh_json(f"repos/{repo}/commits/{info_['default_branch']}")["sha"]
        cur = (dest / ".commit").read_text().strip() if (dest / ".commit").exists() else ""
        if cur != sha or self.a.force:
            z = http(f"https://codeload.github.com/{repo}/zip/{sha}", self.dl / f"{dest.name}.zip")
            shutil.rmtree(dest, ignore_errors=True)
            safe_extract_zip(z, dest, strip_top=True)
            (dest / ".commit").write_text(sha)
            z.unlink()
        return sha

    def bmc_tools(self):
        step("bmc-tools (ANSSI-FR) - RDP bitmap cache")
        sha = self._gh_source("ANSSI-FR/bmc-tools", self.tools / "bmc-tools")
        ok(f"bmc-tools commit {sha[:12]}")
        self.record("bmc-tools", f"git:{sha}", "https://github.com/ANSSI-FR/bmc-tools")

    def regripper(self):
        repo = "keydet89/RegRipper4.0" if self.a.regripper == "4" else "keydet89/RegRipper3.0"
        step(f"RegRipper {self.a.regripper}.0 (keydet89) + Parse::Win32Registry")
        if not self.facts["perl"]:
            warn("perl missing - RegRipper skipped")
            return
        rr = self.tools / "regripper"
        if (rr / ".commit").exists() and (rr / ".repo").exists() and (rr / ".repo").read_text() != repo:
            shutil.rmtree(rr)  # switching major version
        sha = self._gh_source(repo, rr)
        (rr / ".repo").write_text(repo)
        lib = self.tools / "perl5" / "lib" / "perl5"
        if not (lib / "Parse" / "Win32Registry.pm").exists() or self.a.force:
            sums = http(CPAN_DIR + "CHECKSUMS").decode()
            m = re.search(re.escape(f"'{PWR}'") + r".*?'sha256' => '([0-9a-f]{64})'", sums, re.S)
            tgz = http(CPAN_DIR + PWR, self.dl / PWR)
            verify(tgz, m.group(1) if m else "")
            x = self.dl / "pwr_x"
            shutil.rmtree(x, ignore_errors=True)
            safe_extract_tar(tgz, x)
            src = next(x.glob("Parse-Win32Registry-*")) / "lib"
            lib.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, lib, dirs_exist_ok=True)
            shutil.rmtree(x, ignore_errors=True)
            tgz.unlink()
        # keydet89's patched Win32Registry modules (newer hive handling) shipped with RegRipper 3.0
        rr3 = gh_json("repos/keydet89/RegRipper3.0/commits/master")["sha"]
        for f in ("Base.pm", "File.pm"):
            data = http(f"https://raw.githubusercontent.com/keydet89/RegRipper3.0/{rr3}/{f}")
            (lib / "Parse" / "Win32Registry" / "WinNT" / f).write_bytes(data)
        out = run(["perl", str(rr / "rip.pl"), "-l"], env={**os.environ, "PERL5LIB": str(lib)}).stdout
        n = len(re.findall(r"^\d+\.\s", out, re.M))
        if "usbstor" not in out:
            raise SetupError("RegRipper does not run on this system")
        ok(f"RegRipper {self.a.regripper}.0 commit {sha[:12]} ({n} plugins)")
        self.record("regripper", f"{self.a.regripper}.0 git:{sha}", f"https://github.com/{repo}")

    def thor(self):
        step("THOR (optional, disabled until extended YARA rules are added)")
        d = self.tools / "thor" / "custom-signatures" / "yara"
        d.mkdir(parents=True, exist_ok=True)
        readme = self.tools / "thor" / "README.txt"
        if not readme.exists():
            readme.write_text(
                "THOR is optional and disabled.\n"
                "1. Download THOR / THOR Lite for Linux from https://www.nextron-systems.com and extract it here\n"
                "   (binary: thor-lite-linux-64 or thor-linux-64).\n"
                "2. Put EXTENDED YARA rules in custom-signatures/yara/ (*.yar, *.yara).\n"
                "3. Set modules.thor.enabled: true in config.yaml.\n"
                "Built-in signatures alone are never used - the module skips itself.\n")
        ok(f"placeholder ready at {self.tools / 'thor'}")

    def command_link(self) -> bool:
        """Link the launcher into ~/.local/bin so `dfir-triage` runs from any folder."""
        step("Command 'dfir-triage' on PATH")
        bindir = Path("~/.local/bin").expanduser()
        link, target = bindir / "dfir-triage", HERE / "dfir-triage"
        if link.exists() and not link.is_symlink():
            warn(f"{link} exists and is not a link - left untouched")
            return False
        bindir.mkdir(parents=True, exist_ok=True)
        link.unlink(missing_ok=True)
        link.symlink_to(target)
        ok(f"{link} -> {target}")
        if str(bindir) in os.environ.get("PATH", "").split(":"):
            return True
        # Ubuntu's ~/.profile adds ~/.local/bin at login once it exists; otherwise add it via ~/.bashrc
        profile, bashrc = Path("~/.profile").expanduser(), Path("~/.bashrc").expanduser()
        covered = any(".local/bin" in f.read_text(errors="ignore") for f in (profile, bashrc) if f.is_file())
        if not covered:
            with bashrc.open("a") as f:
                f.write('\n# DFIR Triage Agent\nexport PATH="$HOME/.local/bin:$PATH"\n')
            info(f"added ~/.local/bin to PATH in {bashrc}")
        info("open a new WSL terminal (or run: source ~/.profile) to use 'dfir-triage' from any folder")
        return True

    # --------------------------------------------------------------- run
    def run_all(self):
        banner()
        self.check_system()
        self.system_packages()
        self.guarded("python", self.python_env, required=True)
        self.save()
        self.guarded("dotnet-linux", self.dotnet_linux, required=True)
        self.guarded("dotnet-windows", self.dotnet_windows)
        self.guarded("ez-tools", self.ez_tools)
        self.guarded("hayabusa", self.hayabusa)
        self.guarded("chainsaw", self.chainsaw)
        self.guarded("chopchopgo", self.chopchopgo)
        self.guarded("zircolite", self.zircolite)
        self.guarded("bmc-tools", self.bmc_tools)
        if not self.a.skip_regripper:
            self.guarded("regripper", self.regripper)
        self.thor()
        self.env["mactime"] = shutil.which("mactime") or ""
        self.env["installed"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.save()
        launcher = HERE / "dfir-triage"
        if launcher.exists():
            launcher.chmod(0o755)
        linked = not self.a.no_link and launcher.exists() and self.command_link()
        step("Tool status")
        subprocess.run([self.env["python"], str(HERE / "dfir-triage.py"), "--check-tools"])
        print()
        if self.problems:
            print(f"{C.Y}Setup finished with {len(self.problems)} problem(s):{C.R}")
            for p in self.problems:
                print(f"   - {p}")
            print(f"{C.D}Affected modules are skipped at run time; re-run ./setup.sh after fixing.{C.R}")
        else:
            print(f"{C.G}Setup complete.{C.R}")
        cmd = "dfir-triage" if linked else HERE / "dfir-triage"
        print(f"Run:  {C.B}{cmd} -i <collection.zip|folder> -o <output>{C.R}")
        return 1 if self.problems else 0


def main():
    p = argparse.ArgumentParser(description="DFIR Triage Agent installer / updater")
    p.add_argument("--python", choices=["auto", "venv", "current"], default="auto",
                   help="auto (default): reuse the current Python if it already has all libraries, else create a "
                        "venv | venv: always isolated venv | current: install missing libraries for this Python")
    p.add_argument("--force", action="store_true", help="reinstall everything")
    p.add_argument("--update-ez", action="store_true",
                   help="download the latest EZ tools into ~/.dfir-triage-agent/tools/EZ (signature verified)")
    p.add_argument("--allow-unverified", action="store_true", help="allow EZ download without signature check")
    p.add_argument("--regripper", choices=["4", "3"], default="4", help="RegRipper major version (default 4)")
    p.add_argument("--skip-regripper", action="store_true")
    p.add_argument("--no-system-packages", action="store_true", help="never call apt/sudo")
    p.add_argument("--no-link", action="store_true", help="do not link 'dfir-triage' into ~/.local/bin")
    p.add_argument("-y", "--yes", action="store_true", help="non-interactive: accept defaults")
    a = p.parse_args()
    sys.stdout.reconfigure(line_buffering=True)  # keep order with sub-process output when piped/logged
    try:
        return Installer(a).run_all()
    except SetupError as e:
        fail(str(e))
        return 2
    except KeyboardInterrupt:
        print("\naborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
