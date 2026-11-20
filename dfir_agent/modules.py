"""Processing modules: builds the task graph for one collection."""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import postproc, sysinfo
from .collection import IN_PLACE, Extractor, find_ci
from .config import module_enabled, module_opt
from .engine import Job, SkipTask, Task, TaskWarning
from .tools import to_windows_path

AV_NOTE = "AV scanning is not supported in this environment (removed)"


# =============================================================================== helpers
def _arg(job: Job, tool: str, a) -> str:
    if isinstance(a, Path):
        return to_windows_path(a) if job.tb.ez_runs_on_windows(tool) else str(a)
    return str(a)


def ez(job: Job, task: Task, tool: str, args: list, log_name: str | None = None, **kw):
    base = job.tb.ez_cmd(tool)
    if not base:
        raise SkipTask(f"{tool} not found in EZ tools folder ({job.tb.ez_dir})")
    cwd = job.tb.ez_home(tool) if not job.tb.ez_runs_on_windows(tool) else Path("/tmp")
    return job.run(task, base + [_arg(job, tool, a) for a in args], cwd=cwd, log_name=log_name, **kw)


_INDEX: dict[Path, list[tuple[str, Path]]] = {}
_INDEX_LOCK = threading.Lock()


def file_index(base: Path) -> list[tuple[str, Path]]:
    """(relative posix path, path) for every file under base - walked once, then cached.

    Many modules search the evidence tree; walking it repeatedly is slow on /mnt (9P)."""
    with _INDEX_LOCK:
        if base not in _INDEX:
            parent = next((k for k in _INDEX if k in base.parents), None)
            if parent is not None:  # derive a drive index from the collection-root index
                pre = base.relative_to(parent).as_posix() + "/"
                _INDEX[base] = [(r[len(pre):], p) for r, p in _INDEX[parent] if r.startswith(pre)]
            else:
                items = []
                for root, _, files in os.walk(base):
                    for f in files:
                        p = Path(root) / f
                        items.append((p.relative_to(base).as_posix(), p))
                _INDEX[base] = sorted(items)
        return _INDEX[base]


def forget_index(base: Path) -> None:
    """Drop the cached index of base and of every folder below it (a finished job's evidence tree)."""
    with _INDEX_LOCK:
        for k in [k for k in _INDEX if k == base or base in k.parents]:
            del _INDEX[k]


def rglob_ci(base: Path, pattern: str) -> list[Path]:
    """Recursive regex search on base-relative posix paths (case-insensitive)."""
    rx = re.compile(pattern, re.I)
    if not base or not base.exists():
        return []
    return [p for rel, p in file_index(base) if rx.search(rel)]


def _user_of(p: Path) -> str:
    parts = p.parts
    for i, x in enumerate(parts):
        if x.lower() == "users" and i + 1 < len(parts):
            return parts[i + 1]
    return "unknown"


def _rows(p: Path) -> str:
    return f"{postproc.count_rows(p):,} rows" if p.exists() else ""


def _drive_tag(job: Job, letter: str) -> str:
    """'' for the system drive (keeps the established file names), else '_<letter>' (e.g. '_VSS1', '_D')."""
    return "" if letter == job.layout.system_drive else f"_{letter}"


def _snapshot(d: Path) -> set[Path]:
    return set(d.iterdir()) if d.exists() else set()


def _stage(job: Job, key: str) -> Path:
    """Private, empty output folder for one tool run.

    Category folders are shared by tasks running in parallel; diffing a shared folder (before/after
    snapshots) would pick up - and rename - files another tool is writing at the same time."""
    d = job.work / "_staging" / key
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    return d


def _publish(job: Job, stage: Path, out: Path, stem: str) -> list[Path]:
    """Normalise the names of a staged tool run and move its files into the category folder."""
    moved = []
    for f in job.tidy_outputs(stage, stem):
        dst = out / f.name
        i = 1
        while dst.exists():
            i += 1
            dst = out / f"{f.stem}_{i}{f.suffix}"
        shutil.move(str(f), dst)
        moved.append(dst)
    shutil.rmtree(stage, ignore_errors=True)
    return moved


# =============================================================================== extraction
def build_extract(job: Job) -> None:
    def act(j: Job, t: Task):
        j.stage = "Extracting"
        if j.item.kind in IN_PLACE:
            t.detail = "processing folder in place"

        def prog(done, total, msg):
            t.progress = done / total if total else None
            t.detail = msg
        ex = Extractor(j.item, j.work, hash_files=j.cfg["general"].get("hash_extracted", True),
                       max_sparse_expand=int(j.cfg["general"].get("max_sparse_expand_gb", 8)) * 1024 ** 3,
                       progress=prog, log=lambda m: j.log(f"[extract] {m}"))
        j.layout = ex.run()
        if not j.layout.drives:
            raise RuntimeError("no drive folders found in collection")
        t.detail = "indexing extracted files"
        file_index(j.layout.files)
        j.stage = "Processing"
        if j.layout.os == "linux":
            from . import linux
            if j.layout.uac:
                file_index(j.layout.uac)
            linux.build_processing(j)
            n = len(file_index(j.layout.rootfs))
            return (f"Linux/Unix root file system, {n:,} files" + (" + UAC output" if j.layout.uac else "")
                    + (f", {len(j.layout.symlinks):,} symlinks recorded" if j.layout.symlinks else ""))
        build_processing(j)
        drives = ", ".join(f"{k}:" for k in j.layout.drives)
        return f"drives {drives}; {len(j.layout.sparse_rebuilt)} sparse files rebuilt"
    label = {"velo_zip": "Decrypt & extract collection", "velo_dir": "Normalise collection folder",
             "kape_dir": "Index KAPE folder", "uac_tar": "Extract UAC collection",
             "uac_zip": "Decrypt & extract UAC collection", "uac_dir": "Index UAC folder"}[job.item.kind]
    tool = "UAC" if job.item.kind.startswith("uac") else "Velociraptor"
    job.add(Task("extract", label, tool, "info", act, pool="extract"))


# =============================================================================== processing graph
def build_processing(job: Job) -> None:
    cfg, L, sysd = job.cfg, job.layout, job.sysdrive
    tasks: list[Task] = []

    def T(key, name, tool, cat, fn, deps=None, pool="normal", soft=False, module=None):
        if module and not module_enabled(cfg, module):
            return
        tasks.append(Task(key, name, tool, cat, fn, deps or [], pool, soft))

    T("sysinfo", "System information", "python-registry", "info", task_sysinfo)
    T("inventory", "Artifact inventory & collection gaps", "python", "info", task_inventory,
      deps=["sysinfo"], soft=True)
    # ---- Evidence of execution
    T("amcache", "Amcache", "AmcacheParser", "exec", task_amcache, module="amcache")
    T("shimcache", "ShimCache (AppCompatCache)", "AppCompatCacheParser", "exec", task_shimcache, module="shimcache")
    T("prefetch", "Prefetch", "PECmd", "exec", task_prefetch, module="prefetch")
    T("recentfilecache", "RecentFileCache.bcf", "RecentFileCacheParser", "exec", task_rfc, module="recentfilecache")
    T("srum", "SRUM", "SrumECmd", "exec", task_srum, module="srum")
    T("sum", "User Access Logging (SUM, servers)", "SumECmd", "network", task_sum, module="sum")
    # ---- Registry
    T("recmd", "Registry batch (all hives)", "RECmd", "registry", task_recmd, module="recmd")
    T("registry_route", "Registry -> artifact categories", "python", "registry", task_registry_route,
      deps=["recmd"], module="recmd")
    T("regripper", "RegRipper (all hives)", "RegRipper", "registry", task_regripper, module="regripper")
    # ---- File / folder opening
    T("lnk", "LNK files", "LECmd", "fileopen", task_lnk, module="lnk")
    T("jumplists", "Jump Lists", "JLECmd", "fileopen", task_jumplists, module="jumplists")
    T("shellbags", "ShellBags", "SBECmd", "fileopen", task_shellbags, module="shellbags")
    T("activities", "Windows Timeline (ActivitiesCache)", "WxTCmd", "fileopen", task_activities, module="activities")
    # ---- Deleted files
    T("recyclebin", "Recycle Bin ($I)", "RBCmd", "deleted", task_recyclebin, module="recyclebin")
    # ---- File system (per volume)
    if module_enabled(cfg, "filesystem"):
        for letter, d in L.drives.items():
            mft = find_ci(d, "$MFT")
            if not mft:
                continue
            lk = letter.lower()
            T(f"mft_{lk}", f"$MFT -> CSV ({letter}:)", "MFTECmd", "fs", _mft_csv(letter, mft), pool="heavy")
            if module_enabled(cfg, "fs_timeline"):
                T(f"body_{lk}", f"$MFT -> bodyfile ({letter}:)", "MFTECmd", "fs", _mft_body(letter, mft), pool="heavy")
                T(f"tl_{lk}", f"File system timeline ({letter}:)", "mactime", "fs", _mactime(letter),
                  deps=[f"body_{lk}"], pool="heavy")
            j = find_ci(d, "$Extend/$UsnJrnl_$J")
            if j:
                T(f"usn_{lk}", f"$UsnJrnl:$J ({letter}:)", "MFTECmd", "fs", _usn(letter, j, mft), pool="heavy")
            T(f"ntfs_{lk}", f"$LogFile / $SDS / $Boot ({letter}:)", "MFTECmd", "fs", _ntfs_meta(letter, d))
    # ---- Event logs
    T("evtxecmd", "Event logs -> CSV (all)", "EvtxECmd", "evtx", task_evtxecmd, pool="heavy", module="evtx")
    T("evtx_route", "Event logs -> artifact categories", "python", "evtx", task_evtx_route,
      deps=["evtxecmd"], module="evtx")
    T("hayabusa", "Hayabusa DFIR timeline", "Hayabusa", "hunt", task_hayabusa, pool="heavy", module="hayabusa")
    T("hayabusa_logons", "Hayabusa logon summary", "Hayabusa", "account", task_hayabusa_logons, module="hayabusa")
    T("chainsaw", "Chainsaw Sigma hunt", "Chainsaw", "hunt", task_chainsaw, pool="heavy", module="chainsaw")
    # ---- Browser / apps
    T("sqlecmd", "SQLite databases (browsers & apps)", "SQLECmd", "browser", task_sqlecmd, module="sqlecmd")
    # ---- Remote access, persistence, devices, live response
    T("rdpcache", "RDP bitmap cache", "bmc-tools", "remote", task_rdpcache, module="rdpcache")
    if module_enabled(cfg, "rdpcache"):
        T("rdp_reconstruct", "RDP cache image reconstruction", "python (numpy)", "remote", task_rdp_reconstruct,
          deps=["rdpcache"], pool="heavy", module="rdp_reconstruct")
    T("schtasks", "Scheduled tasks (XML)", "python", "persist", task_schtasks, module="schtasks")
    T("setupapi", "USB / device installs (setupapi)", "python", "usb", task_setupapi, module="setupapi")
    T("rawcopy", "Raw text artifacts (PS history, RAT & Defender logs)", "python", "remote", task_rawcopy,
      module="rawcopy")
    T("velociraptor", "Velociraptor live response results", "python", "live", task_velociraptor,
      module="velociraptor")
    T("thor", "THOR scan (custom YARA)", "THOR", "hunt", task_thor, pool="heavy")
    # ---- Correlation + report
    T("exec_timeline", "Program execution timeline", "python", "exec", task_exec_timeline,
      deps=["amcache", "shimcache", "prefetch", "srum", "registry_route", "evtx_route"], soft=True)
    keys = [t.key for t in tasks]
    T("summary", "Processing summary report", "python", "info", task_summary, deps=keys, soft=True)
    job.add(*tasks)


# =============================================================================== info
def task_sysinfo(job: Job, t: Task):
    sd = job.sysdrive
    system = find_ci(sd, "Windows/System32/config/SYSTEM") if sd else None
    software = find_ci(sd, "Windows/System32/config/SOFTWARE") if sd else None
    if not system and not software:
        raise SkipTask("no SYSTEM/SOFTWARE hive in collection")
    info = sysinfo.collect(system, software)
    job.sysinfo = info
    extra = {"Source": str(job.item.path), "Collection type": job.item.kind,
             "Hostname (from file name)": job.item.host, "Collected at": job.item.stamp,
             "Volumes": ", ".join(f"{k}:" for k in job.layout.drives)}
    if job.layout.velo_meta:
        vinfo, _ = postproc.velociraptor_meta(job.layout.velo_meta)
        extra.update(vinfo)
    d = job.cat_dir("info")
    (d / job.name("System_Info", "txt")).write_text(sysinfo.render_text(info, extra), encoding="utf-8")
    (d / job.name("System_Info", "json")).write_text(json.dumps({**info, "collection": extra}, indent=2, default=str))
    if info.get("ComputerName") and info["ComputerName"].upper() != job.host.upper():
        job.log(f"hostname in registry ({info['ComputerName']}) differs from collection name ({job.host})", "warn", True)
    return f"{info.get('ComputerName', '?')} | {info.get('ProductName', '?')} {info.get('DisplayVersion', '')} " \
           f"build {info.get('Build', '?')} | {info.get('TimeZone', '')}"


def task_inventory(job: Job, t: Task):
    rows, gaps = postproc.inventory(job, file_index)
    notes = []
    if job.layout.velo_meta:
        _, notes = postproc.velociraptor_meta(job.layout.velo_meta)
    d = job.cat_dir("info")
    import csv
    with open(d / job.name("Artifact_Inventory"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Artifact", "Category", "FilesFound", "PerVolume", "NoteIfMissing"])
        w.writerows(rows)
    txt = ["COLLECTION GAP REPORT", "=" * 60, ""] + (gaps or ["No gaps detected for tracked artifacts."]) \
        + ["", "COLLECTOR LOG NOTES", "-" * 60] + (notes or ["none"])
    if job.layout.sparse_rebuilt:
        txt += ["", "SPARSE FILES REBUILT FROM VELOCIRAPTOR .idx (original layout restored)", "-" * 60] \
            + job.layout.sparse_rebuilt
    (d / job.name("Collection_Gaps", "txt")).write_text("\n".join(txt) + "\n", encoding="utf-8")
    missing = sum(1 for g in gaps if g.startswith("[MISSING]"))
    return f"{sum(1 for r in rows if r[2])}/{len(rows)} artifact types present, {missing} gaps"


# =============================================================================== execution
def task_amcache(job: Job, t: Task):
    hives = [h for d in job.layout.drives.values() for h in
             rglob_ci(d, r"^(Windows|Windows\.old/Windows)/AppCompat/Programs/Amcache\.hve$")]
    if not hives:
        raise SkipTask("Amcache.hve not collected")
    out = job.cat_dir("exec")
    for i, h in enumerate(hives):
        stage = _stage(job, f"amcache_{i}")
        ez(job, t, "AmcacheParser", ["-f", h, "-i", "--csv", stage, "--csvf", job.name("Amcache" if not i else f"Amcache_{i}")])
        _publish(job, stage, out, "Amcache")
    return f"{len(hives)} hive(s)"


def task_shimcache(job: Job, t: Task):
    hives = [(letter, h) for letter, d in job.layout.drives.items()
             for h in rglob_ci(d, r"^Windows/System32/config/(RegBack/)?SYSTEM$")]
    if not hives:
        raise SkipTask("SYSTEM hive not collected")
    out = job.cat_dir("exec")
    for letter, h in hives:
        tag = "AppCompatCache_RegBack" if "regback" in h.as_posix().lower() else "AppCompatCache"
        tag += _drive_tag(job, letter)  # VSS copies must not overwrite the live volume's output
        ez(job, t, "AppCompatCacheParser", ["-f", h, "--csv", out, "--csvf", job.name(tag)])
    return _rows(out / job.name("AppCompatCache"))


def task_prefetch(job: Job, t: Task):
    pf_dir = find_ci(job.sysdrive, "Windows/Prefetch") if job.sysdrive else None
    # one suffix test, not '*.pf' + '*.PF' globs: on case-insensitive mounts both globs match every file
    pfs = [p for p in pf_dir.iterdir() if p.is_file() and p.suffix.lower() == ".pf"] if pf_dir else []
    if not pfs:
        raise SkipTask("no Prefetch files collected")
    out = job.cat_dir("exec")
    ez(job, t, "PECmd", ["-d", pf_dir, "--csv", out, "--csvf", job.name("Prefetch")],
       progress_rx=r"^Processing\s", total=len(pfs))
    return f"{len(pfs)} .pf files, {_rows(out / job.name('Prefetch_Timeline'))} run times"


def task_rfc(job: Job, t: Task):
    f = find_ci(job.sysdrive, "Windows/AppCompat/Programs/RecentFileCache.bcf") if job.sysdrive else None
    if not f:
        raise SkipTask("RecentFileCache.bcf not present (Windows 8+)")
    ez(job, t, "RecentFileCacheParser", ["-f", f, "--csv", job.cat_dir("exec"), "--csvf", job.name("RecentFileCache")])


_ESE_FAILED = re.compile(r"error processing|can't be opened|could not repair", re.I)


def _ese_scratch(job: Job, name: str) -> Path:
    """Windows-local scratch folder for ESE databases (repair fails on \\\\wsl.localhost paths)."""
    root = job.tb.win_scratch_root()
    d = (root / job.item.label / name) if root else (job.work / "_ese" / name)
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ese_run(job: Job, t: Task, tool: str, args: list, log: str) -> bool:
    """Run an ESE parser with a Windows-local --temp (newer EZ builds repair dirty databases there).
    Returns False when the tool reported that it could not open the database (it still exits 0)."""
    scratch = None
    if job.tb.ez_supports(tool, "--temp"):
        scratch = _ese_scratch(job, f"{tool}_temp")
        args = args + ["--temp", scratch]
    try:
        _, tail = ez(job, t, tool, args, log_name=log)
    finally:
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)
    return not any(_ESE_FAILED.search(l) for l in tail)


def _ese_repair_copy(job: Job, t: Task, src_dir: Path, base: str, log: str) -> Path:
    """Copy an ESE folder to Windows-local NTFS, replay logs (esentutl /r) and repair (/p) the copy."""
    if not job.tb.esentutl:
        raise RuntimeError("database is dirty and esentutl.exe is not reachable (Windows interop)")
    t.detail = "repairing a copy with esentutl (Windows-local scratch)"
    rep = _ese_scratch(job, f"{log}_repair")
    for f in src_dir.iterdir():
        if f.is_file():
            shutil.copy2(f, rep / f.name)
    w = to_windows_path(rep)
    job.run(t, [job.tb.esentutl, "/r", base, "/i", f"/d{w}", f"/l{w}", f"/s{w}"], cwd=Path("/tmp"),
            log_name=f"{log}_esentutl", ok_codes=None)
    for db in [p for p in rep.iterdir() if p.suffix.lower() in (".dat", ".mdb")]:
        job.run(t, [job.tb.esentutl, "/p", to_windows_path(db), "/o"], cwd=Path("/tmp"),
                log_name=f"{log}_esentutl", ok_codes=None)
    return rep


def task_srum(job: Job, t: Task):
    sd = job.sysdrive
    db = find_ci(sd, "Windows/System32/sru/SRUDB.dat") if sd else None
    sw = find_ci(sd, "Windows/System32/config/SOFTWARE") if sd else None
    if not db:
        raise SkipTask("SRUDB.dat not collected")
    out = job.cat_dir("exec") / "SRUM"
    out.mkdir(exist_ok=True)
    reg = ["-r", sw] if sw else []
    note = ""
    if not _ese_run(job, t, "SrumECmd", ["-f", db, "--csv", out] + reg, "srum"):
        rep = _ese_repair_copy(job, t, db.parent, "sru", "srum")
        try:
            if not _ese_run(job, t, "SrumECmd", ["-f", rep / db.name, "--csv", out] + reg, "srum_retry"):
                raise RuntimeError("SrumECmd could not open SRUDB.dat even after esentutl repair - see _logs/srum*.log")
        finally:
            shutil.rmtree(rep, ignore_errors=True)
        note = " (repaired copy)"
    files = job.tidy_outputs(out, "SRUM")
    tables = [f for f in files if f.name.endswith("_Output.csv")]
    if not tables:
        raise RuntimeError("SrumECmd produced no tables - see _logs/srum*.log")
    net = job.cat_dir("network") / "SRUM"
    net.mkdir(exist_ok=True)
    for f in tables:
        if re.search(r"Network(Usages|Connections)", f.name):
            shutil.copy2(f, net / f.name)
    return f"{len(tables)} tables{note}"


def task_sum(job: Job, t: Task):
    sd = job.sysdrive
    sumdir = find_ci(sd, "Windows/System32/LogFiles/SUM") if sd else None
    if not sumdir or not any(p.suffix.lower() == ".mdb" for p in sumdir.iterdir()):
        raise SkipTask("no User Access Logging databases (Windows Server only)")
    out = job.cat_dir("network") / "SUM_UserAccessLogging"
    out.mkdir(exist_ok=True)
    note = ""
    if not _ese_run(job, t, "SumECmd", ["-d", sumdir, "--csv", out], "sum"):
        rep = _ese_repair_copy(job, t, sumdir, "svc", "sum")
        try:
            if not _ese_run(job, t, "SumECmd", ["-d", rep, "--csv", out], "sum_retry"):
                raise RuntimeError("SumECmd could not open the SUM databases even after repair - see _logs/sum*.log")
        finally:
            shutil.rmtree(rep, ignore_errors=True)
        note = " (repaired copy)"
    tables = [f for f in job.tidy_outputs(out, "SUM") if f.suffix.lower() == ".csv"]
    return f"{len(tables)} tables{note}"


# =============================================================================== registry
def task_recmd(job: Job, t: Task):
    batch = job.cfg["tools"].get("recmd_batch", "Kroll_Batch.reb")
    home = job.tb.ez_home("RECmd")
    reb = (home / "BatchExamples" / batch) if home else None
    if not reb or not reb.exists():
        raise SkipTask(f"RECmd batch file {batch} not found")
    out = job.cat_dir("registry")
    for letter, d in job.layout.drives.items():
        if not rglob_ci(d, r"(^Windows/System32/config/(SYSTEM|SOFTWARE|SAM)$|NTUSER\.DAT$|UsrClass\.dat$)"):
            continue
        before = _snapshot(out)
        # no --csvf: RECmd derives plugin detail file names from it and per-hive files would collide
        ez(job, t, "RECmd", ["-d", d, "--bn", reb, "--csv", out], log_name=f"recmd_{letter}")
        for f in _snapshot(out) - before:
            if f.is_file() and f.name.endswith("_Output.csv"):
                f.rename(out / job.name(f"RECmd_{letter}"))
    return _rows(out / job.name(f"RECmd_{job.layout.system_drive}"))


def task_registry_route(job: Job, t: Task):
    reg = job.cat_dir("registry")
    plugins = postproc.flatten_recmd_plugins(reg)
    res: dict = {}
    for b in reg.glob(f"{job.host}_RECmd_*.csv"):
        res.update(postproc.route_registry(job, b, plugins))
    for f in plugins:  # prefix plugin detail files with host
        f.rename(f.with_name(f"{job.host}_{f.name}"))
    return f"{len(res)} category files, {len(plugins)} plugin tables"


def task_regripper(job: Job, t: Task):
    if not job.tb.regripper.exists():
        raise SkipTask("RegRipper not installed (setup.sh)")
    hives: list[tuple[str, Path]] = []
    for letter, d in job.layout.drives.items():
        hives += [(letter, h) for h in rglob_ci(d, r"(^Windows/System32/config/(SYSTEM|SOFTWARE|SAM|SECURITY)$|"
                                                   r"(^|/)NTUSER\.DAT$|UsrClass\.dat$|Amcache\.hve$)")]
    if not hives:
        raise SkipTask("no hives")
    out = job.cat_dir("registry") / "RegRipper"
    out.mkdir(exist_ok=True)
    done = [0, 0]  # finished, failed
    done_lock = threading.Lock()

    def rip(item: tuple[str, Path]):
        letter, h = item
        tag = h.name if "Users" not in h.parts else f"{_user_of(h)}_{h.name}"
        if "ServiceProfiles" in h.parts:
            tag = f"{h.parent.name}_{h.name}"
        if job.layout.system_drive and letter != job.layout.system_drive:
            tag = f"{letter}_{tag}"  # same hive from a VSS copy / second volume
        try:
            job.run(t, ["perl", str(job.tb.regripper), "-r", str(h), "-a"], cwd=job.tb.regripper.parent,
                    log_name=f"regripper_{tag}", stdout_file=out / f"{job.host}_RegRipper_{tag}.txt")
        except RuntimeError:
            with done_lock:
                done[1] += 1
        with done_lock:
            done[0] += 1
            t.progress = done[0] / len(hives)
            t.detail = f"{done[0]}/{len(hives)} hives"

    # perl is single threaded; the largest hives (SOFTWARE, NTUSER) dominate, so rip them in parallel
    with ThreadPoolExecutor(max_workers=int(module_opt(job.cfg, "regripper", "parallel", 3))) as ex:
        list(ex.map(rip, sorted(hives, key=lambda x: -x[1].stat().st_size)))
    fails = done[1]
    if fails:
        raise TaskWarning(f"{len(hives) - fails}/{len(hives)} hives parsed")
    return f"{len(hives)} hives"


# =============================================================================== file / folder opening
def task_lnk(job: Job, t: Task):
    n = len(rglob_ci(job.files, r"\.lnk$"))
    if not n:
        raise SkipTask("no .lnk files")
    out = job.cat_dir("fileopen")
    ez(job, t, "LECmd", ["-d", job.files, "--csv", out, "--csvf", job.name("LNK"), "-q"])
    return f"{n} LNK files, {_rows(out / job.name('LNK'))}"


def task_jumplists(job: Job, t: Task):
    n = len(rglob_ci(job.files, r"Destinations-ms$"))
    if not n:
        raise SkipTask("no jump lists")
    out = job.cat_dir("fileopen")
    stage = _stage(job, "jumplists")
    ez(job, t, "JLECmd", ["-d", job.files, "--csv", stage, "--csvf", job.name("JumpLists"), "-q"])
    _publish(job, stage, out, "JumpLists")
    return f"{n} jump list files"


def task_shellbags(job: Job, t: Task):
    users = [d for d in job.layout.drives.values() if find_ci(d, "Users")]
    if not users:
        raise SkipTask("no user hives")
    out = job.cat_dir("fileopen") / "ShellBags"
    out.mkdir(exist_ok=True)
    for d in users:
        ez(job, t, "SBECmd", ["-d", find_ci(d, "Users"), "--csv", out])
    files = job.tidy_outputs(out, "ShellBags")
    return f"{len(files)} files"


def task_activities(job: Job, t: Task):
    dbs = rglob_ci(job.files, r"ConnectedDevicesPlatform/[^/]+/ActivitiesCache\.db$")
    if not dbs:
        raise SkipTask("ActivitiesCache.db not collected")
    out = job.cat_dir("fileopen") / "Windows_Timeline"
    out.mkdir(exist_ok=True)
    for db in dbs:
        before = _snapshot(out)
        ez(job, t, "WxTCmd", ["-f", db, "--csv", out])
        job.tidy_outputs(out, f"Timeline_{_user_of(db)}_{db.parent.name[:8]}", before)
    return f"{len(dbs)} database(s)"


# =============================================================================== deleted
def task_recyclebin(job: Job, t: Task):
    n = len(rglob_ci(job.files, r"\$Recycle\.Bin/.+/\$I[^/]+$"))
    if not n:
        raise SkipTask("no $I files in collection")
    out = job.cat_dir("deleted")
    ez(job, t, "RBCmd", ["-d", job.files, "--csv", out, "--csvf", job.name("RecycleBin"), "-q"])
    return f"{n} $I records"


# =============================================================================== file system
def _mft_csv(letter, mft):
    def act(job: Job, t: Task):
        out = job.cat_dir("fs")
        name = job.name(f"{letter}_MFT")
        ez(job, t, "MFTECmd", ["-f", mft, "--csv", out, "--csvf", name], log_name=f"mft_{letter}")
        return _rows(out / name)
    return act


def _mft_body(letter, mft):
    def act(job: Job, t: Task):
        out = job.cat_dir("fs")
        ez(job, t, "MFTECmd", ["-f", mft, "--body", out, "--bodyf", job.name(f"{letter}_MFT", "body"),
                               "--bdl", letter], log_name=f"body_{letter}")
        return f"bodyfile {(out / job.name(f'{letter}_MFT', 'body')).stat().st_size / 1048576:.0f} MB"
    return act


def _mactime(letter):
    def act(job: Job, t: Task):
        out = job.cat_dir("fs")
        body = out / job.name(f"{letter}_MFT", "body")
        dst = out / job.name(f"{letter}_FileSystem_Timeline")
        if job.tb.mactime:
            t.detail = "sorting MACB events (mactime)"
            job.run(t, [job.tb.mactime, "-b", str(body), "-d", "-y", "-z", "UTC"], log_name=f"mactime_{letter}",
                    stdout_file=dst)
            return _rows(dst)
        t.tool = "python (mactime)"
        t.detail = "sorting MACB events (built-in, sleuthkit not installed)"
        return f"{postproc.mactime_py(body, dst):,} rows"
    return act


def _usn(letter, j, mft):
    def act(job: Job, t: Task):
        out = job.cat_dir("fs")
        stage = job.work / "_staging" / f"usn_{letter}"
        stage.mkdir(parents=True, exist_ok=True)
        name = job.name(f"{letter}_UsnJrnl")
        # -m resolves full parent paths; MFTECmd then also dumps the $MFT, so stage and keep only $J output
        ez(job, t, "MFTECmd", ["-f", j, "-m", mft, "--csv", stage, "--csvf", name], log_name=f"usn_{letter}")
        shutil.move(str(stage / name), out / name)
        shutil.rmtree(stage, ignore_errors=True)
        return _rows(out / name)
    return act


def _ntfs_meta(letter, d):
    def act(job: Job, t: Task):
        out = job.cat_dir("fs")
        done = []
        for fname, tag in (("$LogFile", "LogFile"), ("$Secure_$SDS", "SDS"), ("$Boot", "Boot")):
            f = find_ci(d, fname)
            if f:
                ez(job, t, "MFTECmd", ["-f", f, "--csv", out, "--csvf", job.name(f"{letter}_{tag}")],
                   log_name=f"ntfs_{letter}")
                done.append(tag)
        if not done:
            raise SkipTask("no $LogFile/$SDS/$Boot")
        return ", ".join(done)
    return act


# =============================================================================== event logs
def _logs_dir(job: Job) -> tuple[Path | None, int]:
    d = find_ci(job.sysdrive, "Windows/System32/winevt/Logs") if job.sysdrive else None
    n = len([p for p in d.iterdir() if p.suffix.lower() == ".evtx"]) if d else 0
    return d, n


def task_evtxecmd(job: Job, t: Task):
    d, n = _logs_dir(job)
    if not n:
        raise SkipTask("no .evtx files")
    out = job.cat_dir("evtx")
    ez(job, t, "EvtxECmd", ["-d", d, "--csv", out, "--csvf", job.name("EventLogs_All")],
       progress_rx=r"^Processing\s", total=n)
    return f"{n} logs, {_rows(out / job.name('EventLogs_All'))}"


def task_evtx_route(job: Job, t: Task):
    res = postproc.split_event_logs(job, job.cat_dir("evtx") / job.name("EventLogs_All"))
    return f"{sum(res.values()):,} events into {len(res)} views"


def task_hayabusa(job: Job, t: Task):
    d, n = _logs_dir(job)
    if not n:
        raise SkipTask("no .evtx files")
    if not job.tb.hayabusa.exists():
        raise SkipTask("Hayabusa not installed (setup.sh)")
    out = job.cat_dir("hunt")
    csvf = out / job.name("Hayabusa_Timeline")
    job.run(t, [str(job.tb.hayabusa), "dfir-timeline", "-d", str(d), "-o", str(csvf), "-w", "-C", "-U", "-q", "-K",
                "-H", str(out / job.name("Hayabusa_Summary", "html"))], cwd=job.tb.hayabusa.parent)
    return f"{postproc.count_rows(csvf):,} detections"


def task_hayabusa_logons(job: Job, t: Task):
    d, n = _logs_dir(job)
    if not n or not job.tb.hayabusa.exists():
        raise SkipTask("no .evtx files / Hayabusa missing")
    out = job.cat_dir("account")
    base = out / f"{job.host}_Hayabusa_LogonSummary"
    job.run(t, [str(job.tb.hayabusa), "logon-summary", "-d", str(d), "-o", str(base), "-C", "-q", "-K"],
            cwd=job.tb.hayabusa.parent)
    return f"{len(list(out.glob(base.name + '*')))} files"


def task_chainsaw(job: Job, t: Task):
    d, n = _logs_dir(job)
    if not n:
        raise SkipTask("no .evtx files")
    tb = job.tb
    if not tb.chainsaw.exists():
        raise SkipTask("Chainsaw not installed (setup.sh)")
    out = job.cat_dir("hunt") / "Chainsaw"
    mapping = next(iter(sorted((tb.chainsaw.parent / "mappings").glob("sigma-event-logs-all.y*ml"))), None)
    cmd = [str(tb.chainsaw), "hunt", str(d), "-r", str(tb.chainsaw.parent / "rules"),
           "--csv", "--output", str(out), "--skip-errors", "-q"]
    if tb.sigma_rules.is_dir() and mapping:
        cmd[3:3] = ["-s", str(tb.sigma_rules), "--mapping", str(mapping)]
    job.run(t, cmd, cwd=tb.chainsaw.parent)
    files = [f for f in out.glob("*.csv")]
    for f in files:
        if not f.name.startswith(job.host):
            f.rename(f.with_name(f"{job.host}_Chainsaw_{f.name}"))
    return f"{len(files)} detection groups"


# =============================================================================== browser / apps
_BROWSER_RX = re.compile(r"Chrom|Edge|Firefox|Brave|Opera|Vivaldi|Browser", re.I)


def task_sqlecmd(job: Job, t: Task):
    stage = job.work / "_staging" / "sqlecmd"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    ez(job, t, "SQLECmd", ["-d", job.files, "--csv", stage], ok_codes=(0, 1))
    files = job.tidy_outputs(stage, "SQLECmd")
    nb = na = 0
    for f in files:
        if _BROWSER_RX.search(f.name):
            dst = job.cat_dir("browser")
            nb += 1
        else:
            dst = job.cat_dir("apps") / "SQLite_Databases"
            dst.mkdir(exist_ok=True)
            na += 1
        shutil.move(str(f), dst / f.name)
    shutil.rmtree(stage, ignore_errors=True)
    if not files:
        raise SkipTask("no SQLite databases matching SQLECmd maps")
    return f"{nb} browser tables, {na} application tables"


# =============================================================================== remote / persistence / usb / live
def task_rdpcache(job: Job, t: Task):
    caches = [p for p in rglob_ci(job.files, r"Terminal Server Client/Cache/(Cache\d+\.bin|bcache\d+\.bmc)$")
              if p.stat().st_size > 0]
    if not caches:
        raise SkipTask("no RDP bitmap cache")
    if not job.tb.bmc_tools.exists():
        raise SkipTask("bmc-tools not installed (setup.sh)")
    base = job.cat_dir("remote") / "RDP_Bitmap_Cache"
    for i, c in enumerate(caches):
        t.progress = i / len(caches)
        d = base / f"{_user_of(c)}_{c.stem}"
        d.mkdir(parents=True, exist_ok=True)
        job.run(t, [sys.executable, str(job.tb.bmc_tools), "-s", str(c), "-d", str(d), "-b"],
                cwd=job.tb.bmc_tools.parent, log_name="rdpcache")
    tiles = sum(1 for _ in base.rglob("*.bmp"))
    return f"{len(caches)} cache files, {tiles} tiles (+ collage)"


def task_rdp_reconstruct(job: Job, t: Task):
    from . import rdp_stitch
    if not rdp_stitch.available():
        raise SkipTask("numpy/Pillow not installed (setup.sh)")
    base = job.cat_dir("remote") / "RDP_Bitmap_Cache"
    dirs = sorted(d for d in base.iterdir() if d.is_dir()) if base.is_dir() else []
    if not dirs:
        raise SkipTask("no extracted RDP cache tiles")
    out = job.cat_dir("remote") / "RDP_Reconstructed"
    opt = lambda k, d: module_opt(job.cfg, "rdp_reconstruct", k, d)  # noqa: E731
    results = {}
    for i, d in enumerate(dirs):
        t.progress = i / len(dirs)

        def say(m, d=d):
            t.detail = f"{d.name}: {m}"
            job.log(f"[{t.key}] {d.name}: {m}")
        r = rdp_stitch.reconstruct_dir(d, out / d.name, f"{job.host}_{d.name}",
                                       min_tiles=int(opt("min_tiles", 4)), max_mse=float(opt("max_mse", 150)),
                                       ratio=float(opt("ratio", 0.85)), progress=say)
        job.log(f"[{t.key}] {d.name}: {r['tiles']} tiles, {r['unique']} unique, "
                f"{len(r['fragments'])} fragments, {r['placed']} placed")
        results[d.name] = r
    nf = sum(len(r["fragments"]) for r in results.values())
    if not nf:
        raise SkipTask("no tiles could be joined")
    rdp_stitch.write_gallery(out, job.host, results)
    placed = sum(r["placed"] for r in results.values())
    uniq = sum(r["unique"] for r in results.values())
    biggest = max((f["tiles"] for r in results.values() for f in r["fragments"]), default=0)
    return (f"{nf} fragments from {len(dirs)} caches, {placed}/{uniq} unique tiles placed, "
            f"largest {biggest} tiles - open {job.host}_RDP_Reconstruction.html")


def task_schtasks(job: Job, t: Task):
    d = find_ci(job.sysdrive, "Windows/System32/Tasks") if job.sysdrive else None
    if not d:
        raise SkipTask("Tasks folder not collected")
    n = postproc.scheduled_tasks(job, d)
    return f"{n} task actions"


def task_setupapi(job: Job, t: Task):
    files = [f for d in job.layout.drives.values() for f in rglob_ci(d, r"^Windows/INF/setupapi\.(dev|offline|setup|upgrade).*\.log$")]
    if not files:
        raise SkipTask("setupapi logs not collected")
    n = postproc.setupapi(job, files)
    return f"{n} device installs from {len(files)} logs"


def task_rawcopy(job: Job, t: Task):
    n = 0
    ps = rglob_ci(job.files, r"PSReadLine/ConsoleHost_history\.txt$")
    for f in ps:
        d = job.cat_dir("exec") / "PowerShell_History"
        d.mkdir(exist_ok=True)
        shutil.copy2(f, d / f"{job.host}_{_user_of(f)}_ConsoleHost_history.txt")
        n += 1
    rx = "|".join(re.escape(x) for x in postproc.REMOTE_TOOLS)
    rat = [f for f in rglob_ci(job.files, rf"/({rx})[^/]*/") if f.suffix.lower() in
           (".log", ".txt", ".trace", ".conf", ".ini", ".xml", "")]
    rat = [f for f in rat if "/Prefetch/" not in f.as_posix()]
    n += postproc.copy_tree_files(rat, job.files, job.cat_dir("remote") / "Tool_Logs")
    dfn = rglob_ci(job.files, r"Windows Defender/(Support|Scans/History)/")
    n += postproc.copy_tree_files(dfn, job.files, job.cat_dir("hunt") / "Defender_Logs")
    if not n:
        raise SkipTask("nothing to copy")
    return f"{len(ps)} PS histories, {len(rat)} remote-tool files, {len(dfn)} Defender files"


def task_velociraptor(job: Job, t: Task):
    if not job.layout.velo_results:
        raise SkipTask("no Velociraptor artifact results in collection")
    res = postproc.velociraptor_results(job, job.layout.velo_results)
    if not res:
        raise SkipTask("results empty")
    return ", ".join(f"{k.split('Velociraptor_')[-1][:-4]}={v}" for k, v in res.items())


def task_thor(job: Job, t: Task):
    cfg = job.cfg
    if not module_enabled(cfg, "thor", default=False):
        raise SkipTask("THOR disabled in config (only built-in YARA rules) - ready for later use")
    thor = job.tb.thor_binary()
    rules = job.tb.thor_custom_rules()
    if not thor:
        raise SkipTask("THOR binary not installed in tools/thor")
    if module_opt(cfg, "thor", "require_custom_rules", True) and not rules:
        raise SkipTask("only built-in signatures available - extended YARA rules required")
    out = job.cat_dir("hunt") / "THOR"
    out.mkdir(exist_ok=True)
    args = module_opt(cfg, "thor", "args", ["-a", "Filescan", "--intense", "--norescontrol", "--nosoft",
                                              "--cross-platform"])
    job.run(t, [str(thor)] + list(args) + ["-p", str(job.files), "-e", str(out)], cwd=thor.parent,
            ok_codes=(0, 1))
    return f"{len(rules)} custom rule files"


# =============================================================================== correlation / report
def task_exec_timeline(job: Job, t: Task):
    n = postproc.execution_timeline(job)
    if not n:
        raise SkipTask("no execution evidence parsed")
    return f"{n:,} events"


def task_summary(job: Job, t: Task):
    import datetime as dt
    tasks = [x for x in job.task_list() if x.key != "summary"]
    lines = [f"DFIR Triage Agent - processing summary for {job.host}",
             f"Generated : {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
             f"Source    : {job.item.path}",
             f"Output    : {job.out}",
             f"Duration  : {time.monotonic() - job.started:.0f}s", "",
             f"{'STATUS':<9}{'TASK':<48}{'TOOL':<22}{'TIME':>8}  RESULT", "-" * 130]
    for x in tasks:
        lines.append(f"{x.status.value.upper():<9}{x.name[:47]:<48}{x.tool[:21]:<22}{x.elapsed:>7.0f}s  {x.message}")
    lines += ["", "Antivirus scanning: " + AV_NOTE, "", "OUTPUT FILES", "-" * 130]
    for cat in sorted(p for p in job.out.iterdir() if p.is_dir() and not p.name.startswith("_")):
        lines.append(f"[{cat.name}]")
        for root, dirs, files in os.walk(cat):
            dirs.sort()
            rel = Path(root).relative_to(job.out)
            if len(files) > 25:  # e.g. RDP bitmap tiles - summarise instead of listing
                size = sum(os.path.getsize(os.path.join(root, f)) for f in files)
                lines.append(f"{size / 1048576:>10.2f} MB  {rel}/  ({len(files)} files)")
                continue
            for f in sorted(files):
                lines.append(f"{os.path.getsize(os.path.join(root, f)) / 1048576:>10.2f} MB  {rel / f}")
    d = job.cat_dir("info")
    (d / job.name("Processing_Summary", "txt")).write_text("\n".join(lines) + "\n", encoding="utf-8")
    (d / job.name("Processing_Summary", "json")).write_text(json.dumps([
        {"key": x.key, "task": x.name, "tool": x.tool, "category": x.category, "status": x.status.value,
         "seconds": round(x.elapsed, 1), "result": x.message} for x in tasks], indent=2))
    # summary runs after every other task of the job: its index is no longer needed (frees memory in
    # multi-collection runs and avoids stale entries if the agent is reused in-process)
    forget_index(job.layout.files)
    if not job.cfg["general"].get("keep_extracted", True) and job.work.exists() and job.item.kind not in IN_PLACE:
        shutil.rmtree(job.work, ignore_errors=True)
    return "written"
