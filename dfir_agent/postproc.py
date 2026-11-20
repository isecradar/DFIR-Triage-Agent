"""Post-processing: route tool output into artifact categories, timelines and reports (pure Python)."""
from __future__ import annotations

import csv
import json
import re
import shutil
import sys
import xml.etree.ElementTree as ET

try:  # task XML comes from the (possibly hostile) evidence host
    from defusedxml.ElementTree import fromstring as _xml_fromstring
except ImportError:
    _xml_fromstring = None
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Iterator

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2 ** 31 - 1)


# ============================================================================ csv helpers
def iter_csv(path: Path) -> Iterator[dict]:
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        yield from csv.DictReader((l.replace("\0", "") for l in fh))


def csv_header(path: Path) -> list[str]:
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        return next(csv.reader((l.replace("\0", "") for l in fh)), [])


class CsvSink:
    """Lazily-opened CSV writers keyed by output path."""

    def __init__(self):
        self.files: dict[Path, tuple] = {}
        self.rows: dict[Path, int] = defaultdict(int)

    def write(self, path: Path, header: list[str], row: dict | list) -> None:
        if path not in self.files:
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = open(path, "w", encoding="utf-8", errors="backslashreplace", newline="")
            w = csv.writer(fh)
            w.writerow(header)
            self.files[path] = (fh, w, header)
        fh, w, hdr = self.files[path]
        w.writerow([row.get(h, "") for h in hdr] if isinstance(row, dict) else row)
        self.rows[path] += 1

    def close(self) -> dict[Path, int]:
        for fh, _, _ in self.files.values():
            fh.close()
        return dict(self.rows)


def count_rows(path: Path) -> int:
    try:
        with open(path, "rb") as fh:
            return max(0, sum(1 for _ in fh) - 1)
    except OSError:
        return 0


# ============================================================================ bodyfile -> timeline
def mactime_py(body: Path, dst: Path, chunk_rows: int = 1_500_000) -> int:
    """Pure-Python equivalent of `mactime -b body -d -y -z UTC` (used when sleuthkit is absent).

    One row per distinct timestamp per file with its MACB flags; external merge sort keeps memory bounded."""
    import datetime as dt
    import heapq
    import tempfile

    epoch = dt.datetime(1970, 1, 1)

    def iso(t: int) -> str:
        # timestomped / corrupt $MFT entries can carry FILETIMEs past year 9999: keep the event, show raw seconds
        try:
            return (epoch + dt.timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, ValueError):
            return f"epoch:{t}"

    chunks: list[Path] = []
    buf: list[tuple[int, str]] = []
    tmpdir = Path(tempfile.mkdtemp(prefix="mactime_", dir=dst.parent))

    def flush():
        if not buf:
            return
        buf.sort(key=lambda r: r[0])
        p = tmpdir / f"chunk{len(chunks)}.tsv"
        with open(p, "w", encoding="utf-8") as fh:
            for t, rest in buf:
                fh.write(f"{t}\t{rest}\n")
        chunks.append(p)
        buf.clear()

    with open(body, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split("|")
            if len(f) < 11:
                continue
            # md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
            name, inode, mode, uid, gid, size = f[1], f[2], f[3], f[4], f[5], f[6]
            stamps: dict[int, list[str]] = {}
            for flag, val in zip("macb", (f[8], f[7], f[9], f[10])):
                try:
                    t = int(float(val))
                except (ValueError, OverflowError):  # also 'inf' / 'nan'
                    continue
                if t > 0:
                    stamps.setdefault(t, []).append(flag)
            for t, flags in stamps.items():
                macb = "".join(c if c in flags else "." for c in "macb")
                q = '"' + name.replace('"', '""') + '"'
                buf.append((t, f"{size},{macb},{mode},{uid},{gid},{inode},{q}"))
            if len(buf) >= chunk_rows:
                flush()
    flush()
    n = 0
    files = [open(p, encoding="utf-8") for p in chunks]
    try:
        streams = [((int(l.split("\t", 1)[0]), l) for l in fh) for fh in files]
        with open(dst, "w", encoding="utf-8", newline="") as out:
            out.write("Date,Size,Type,Mode,UID,GID,Meta,File Name\n")
            for t, l in heapq.merge(*streams, key=lambda x: x[0]):
                out.write(f"{iso(t)},{l.split(chr(9), 1)[1]}")
                n += 1
    finally:
        for fh in files:
            fh.close()
        shutil.rmtree(tmpdir, ignore_errors=True)
    return n


# ============================================================================ registry routing
RECMD_ROUTES = {
    "Program Execution": "exec", "User Activity": "fileopen", "Microsoft Office": "fileopen",
    "Devices": "usb", "Autoruns": "persist", "Services": "persist", "User Accounts": "account",
    "Network Shares": "network", "Web Browsers": "browser", "Threat Hunting": "hunt",
    "Antivirus": "hunt", "Installed Software": "apps", "Third Party Applications": "apps",
    "Cloud Storage": "apps", "Volume Shadow Copies": "fs", "System Info": "info", "Event Logs": "evtx",
}
# (description regex, extra category) - a row may land in several categories
RECMD_DESC_ROUTES = [
    (re.compile(r"Terminal Server Client|\bRDP\b|TeamViewer|AnyDesk|WinSCP", re.I), "remote"),
    (re.compile(r"Network|MAC Address|Firewall|Wireless|WLAN|Known Networks", re.I), "network"),
    (re.compile(r"TypedURLs|TypedPaths", re.I), "browser"),
]
PLUGIN_ROUTES = {
    "exec": ["UserAssist", "BamDam", "AppCompat", "AppCompatFlags2", "RunMRU", "RADAR", "CIDSizeMRU",
             "JumplistData", "RecentApps", "MuiCache", "Taskband"],
    "fileopen": ["RecentDocs", "OpenSavePidlMRU", "LastVisitedPidlMRU", "OfficeMRU", "TrustedDocuments",
                 "FirstFolder", "FileExts", "WordWheelQuery", "TypedPaths", "Shellbags"],
    "usb": ["USBSTOR", "USB", "SCSI", "DeviceClasses", "MountedDevices", "WindowsPortableDevices",
            "VolumeInfoCache", "MountPoints2"],
    "network": ["KnownNetworks", "NetworkSetup2", "NetworkAdapters", "FirewallRules", "NetworkList"],
    "persist": ["Services", "TaskCache"],
    "account": ["SAMBuiltin", "UserAccounts", "ProfileList"],
    "remote": ["TerminalServerClient"],
    "browser": ["TypedURLs"],
    "apps": ["UnInstall", "Products", "AppPaths"],
    "info": ["TimeZoneInfo", "ETW"],
}
_PLUGIN_TO_CAT = {p.lower(): c for c, ps in PLUGIN_ROUTES.items() for p in ps}


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


def flatten_recmd_plugins(reg_dir: Path) -> list[Path]:
    """RECmd on Linux nests plugin detail files under the hive path; flatten to Plugins/<Plugin>__<hive>.csv."""
    plugin_dir = reg_dir / "Plugins"
    out = []
    for ts_dir in [d for d in reg_dir.iterdir() if d.is_dir() and re.fullmatch(r"\d{14}", d.name)]:
        for f in ts_dir.rglob("*.csv"):
            rel = f.relative_to(ts_dir)
            top = rel.parts[0]
            m = re.match(r"\d{14}_(.+?)_?$", top)
            plugin = m.group(1) if m else top
            hive = "_".join(rel.parts[1:]) if len(rel.parts) > 1 else rel.name
            name = f"{plugin}__{_safe_name(hive.replace('.csv', ''))}.csv"
            plugin_dir.mkdir(exist_ok=True)
            dst = plugin_dir / name
            i = 1
            while dst.exists():  # same plugin + hive path from another run (e.g. a VSS volume)
                i += 1
                dst = plugin_dir / f"{name[:-4]}_{i}.csv"
            shutil.move(str(f), dst)
            out.append(dst)
        shutil.rmtree(ts_dir, ignore_errors=True)
    return out


def route_registry(job, batch_csv: Path, plugin_files: list[Path]) -> dict[str, int]:
    """Split the RECmd batch output by Category into artifact folders + copy plugin details."""
    sink = CsvSink()
    header = csv_header(batch_csv)
    for row in iter_csv(batch_csv):
        cat = row.get("Category", "")
        targets = {RECMD_ROUTES.get(cat, "registry")}
        desc = row.get("Description", "")
        for rx, extra in RECMD_DESC_ROUTES:
            if rx.search(desc):
                targets.add(extra)
        for t in targets:
            if t == "registry":
                continue
            stem = _safe_name(cat if t == RECMD_ROUTES.get(cat) else f"{cat}_{t}")
            sink.write(job.cat_dir(t) / f"{job.host}_Registry_{stem}.csv", header, row)
    rows = sink.close()
    for f in plugin_files:
        cat = _PLUGIN_TO_CAT.get(f.name.split("__")[0].lower())
        if cat:
            d = job.cat_dir(cat) / "Registry_Plugins"
            d.mkdir(exist_ok=True)
            shutil.copy2(f, d / f"{job.host}_{f.name}")
    return {p.name: n for p, n in rows.items()}


# ============================================================================ event log views
EVENT_VIEWS = [
    ("Logons_and_Account_Management", "account", [
        ("Security", [4624, 4625, 4634, 4647, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732,
                      4738, 4740, 4756, 4767, 4768, 4769, 4771, 4776, 4798, 4799])]),
    ("Process_Creation", "exec", [
        ("Security", [4688]), ("Microsoft-Windows-Sysmon/Operational", [1])]),
    ("PowerShell", "exec", [
        ("Microsoft-Windows-PowerShell/Operational", [4103, 4104]),
        ("Windows PowerShell", [400, 403, 600, 800]),
        ("PowerShellCore/Operational", [4103, 4104])]),
    ("Services_Tasks_WMI", "persist", [
        ("System", [7045, 7034, 7035, 7036, 7040]),
        ("Security", [4697, 4698, 4699, 4700, 4701, 4702]),
        ("Microsoft-Windows-TaskScheduler/Operational", [106, 140, 141, 200, 201]),
        ("Microsoft-Windows-WMI-Activity/Operational", [5857, 5858, 5859, 5860, 5861])]),
    ("RDP_and_Remote_Logons", "remote", [
        ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", [21, 22, 23, 24, 25, 39, 40]),
        ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", [261, 1149]),
        ("Microsoft-Windows-TerminalServices-RDPClient/Operational", [1024, 1026, 1027, 1029, 1102]),
        ("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", [98, 131]),
        ("Microsoft-Windows-WinRM/Operational", [6, 91, 168]),
        ("Security", [4778, 4779])]),
    ("Network_Shares_and_Connections", "network", [
        ("Security", [5140, 5142, 5143, 5144, 5145]),
        ("Microsoft-Windows-NetworkProfile/Operational", [10000, 10001]),
        ("Microsoft-Windows-WLAN-AutoConfig/Operational", [8001, 8002, 8003]),
        ("Microsoft-Windows-SMBClient/Security", [31001]),
        ("Microsoft-Windows-Bits-Client/Operational", [3, 59, 60])]),
    ("USB_and_Storage_Devices", "usb", [
        ("Microsoft-Windows-Partition/Diagnostic", [1006]),
        ("Microsoft-Windows-Kernel-PnP/Configuration", [400, 410, 430]),
        ("Microsoft-Windows-DriverFrameworks-UserMode/Operational", [2003, 2004, 2100, 2101, 2102]),
        ("System", [20001, 20003])]),
    ("Defender_Detections", "hunt", [
        ("Microsoft-Windows-Windows Defender/Operational", [1006, 1007, 1015, 1116, 1117, 1118, 1119,
                                                             5001, 5004, 5007, 5010, 5012])]),
    ("Log_Cleared_and_System_Power", "evtx", [
        ("Security", [1100, 1102]), ("System", [104, 1074, 6005, 6006, 6008, 41])]),
]


def split_event_logs(job, evtx_csv: Path) -> dict[str, int]:
    rules: dict[tuple[str, int], list[tuple[str, str]]] = defaultdict(list)
    for name, cat, specs in EVENT_VIEWS:
        for channel, ids in specs:
            for i in ids:
                rules[(channel.lower(), i)].append((name, cat))
    sink = CsvSink()
    header = csv_header(evtx_csv)
    for row in iter_csv(evtx_csv):
        try:
            eid = int(row.get("EventId") or -1)
        except ValueError:
            continue
        for name, cat in rules.get(((row.get("Channel") or "").lower(), eid), ()):
            sink.write(job.cat_dir(cat) / f"{job.host}_EventLogs_{name}.csv", header, row)
    return {p.name: n for p, n in sink.close().items()}


# ============================================================================ execution timeline
TL_HEADER = ["Timestamp", "Source", "TimestampMeaning", "FullPath", "ProcessName", "User", "RunCount",
             "SHA1", "Details", "Hostname"]


def _proc(path: str) -> str:
    return re.split(r"[\\/]", path.rstrip("\\/"))[-1] if path else ""


def _user_from_name(name: str) -> str:
    m = re.search(r"Users_([^_]+)_(?:NTUSER|ntuser|UsrClass)", name)
    return m.group(1) if m else ""


def _tl_key(r: list) -> tuple:
    return r[0][:19], r[1], r[3]


class _SortedSpill:
    """Collects rows and returns them sorted; above `chunk_rows` rows sorted runs are spilled to temp
    CSV files and merged, so hosts with millions of 4688 events do not need them all in RAM."""

    def __init__(self, tmp_parent: Path, key, chunk_rows: int = 500_000):
        self.tmp_parent, self.key, self.chunk_rows = tmp_parent, key, chunk_rows
        self.buf: list[list] = []
        self.chunks: list[Path] = []
        self.tmpdir: Path | None = None
        self.n = 0

    def append(self, row: list) -> None:
        self.buf.append(row)
        self.n += 1
        if len(self.buf) >= self.chunk_rows:
            self._flush()

    def _flush(self) -> None:
        import tempfile
        if not self.buf:
            return
        if self.tmpdir is None:
            self.tmpdir = Path(tempfile.mkdtemp(prefix="timeline_", dir=self.tmp_parent))
        self.buf.sort(key=self.key)
        p = self.tmpdir / f"chunk{len(self.chunks)}.csv"
        with open(p, "w", encoding="utf-8", newline="") as fh:
            csv.writer(fh).writerows(self.buf)
        self.chunks.append(p)
        self.buf.clear()

    def write_sorted(self, w) -> None:
        import heapq
        if not self.chunks:  # common case: everything fits in memory
            self.buf.sort(key=self.key)
            w.writerows(self.buf)
            return
        self._flush()
        files = [open(p, encoding="utf-8", newline="") for p in self.chunks]
        try:
            w.writerows(heapq.merge(*(csv.reader(fh) for fh in files), key=self.key))
        finally:
            for fh in files:
                fh.close()
            shutil.rmtree(self.tmpdir, ignore_errors=True)


def execution_timeline(job, chunk_rows: int = 500_000) -> int:
    ex = job.cat_dir("exec")
    rows = _SortedSpill(ex, _tl_key, chunk_rows)

    def add(ts, src, meaning, path, user="", count="", sha1="", details=""):
        if ts:
            rows.append([ts, src, meaning, path, _proc(path), user, count, sha1, details, job.host])

    for f in ex.glob("*Amcache*FileEntries*.csv"):
        for r in iter_csv(f):
            add(r.get("FileKeyLastWriteTimestamp"), "Amcache", "File key last write (first seen/installed)",
                r.get("FullPath") or r.get("KeyName", ""), sha1=r.get("SHA1", ""),
                details=f"{r.get('ProductName', '')} {r.get('Version', '')}".strip())
    for f in ex.glob("*AppCompatCache*.csv"):
        variant = f.stem.split("AppCompatCache", 1)[-1].strip("_")  # '', 'RegBack', 'VSS1', 'RegBack_VSS1'
        src = f"ShimCache ({variant})" if variant else "ShimCache"
        for r in iter_csv(f):
            add(r.get("LastModifiedTimeUTC"), src, "File last modified (presence, not execution)",
                r.get("Path", ""), details=f"Executed={r.get('Executed', '')} Pos={r.get('CacheEntryPosition', '')}")
    for f in ex.glob("*Prefetch*Timeline*.csv"):
        for r in iter_csv(f):
            add(r.get("RunTime"), "Prefetch", "Run time", r.get("ExecutableName", ""))
    for f in ex.glob("Registry_Plugins/*UserAssist*.csv"):
        u = _user_from_name(f.name)
        for r in iter_csv(f):
            p = (r.get("ProgramName") or "").replace("UEME_RUNPATH:", "").replace("UEME_RUNPIDL:", "")
            add(r.get("LastExecuted"), "UserAssist", "Last executed (GUI)", p, u, r.get("RunCounter", ""),
                details=f"FocusTime={r.get('FocusTime', '')}")
    for f in ex.glob("Registry_Plugins/*BamDam*.csv"):
        for r in iter_csv(f):
            sid = (r.get("BatchKeyPath") or "").rsplit("\\", 1)[-1]
            add(r.get("ExecutionTime"), "BAM/DAM", "Last execution", r.get("Program", ""), sid)
    for f in ex.glob("Registry_Plugins/*RunMRU*.csv"):
        u = _user_from_name(f.name)
        for r in iter_csv(f):
            add(r.get("OpenedOn"), "RunMRU", "Typed in Run dialog (MRU 0 only timestamped)", r.get("Executable", ""), u)
    for f in ex.glob("Registry_Plugins/*RecentApps*.csv"):
        u = _user_from_name(f.name)
        for r in iter_csv(f):
            add(r.get("LastAccessed"), "RecentApps", "Last accessed", r.get("AppId", ""), u, r.get("LaunchCount", ""))
    # SRUM: aggregate to first/last seen per executable+user (raw table has 100k+ rows)
    seen: dict[tuple, list] = {}
    for f in ex.glob("SRUM/*AppResourceUseInfo*.csv"):
        for r in iter_csv(f):
            k = (r.get("ExeInfo", ""), r.get("UserName", "") or r.get("Sid", ""))
            ts = r.get("Timestamp", "")
            if not k[0] or not ts:
                continue
            v = seen.setdefault(k, [ts, ts, 0])
            v[0], v[1], v[2] = min(v[0], ts), max(v[1], ts), v[2] + 1
    for (exe, user), (first, last, n) in seen.items():
        add(first, "SRUM", "First seen in SRUM (hourly resource usage)", exe, user, details=f"{n} SRUM records")
        if last != first:
            add(last, "SRUM", "Last seen in SRUM (hourly resource usage)", exe, user, details=f"{n} SRUM records")
    for f in ex.glob("*EventLogs_Process_Creation.csv"):
        for r in iter_csv(f):
            add(r.get("TimeCreated"), f"EventLog {r.get('EventId')}", "Process created",
                r.get("ExecutableInfo") or r.get("PayloadData1", ""), r.get("UserName", ""),
                details=r.get("PayloadData2", ""))
    out = ex / f"{job.host}_ProgramExecution_Timeline.csv"
    with open(out, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(TL_HEADER)
        rows.write_sorted(w)
    return rows.n


# ============================================================================ Velociraptor results
VELO_ROUTES = {"Autoruns": ["persist"], "Services": ["persist"], "Netstat": ["network"]}


def velociraptor_results(job, results_dir: Path) -> dict[str, int]:
    out = {}
    live = job.cat_dir("live")
    for f in sorted(results_dir.glob("*.json")):
        name = f.stem.replace("%2F", "_").replace("/", "_")
        rows, keys = [], []
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(obj, dict):  # JSONL rows are objects; skip stray arrays/scalars
                    continue
                flat ={k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v)
                        for k, v in obj.items()}
                for k in flat:
                    if k not in keys:
                        keys.append(k)
                rows.append(flat)
        if not rows:
            continue
        dst = live / f"{job.host}_Velociraptor_{_safe_name(name)}.csv"
        with open(dst, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        out[dst.name] = len(rows)
        for key, cats in VELO_ROUTES.items():
            if key.lower() in name.lower():
                for c in cats:
                    shutil.copy2(dst, job.cat_dir(c) / dst.name)
    return out


# ============================================================================ scheduled tasks
_SUSP_RULES = [
    (re.compile(r"\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|\\Public\\|\\Downloads\\|%temp%|%appdata%", re.I),
     "user-writable path"),
    (re.compile(r"mshta|certutil|bitsadmin|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64|iex\b|"
                r"downloadstring|invoke-expression", re.I), "LOLBIN / encoded command"),
    (re.compile(r"https?://|\\\\[0-9a-z.\-]+\\", re.I), "remote URL / UNC path"),
    (re.compile(r"\.(ps1|vbs|vbe|js|jse|hta|bat|cmd|scr)\b", re.I), "script file"),
]
_LOLBIN = re.compile(r"powershell|pwsh|cmd(\.exe)?|wscript|cscript|rundll32|regsvr32", re.I)


def _suspicious(task_path: str, cmd: str, args: str) -> str:
    reasons = [why for rx, why in _SUSP_RULES if rx.search(f"{cmd} {args}")]
    # built-in \Microsoft\ tasks legitimately use rundll32/cmd - only flag LOLBINs in third-party tasks
    if _LOLBIN.search(cmd) and not task_path.lower().startswith("\\microsoft\\"):
        reasons.append("script host / LOLBIN in non-Microsoft task")
    return "; ".join(reasons)


_DTD_MARKERS = [m.encode(enc) for m in ("<!DOCTYPE", "<!ENTITY") for enc in ("utf-8", "utf-16-le", "utf-16-be")]


def _parse_task_xml(data: bytes) -> ET.Element:
    """Parse a task definition without entity expansion (real task XML never has a DTD)."""
    if _xml_fromstring is not None:
        return _xml_fromstring(data, forbid_dtd=True)
    if any(m in data for m in _DTD_MARKERS):
        raise ValueError("DTD / entity declaration in task XML")
    return ET.fromstring(data)


def scheduled_tasks(job, tasks_dir: Path) -> int:
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    hdr = ["TaskPath", "Enabled", "Hidden", "Author", "RegistrationDate", "UserId", "RunLevel", "Triggers",
           "Command", "Arguments", "WorkingDirectory", "ComHandler", "Description", "FileModified(UTC)",
           "SuspiciousReason"]
    rows = []
    import datetime as dt
    for f in sorted(p for p in tasks_dir.rglob("*") if p.is_file()):
        try:
            root = _parse_task_xml(f.read_bytes())
        except (ET.ParseError, ValueError):  # defusedxml's DTD/entity errors are ValueErrors
            continue

        def tx(path):
            e = root.find(path, ns)
            return (e.text or "").strip() if e is not None and e.text else ""
        triggers = root.find("t:Triggers", ns)
        trig = ",".join(re.sub(r"\{.*\}", "", c.tag) for c in triggers) if triggers is not None else ""
        cmds = root.findall("t:Actions/t:Exec", ns)
        com = root.find("t:Actions/t:ComHandler/t:ClassId", ns)
        execs = cmds or [None]
        for e in execs:
            cmd = (e.findtext("t:Command", "", ns) or "").strip() if e is not None else ""
            args = (e.findtext("t:Arguments", "", ns) or "").strip() if e is not None else ""
            wd = (e.findtext("t:WorkingDirectory", "", ns) or "").strip() if e is not None else ""
            tpath = "\\" + f.relative_to(tasks_dir).as_posix().replace("/", "\\")
            rows.append([
                tpath,
                tx("t:Settings/t:Enabled") or "true", tx("t:Settings/t:Hidden") or "false",
                tx("t:RegistrationInfo/t:Author"), tx("t:RegistrationInfo/t:Date"),
                tx("t:Principals/t:Principal/t:UserId"), tx("t:Principals/t:Principal/t:RunLevel"), trig,
                cmd, args, wd, (com.text or "") if com is not None else "", tx("t:RegistrationInfo/t:Description")[:300],
                dt.datetime.fromtimestamp(f.stat().st_mtime, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                _suspicious(tpath, cmd, args),
            ])
    out = job.cat_dir("persist") / f"{job.host}_ScheduledTasks.csv"
    with open(out, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(hdr)
        w.writerows(rows)
    return len(rows)


# ============================================================================ setupapi (USB)
_DEV = re.compile(r">>>\s+\[Device Install[^\]]*-\s*(.+?)\]\s*$")
_SEC = re.compile(r">>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")


def setupapi(job, files: list[Path]) -> int:
    out_dir = job.cat_dir("usb")
    raw = out_dir / "setupapi_logs"
    raw.mkdir(exist_ok=True)
    rows = []
    for f in files:
        try:  # drive-prefixed name: the same log from C: and a VSS copy must not overwrite each other
            src_name = f"{f.relative_to(job.files).parts[0]}_{f.name}"
        except ValueError:
            src_name = f.name
        shutil.copy2(f, raw / src_name)
        dev = None
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _DEV.search(line)
                if m:
                    dev = m.group(1).strip()
                    continue
                if dev:
                    s = _SEC.search(line)
                    if s:
                        cls = dev.split("\\", 1)[0]
                        rows.append([s.group(1).replace("/", "-"), cls, dev, src_name])
                        dev = None
    rows.sort()
    out = out_dir / f"{job.host}_SetupAPI_Device_Installs.csv"
    with open(out, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["FirstInstall(LocalTime)", "DeviceClass", "DeviceInstanceId", "SourceLog"])
        w.writerows(rows)
    return len(rows)


# ============================================================================ raw artifact copies
REMOTE_TOOLS = ["TeamViewer", "AnyDesk", "AMMYY", "UltraViewer", "ScreenConnect", "Splashtop", "RustDesk",
                "LogMeIn", "Radmin", "mRemoteNG", "RealVNC", "TightVNC", "UltraVNC", "ZohoMeeting", "ZohoAssist",
                "Atera", "NinjaRMM", "Kaseya", "MeshAgent", "Supremo", "RemotePC", "GoTo", "WinSCP", "MobaXterm",
                "FileZilla", "PuTTY"]


def copy_tree_files(files: Iterable[Path], base: Path, dest: Path) -> int:
    n = 0
    for f in files:
        try:
            rel = f.relative_to(base)
        except ValueError:
            rel = Path(f.name)
        d = dest / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, d)
        n += 1
    return n


# ============================================================================ inventory / gaps
EXPECTED = [
    # name, category, regex on drive-relative posix path, note when missing
    ("$MFT", "fs", r"^\$MFT$", ""),
    ("$UsnJrnl:$J", "fs", r"^\$Extend/\$UsnJrnl_\$J$", "USN journal may be disabled on this volume"),
    ("$LogFile", "fs", r"^\$LogFile$", ""),
    ("$Secure:$SDS", "fs", r"^\$Secure_\$SDS$", ""),
    ("SYSTEM hive", "registry", r"^Windows/System32/config/SYSTEM$", ""),
    ("SOFTWARE hive", "registry", r"^Windows/System32/config/SOFTWARE$", ""),
    ("SAM hive", "registry", r"^Windows/System32/config/SAM$", ""),
    ("SECURITY hive", "registry", r"^Windows/System32/config/SECURITY$", ""),
    ("Hive transaction logs", "registry", r"^Windows/System32/config/(SYSTEM|SOFTWARE)\.LOG[12]$",
     "dirty hives cannot be replayed without .LOG1/.LOG2"),
    ("RegBack hives", "registry", r"^Windows/System32/config/RegBack/", "empty by default since Win10 1803"),
    ("NTUSER.DAT", "registry", r"^Users/[^/]+/NTUSER\.DAT$", ""),
    ("UsrClass.dat", "registry", r"^Users/[^/]+/AppData/Local/Microsoft/Windows/UsrClass\.dat$", ""),
    ("Amcache.hve", "exec", r"^Windows/AppCompat/Programs/Amcache\.hve$", ""),
    ("Prefetch", "exec", r"^Windows/Prefetch/.+\.pf$", "Prefetch disabled (servers/SSD tuning) or not collected"),
    ("PCA launch dictionary (Win11 22H2+)", "exec", r"^Windows/AppCompat/pca/",
     "SANS_Triage glob 'Windows\\appcompat\\pca' has no wildcard -> folder contents not collected. "
     "Add 'Windows\\appcompat\\pca\\*' (PcaAppLaunchDic.txt, PcaGeneralDb0.txt) to the collector."),
    ("SRUM database", "exec", r"^Windows/System32/sru/SRUDB\.dat$", ""),
    ("RecentFileCache.bcf (Win7)", "exec", r"^Windows/AppCompat/Programs/RecentFileCache\.bcf$", "Windows 7 only"),
    ("Syscache.hve", "exec", r"^System Volume Information/Syscache\.hve$", "Win7/2008R2 only"),
    ("PowerShell PSReadLine history", "exec", r"ConsoleHost_history\.txt$", "no PowerShell console history"),
    ("PowerShell transcripts", "exec", r"PowerShell_transcript", "transcription not enabled"),
    ("Event logs (.evtx)", "evtx", r"^Windows/System32/winevt/Logs/.+\.evtx$", ""),
    ("Scheduled Tasks (XML)", "persist", r"^Windows/System32/Tasks/", ""),
    ("WMI repository", "persist", r"^Windows/System32/wbem/Repository/OBJECTS\.DATA$", ""),
    ("Startup folders", "persist", r"Start Menu/Programs/Startup/", "not part of SANS_Triage (see Autoruns results)"),
    ("LNK files", "fileopen", r"\.lnk$", ""),
    ("Jump Lists", "fileopen", r"Destinations-ms$", ""),
    ("ActivitiesCache.db", "fileopen", r"ActivitiesCache\.db$", ""),
    ("Recycle Bin $I", "deleted", r"^\$Recycle\.Bin/.+/\$I", ""),
    ("Recycle Bin $R (content)", "deleted", r"^\$Recycle\.Bin/.+/\$R", "SANS_Triage collects $I metadata only"),
    ("Thumbcache", "deleted", r"thumbcache_.*\.db$", ""),
    ("Chromium history (Chrome/Edge)", "browser", r"/User Data/[^/]+/History$", ""),
    ("Firefox places.sqlite", "browser", r"places\.sqlite$", "Firefox not installed/used"),
    ("WebCacheV01.dat (IE/Legacy Edge)", "browser", r"WebCacheV01\.dat$", ""),
    ("RDP bitmap cache", "remote", r"Terminal Server Client/Cache/", ""),
    ("setupapi.dev.log", "usb", r"^Windows/INF/setupapi\.dev", ""),
    ("SUM / User Access Logging", "network", r"^Windows/System32/LogFiles/SUM/", "Windows Server only"),
    ("Windows Search index", "apps", r"Search/Data/Applications/Windows/Windows\.(edb|db)$", ""),
    ("Defender MPLog", "hunt", r"Windows Defender/Support/MPLog", ""),
    ("Defender DetectionHistory", "hunt", r"Windows Defender/Scans/History/Service/DetectionHistory/",
     "no Defender detections stored (or no access)"),
    ("Hosts file", "network", r"^Windows/System32/drivers/etc/hosts$", "not part of SANS_Triage"),
    ("WER reports", "apps", r"/WER/", ""),
]


def inventory(job, index_fn) -> tuple[list[list], list[str]]:
    rels: dict[str, list[str]] = {letter: [r for r, _ in index_fn(d)] for letter, d in job.layout.drives.items()}
    rows, gaps = [], []
    build = 0
    try:
        build = int(str(job.sysinfo.get("Build", "0")).split(".")[0])
    except ValueError:
        pass
    for name, cat, rx, note in EXPECTED:
        r = re.compile(rx, re.I)
        per = {k: sum(1 for p in v if r.search(p)) for k, v in rels.items()}
        total = sum(per.values())
        where = ", ".join(f"{k}:{n}" for k, n in per.items() if n)
        rows.append([name, cat, total, where, note if not total else ""])
        if not total:
            if name.startswith("PCA") and build and build < 22621:
                continue
            if name.startswith(("RecentFileCache", "Syscache", "RegBack")):
                continue
            gaps.append(f"[MISSING] {name}: {note or 'not present in collection'}")
    # per-volume NTFS metadata
    for letter in rels:
        have = {p for p in rels[letter] if p.startswith("$")}
        for meta in ("$MFT", "$Extend/$UsnJrnl_$J", "$LogFile"):
            if meta not in have and any(x in have for x in ("$MFT", "$Boot")):
                gaps.append(f"[MISSING] {letter}: {meta} not collected for this volume")
    if not any(re.match(r"VSS\d+", k) for k in rels):
        gaps.append("[INFO] No Volume Shadow Copies collected (collector VSS option disabled)")
    return rows, gaps


def velociraptor_meta(meta_dir: Path) -> tuple[dict, list[str]]:
    info, notes = {}, []
    ctx = meta_dir / "collection_context.json"
    if ctx.is_file():
        try:
            c = json.loads(ctx.read_text(encoding="utf-8", errors="replace"))
            req = c.get("request") or {}
            info = {
                "Artifacts collected": ", ".join(str(a) for a in req.get("artifacts") or []),
                "Collector parameters": ", ".join(
                    str(e.get("key", "")) for s in req.get("specs") or []
                    for e in (s.get("parameters") or {}).get("env") or [] if e.get("value") == "Y"),
                "Uploaded files": c.get("total_uploaded_files"),
                "Uploaded bytes": f"{c.get('total_uploaded_bytes') or 0} of "
                                  f"{c.get('total_expected_uploaded_bytes') or 0} expected",
                "Collection duration": f"{(c.get('execution_duration') or 0) / 1e9:.0f}s",
                "Collection state": {2: "FINISHED", 1: "RUNNING", 3: "ERROR"}.get(c.get("state"), c.get("state")),
            }
            if c.get("total_uploaded_bytes") != c.get("total_expected_uploaded_bytes"):
                notes.append("[WARN] Velociraptor uploaded fewer bytes than expected - some files are truncated")
        except (OSError, ValueError, KeyError, TypeError, AttributeError):  # unexpected shapes: report nothing
            info = {}
    log = meta_dir / "log.json"
    if log.is_file():
        errs = []
        with open(log, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        for line in lines:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            m = str(obj.get("message") or "").strip()
            if re.search(r"Unable to open|unable to fall back|error", m, re.I) and "OpenProcess" not in m \
                    and "Collecting file" not in m:
                errs.append(m)
        for e in errs[:50]:
            notes.append(f"[COLLECTOR] {e[:250]}")
        if any("sru" in e.lower() and "Unable to open" in e for e in errs):
            notes.append("[INFO] SRUM transaction logs rotated during collection - SRUDB.dat may be dirty "
                         "(the agent repairs a working copy with esentutl when SrumECmd fails)")
    return info, notes
