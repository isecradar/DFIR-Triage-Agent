"""Linux / Unix triage processing (UAC collections, Velociraptor collections of Linux hosts).

Pure Python - no extra tools are required. `journalctl` (systemd) is used for binary journals when it is
installed on the analysis machine and `mactime` (sleuthkit) for the bodyfile timeline (built-in fallback).

Time stamps: binary records (wtmp/btmp/lastlog, journal, audit, bodyfile) are UTC. Classic syslog lines
carry no year and no time zone; the year is inferred from the log file's modification time and the time is
converted to UTC with the host's time zone (/etc/timezone, /etc/localtime link, timedatectl output). When the
zone is unknown the time stays host-local; every CSV has a TimeZone column that says which one applies.
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import json
import os
import posixpath
import re
import shutil
import socket
import struct
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import postproc
from .config import module_enabled, module_opt
from .engine import Job, SkipTask, Task, TaskWarning

UTC = dt.timezone.utc
TS_FMT = "%Y-%m-%d %H:%M:%S"


# =============================================================================== helpers
def _root(job: Job) -> Path:
    return job.layout.rootfs


def files(job: Job, pattern: str) -> list[Path]:
    """Regular files whose rootfs-relative path matches pattern (case-sensitive). Symlinks are never
    followed: in an unpacked UAC folder they point to absolute paths of the analysis machine."""
    from .modules import file_index
    rx = re.compile(pattern)
    return [p for rel, p in file_index(_root(job)) if rx.search(rel) and not p.is_symlink()]


def uac_files(job: Job, pattern: str) -> list[Path]:
    from .modules import file_index
    if not job.layout.uac or not job.layout.uac.is_dir():
        return []
    rx = re.compile(pattern)
    return [p for rel, p in file_index(job.layout.uac) if rx.search(rel) and not p.is_symlink()]


def rel(job: Job, p: Path) -> str:
    """'/etc/passwd' for a file inside the collected root file system."""
    try:
        return "/" + p.relative_to(_root(job)).as_posix()
    except ValueError:
        return p.as_posix()


def one(job: Job, path: str) -> Path | None:
    """A file of the collected root file system by its original path. Symlinks are followed *inside* the
    collection (recorded links of an extracted archive, or real links of an unpacked UAC folder), never into
    the analysis machine: '/etc/os-release' -> '../usr/lib/os-release' -> <rootfs>/usr/lib/os-release."""
    root = _root(job)
    p = "/" + path.lstrip("/")
    for _ in range(8):
        f = root / p.lstrip("/")
        if f.is_symlink():
            try:
                tgt = os.readlink(f)
            except OSError:
                return None
        elif f.is_file():
            return f
        else:
            tgt = job.layout.symlinks.get(p)
            if tgt is None:
                return None
        p = posixpath.normpath(tgt if tgt.startswith("/") else posixpath.join(posixpath.dirname(p), tgt))
    return None


def open_text(p: Path):
    if p.name.endswith(".gz"):
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, encoding="utf-8", errors="replace")


def read_text(p: Path | None, limit: int = 4 * 1024 * 1024) -> str:
    if not p:
        return ""
    try:
        with open_text(p) as fh:
            return fh.read(limit)
    except (OSError, EOFError, gzip.BadGzipFile):
        return ""


def iter_lines(p: Path) -> Iterator[str]:
    try:
        with open_text(p) as fh:
            for line in fh:
                yield line.rstrip("\r\n")
    except (OSError, EOFError, gzip.BadGzipFile):
        return


def mtime_utc(p: Path) -> str:
    try:
        return dt.datetime.fromtimestamp(p.stat().st_mtime, UTC).strftime(TS_FMT)
    except (OSError, OverflowError, ValueError):
        return ""


def epoch_utc(v) -> str:
    try:
        t = float(v)
        if t <= 0:
            return ""
        return (dt.datetime(1970, 1, 1) + dt.timedelta(seconds=t)).strftime(TS_FMT)
    except (TypeError, ValueError, OverflowError):
        return ""


@contextmanager
def writer(path: Path, header: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="backslashreplace", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        yield w


def _rotation_key(p: Path) -> tuple:
    """auth.log.3.gz, auth.log.2.gz, auth.log.1, auth.log -> oldest first."""
    m = re.search(r"\.(\d+)(\.gz)?$", p.name)
    return (p.parent.as_posix(), re.sub(r"(\.\d+)?(\.gz)?$", "", p.name), -(int(m.group(1)) if m else 0))


# =============================================================================== host clock
class Clock:
    """Converts host-local times to UTC with the evidence host's time zone."""

    def __init__(self, tzname: str):
        self.name = tzname
        self.tz = None
        if tzname:
            try:
                from zoneinfo import ZoneInfo
                self.tz = ZoneInfo(tzname)
            except Exception:  # noqa: BLE001 - unknown zone / no tzdata on the analysis machine
                self.tz = None
        self.local_label = f"host local ({tzname or 'time zone unknown'})"

    def local(self, naive: dt.datetime) -> tuple[str, str]:
        if self.tz is None:
            return naive.strftime(TS_FMT), self.local_label
        try:
            return naive.replace(tzinfo=self.tz).astimezone(UTC).strftime(TS_FMT), "UTC"
        except (OverflowError, ValueError):
            return naive.strftime(TS_FMT), self.local_label

    def ref_local(self, p: Path) -> dt.datetime:
        """File modification time as naive host-local time (reference for syslog year inference)."""
        ts = p.stat().st_mtime
        if self.tz is not None:
            return dt.datetime.fromtimestamp(ts, self.tz).replace(tzinfo=None)
        return dt.datetime.fromtimestamp(ts, UTC).replace(tzinfo=None)


def clock(job: Job) -> Clock:
    c = getattr(job, "_lx_clock", None)
    if c is None:
        c = Clock(job.sysinfo.get("TimeZone", "") or detect_timezone(job))
        job._lx_clock = c
    return c


def detect_timezone(job: Job) -> str:
    tz = read_text(one(job, "/etc/timezone")).strip().splitlines()
    if tz and tz[0].strip():
        return tz[0].strip()
    link = job.layout.symlinks.get("/etc/localtime", "")
    if "zoneinfo/" in link:
        return link.split("zoneinfo/", 1)[1].strip("/")
    m = re.search(r'^ZONE="?([^"\n]+)"?', read_text(one(job, "/etc/sysconfig/clock")), re.M)
    if m:
        return m.group(1).strip()
    for p in uac_files(job, r"^live_response/system/[^/]*timedatectl[^/]*$"):
        m = re.search(r"Time zone:\s*(\S+)", read_text(p))
        if m:
            return m.group(1)
    return ""


# =============================================================================== syslog
_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_CLASSIC = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<t>\d{2}:\d{2}:\d{2})(?:\.\d+)? "
                      r"(?P<host>\S+) (?P<rest>.*)$")
_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?(?P<tz>Z|[+-]\d{2}:?\d{2})? "
                  r"(?P<host>\S+) (?P<rest>.*)$")
_PROC = re.compile(r"^(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")


class SyslogParser:
    def __init__(self, clk: Clock, ref: dt.datetime):
        self.clk, self.ref = clk, ref

    def parse(self, line: str) -> tuple | None:
        """-> (timestamp, tz label, host, process, pid, message) or None."""
        m = _CLASSIC.match(line)
        if m:
            mon = _MONTHS.get(m.group("mon"))
            if not mon:
                return None
            h, mi, s = (int(x) for x in m.group("t").split(":"))
            when = None
            for y in range(self.ref.year, self.ref.year - 5, -1):  # year is not logged: newest plausible year
                try:
                    cand = dt.datetime(y, mon, int(m.group("day")), h, mi, s)
                except ValueError:  # Feb 29 in a non-leap year
                    continue
                if cand <= self.ref + dt.timedelta(days=2):
                    when = cand
                    break
            if when is None:
                return None
            ts, tzl = self.clk.local(when)
        else:
            m = _ISO.match(line)
            if not m:
                return None
            try:
                base = dt.datetime.fromisoformat(m.group("ts").replace(" ", "T"))
            except ValueError:
                return None
            tz = m.group("tz")
            if tz:
                tz = "+00:00" if tz == "Z" else (tz if ":" in tz else f"{tz[:3]}:{tz[3:]}")
                try:
                    off = dt.datetime.fromisoformat("2000-01-01T00:00:00" + tz).utcoffset()
                    ts, tzl = (base - off).strftime(TS_FMT), "UTC"
                except (ValueError, TypeError, OverflowError):
                    ts, tzl = self.clk.local(base)
            else:
                ts, tzl = self.clk.local(base)
        pm = _PROC.match(m.group("rest"))
        if pm:
            return ts, tzl, m.group("host"), pm.group("proc"), pm.group("pid") or "", pm.group("msg")
        return ts, tzl, m.group("host"), "", "", m.group("rest")


# (process prefix or None = any, regex on the message, event type)
AUTH_RULES = [
    ("sshd", re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     "SSH_LOGIN_SUCCESS"),
    ("sshd", re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) "
                        r"port (?P<port>\d+)"), "SSH_LOGIN_FAILED"),
    ("sshd", re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"), "SSH_INVALID_USER"),
    ("sshd", re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) "
                        r"from (?P<ip>\S+) port (?P<port>\d+)"), "SSH_MAX_AUTH_EXCEEDED"),
    ("sshd", re.compile(r"^Disconnected from user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"), "SSH_LOGOUT"),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : (?:(?P<fail>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
                        r"USER=(?P<target>\S+) ;(?: [A-Z]+=[^;]* ;)* COMMAND=(?P<cmd>.*)$"), "SUDO_COMMAND"),
    ("sudo", re.compile(r"pam_unix\(sudo(?:-i)?:auth\): authentication failure;.*?ruser=(?P<user>\S*)"),
     "SUDO_AUTH_FAILURE"),
    ("su", re.compile(r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>[^\s(]+)"
                      r"(?:\(uid=\d+\))? by (?P<user>[^\s(]*)"), "SU_SESSION"),
    ("su", re.compile(r"^(?:Successful su for (?P<target>\S+) by (?P<user>\S+)|\(to (?P<target2>\S+)\) "
                      r"(?P<user2>\S+) on)"), "SU"),
    ("su", re.compile(r"^FAILED su for (?P<target>\S+) by (?P<user>\S+)"), "SU_FAILED"),
    ("useradd", re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)"), "USER_CREATED"),
    ("groupadd", re.compile(r"^new group: name=(?P<user>[^,]+), GID=(?P<uid>\d+)"), "GROUP_CREATED"),
    ("usermod", re.compile(r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<target>[^']+)'"), "USER_ADDED_TO_GROUP"),
    ("useradd", re.compile(r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<target>[^']+)'"), "USER_ADDED_TO_GROUP"),
    ("usermod", re.compile(r"^change user '(?P<user>[^']+)'"), "USER_MODIFIED"),
    ("userdel", re.compile(r"^delete user '(?P<user>[^']+)'"), "USER_DELETED"),
    ("passwd", re.compile(r"password changed for (?P<user>\S+)"), "PASSWORD_CHANGED"),
    ("chpasswd", re.compile(r"password changed for (?P<user>\S+)"), "PASSWORD_CHANGED"),
    ("systemd-logind", re.compile(r"^New session (?P<session>\S+) of user (?P<user>\S+)"), "SESSION_START"),
    (None, re.compile(r"pam_unix\((?P<svc>[^:]+):auth\): authentication failure;.*?rhost=(?P<ip>\S*)"
                      r"(?:\s+user=(?P<user>\S*))?"), "AUTH_FAILURE"),
]
AUTH_HEADER = ["Timestamp", "TimeZone", "EventType", "User", "TargetUser", "SourceIP", "Port", "Method",
               "Command", "Process", "PID", "Host", "Message", "SourceLog"]


def auth_event(proc: str, msg: str) -> tuple[str, dict] | None:
    for rp, rx, ev in AUTH_RULES:
        if rp and not proc.startswith(rp):  # sshd also logs as 'sshd-session' (OpenSSH 9.8+)
            continue
        if rp is None and proc.startswith(("sudo", "su")):
            continue  # handled by the specific rules above
        m = rx.search(msg)
        if m:
            g = {k: v for k, v in m.groupdict().items() if v}
            g["user"] = g.get("user") or g.get("user2", "")
            g["target"] = g.get("target") or g.get("target2", "")
            if ev == "SUDO_COMMAND" and g.get("fail"):
                ev = "SUDO_DENIED"
            return ev, g
    return None


def auth_row(ts, tzl, host, proc, pid, msg, src, ev, g) -> list:
    return [ts, tzl, ev, g.get("user", ""), g.get("target", ""), g.get("ip", ""), g.get("port", ""),
            g.get("method", "") or g.get("svc", ""), g.get("cmd", ""), proc, pid, host, msg[:1000], src]


# =============================================================================== suspicious command rules
CMD_RULES = [
    (re.compile(r"\b(curl|wget|fetch)\b[^|;]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b"), "download piped to shell"),
    (re.compile(r"/dev/(tcp|udp)/"), "bash /dev/tcp network redirection (reverse shell)"),
    (re.compile(r"\bnc(at)?\b[^|;]*\s-[a-z]*[ec]\b|\bncat\b.*--(exec|sh-exec)|\bsocat\b.*\bexec:"), "netcat/socat exec"),
    (re.compile(r"\bmkfifo\b.*\bnc\b|\bnc\b.*\bmkfifo\b"), "named-pipe reverse shell"),
    (re.compile(r"\bbase64\s+(-d|--decode)\b|\bbase64 -di\b|\|\s*base64\s+-d"), "base64 decode"),
    (re.compile(r"\bpython[23]?(\.\d+)?\s+-c\s.*\b(socket|pty\.spawn|subprocess|os\.dup2)"), "python one-liner shell"),
    (re.compile(r"\bperl\s+-e\s.*\b(socket|exec)\b|\bphp\s+-r\s|\bruby\s+-rsocket"), "scripting one-liner"),
    (re.compile(r"(^|[\s'\"=;|&])/(tmp|dev/shm|var/tmp|run/shm)/"), "uses world-writable dir (/tmp, /dev/shm)"),
    (re.compile(r"\bchmod\s+(-R\s+)?(\+x|[ugoa]*\+[rw]*[xs]|[0-7]?[0-7]?7[0-7]{2}|[2467][0-7]{3})\b"), "chmod exec/SUID"),
    (re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|HISTSIZE=0|\bset \+o history\b"),
     "shell history tampering"),
    (re.compile(r"\b(rm|shred|truncate|>\s*)\s*.*(/var/log/|\.bash_history|wtmp|btmp|lastlog|audit\.log)"),
     "log / history deletion"),
    (re.compile(r"\b(useradd|adduser|usermod|userdel|passwd|chpasswd|groupadd|gpasswd)\b"), "account change"),
    (re.compile(r"\bcrontab\s|/etc/cron|/var/spool/cron|systemctl\s+(--user\s+)?(enable|daemon-reload)|"
                r"/etc/systemd/system|\.config/systemd|/etc/rc\.local|/etc/init\.d/|\bat\s+now\b"), "persistence setup"),
    (re.compile(r"authorized_keys"), "SSH authorized_keys change"),
    (re.compile(r"\b(insmod|modprobe|rmmod)\b|/etc/ld\.so\.preload|\bLD_PRELOAD="), "kernel module / preload"),
    (re.compile(r"\b(iptables\s+-F|ufw\s+disable|setenforce\s+0|systemctl\s+(stop|disable|mask)\s+\S*"
                r"(auditd|firewalld|apparmor|rsyslog|syslog|falcon|sentinel|clamav))"), "defence tampering"),
    (re.compile(r"\b(nmap|masscan|zmap|hydra|medusa|john|hashcat|mimipenguin|linpeas|linenum|pspy|chisel|ngrok|"
                r"frpc|frps|gost|xmrig|kinsing|kdevtmpfsi|tsunami|sliver|meterpreter|msfvenom|cobaltstrike|"
                r"rclone|megacmd|ligolo)\b", re.I), "offensive / miner / exfil tool"),
    (re.compile(r"\b(tar|zip|7z|rar)\b[^|;]*\s/(etc|home|root|var/www)\b.*\b(curl|nc|scp|rclone)\b"), "archive + exfil"),
    (re.compile(r"\bcat\s+[^|;]*/etc/shadow|\bunshadow\b"), "credential access (/etc/shadow)"),
    (re.compile(r"\b(docker|ctr|kubectl)\s+.*(--privileged|-v\s+/:/|hostPID|nsenter)"), "container escape"),
]


def suspicious(text: str, skip: tuple = ()) -> str:
    return "; ".join(dict.fromkeys(why for rx, why in CMD_RULES if why not in skip and rx.search(text)))


# =============================================================================== accounts
def users(job: Job) -> list[dict]:
    cached = getattr(job, "_lx_users", None)
    if cached is not None:
        return cached
    out = []
    for line in read_text(one(job, "/etc/passwd")).splitlines():
        f = line.split(":")
        if len(f) >= 7 and not line.startswith("#"):
            out.append({"user": f[0], "uid": f[2], "gid": f[3], "gecos": f[4], "home": f[5], "shell": f[6]})
    job._lx_users = out
    return out


def user_of(job: Job, path: str) -> str:
    """Owner of a home-directory path ('/home/bob/.bashrc' -> 'bob')."""
    best = ("", "")
    for u in users(job):
        h = u["home"].rstrip("/")
        if h and h != "/" and (path == h or path.startswith(h + "/")) and len(h) > len(best[0]):
            best = (h, u["user"])
    if best[1]:
        return best[1]
    m = re.match(r"^/(?:home|Users)/([^/]+)/|^/(root)/", path)
    return (m.group(1) or m.group(2)) if m else ""


_INTERACTIVE = re.compile(r"/(ba|z|k|c|tc|da|a|fi)?sh$|/(bash|zsh|ksh|fish|tcsh|csh|dash|ash)$")
_PRIV_GROUPS = {"root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "lxc", "libvirt", "disk", "shadow"}


def _hash_type(h: str) -> str:
    if h == "":
        return "EMPTY (no password!)"
    if h.startswith(("!", "*")):
        return "locked/disabled" + (" (has hash)" if len(h) > 2 else "")
    m = re.match(r"^\$(\w+)\$", h)
    return {"1": "MD5-crypt (weak)", "5": "SHA-256-crypt", "6": "SHA-512-crypt", "y": "yescrypt",
            "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt", "gy": "gost-yescrypt"}.get(
        m.group(1) if m else "", "DES/unknown (weak)" if len(h) == 13 else "unknown")


def _days(v: str) -> str:
    try:
        d = int(v)
        return (dt.date(1970, 1, 1) + dt.timedelta(days=d)).isoformat() if d > 0 else ""
    except (ValueError, OverflowError):
        return ""


def task_accounts(job: Job, t: Task):
    us = users(job)
    if not us:
        raise SkipTask("/etc/passwd not collected")
    shadow = {}
    for line in read_text(one(job, "/etc/shadow")).splitlines():
        f = line.split(":")
        if len(f) >= 8:
            shadow[f[0]] = f
    groups: dict[str, set] = {}
    gid_name = {}
    for line in read_text(one(job, "/etc/group")).splitlines():
        f = line.split(":")
        if len(f) >= 4:
            gid_name[f[2]] = f[0]
            for mem in filter(None, f[3].split(",")):
                groups.setdefault(mem.strip(), set()).add(f[0])
    uid_count: dict[str, int] = {}
    for u in us:
        uid_count[u["uid"]] = uid_count.get(u["uid"], 0) + 1
    sudoers = "\n".join(read_text(p) for p in [one(job, "/etc/sudoers")] + files(job, r"^etc/sudoers\.d/") if p)
    passwd_pw = {f[0]: f[1] for f in (l.split(":") for l in read_text(one(job, "/etc/passwd")).splitlines())
                 if len(f) >= 7}
    out = job.cat_dir("account") / job.name("Users")
    flagged = 0
    with writer(out, ["User", "UID", "GID", "PrimaryGroup", "Groups", "Home", "Shell", "InteractiveShell",
                      "PasswordHash", "PasswordLastChanged", "AccountExpires", "Privileged", "InSudoers",
                      "GECOS", "Suspicious"]) as w:
        for u in us:
            sh = shadow.get(u["user"])
            grp = sorted(groups.get(u["user"], set()))
            prim = gid_name.get(u["gid"], u["gid"])
            interactive = bool(_INTERACTIVE.search(u["shell"]))
            priv = u["uid"] == "0" or bool(_PRIV_GROUPS & set(grp + [prim]))
            in_sudoers = bool(re.search(rf"^\s*{re.escape(u['user'])}\s", sudoers, re.M))
            why = []
            if u["uid"] == "0" and u["user"] != "root":
                why.append("UID 0 (root equivalent)")
            if uid_count[u["uid"]] > 1:
                why.append("duplicate UID")
            pw_field = passwd_pw.get(u["user"], "x")
            if pw_field not in ("x", "*", "!"):  # legacy: hash (or nothing) directly in /etc/passwd
                htype = "hash in /etc/passwd!" if pw_field else "EMPTY (no password!)"
            else:
                htype = _hash_type(sh[1]) if sh else ""
            if htype.startswith(("EMPTY", "hash in")):
                why.append("no/legacy password")
            try:
                uid = int(u["uid"])
            except ValueError:
                uid = -1
            if interactive and 0 < uid < 1000 and u["user"] not in ("sync",) and not htype.startswith("locked"):
                why.append("system account with login shell")
            if why:
                flagged += 1
            w.writerow([u["user"], u["uid"], u["gid"], prim, ",".join(grp), u["home"], u["shell"],
                        "yes" if interactive else "no", htype, _days(sh[2]) if sh else "",
                        _days(sh[7]) if sh else "", "yes" if priv else "", "yes" if in_sudoers else "",
                        u["gecos"], "; ".join(why)])
    return f"{len(us)} accounts, {flagged} flagged" + ("" if shadow else " (no /etc/shadow)")


# =============================================================================== login records
_UTMP = struct.Struct("<hhi32s4s32s256shhiii16s20s")  # glibc x86_64/aarch64: 384 bytes
_UT_TYPES = {1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME", 5: "INIT_PROCESS",
             6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING"}


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


def _ip(raw: bytes) -> str:
    if not any(raw):
        return ""
    try:
        return socket.inet_ntop(socket.AF_INET, raw[:4]) if not any(raw[4:]) else socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return ""


def parse_utmp(p: Path) -> Iterator[list]:
    data = p.read_bytes() if not p.name.endswith(".gz") else gzip.decompress(p.read_bytes())
    if len(data) % _UTMP.size:
        raise ValueError(f"{p.name}: size is not a multiple of 384 bytes (not glibc x86_64/aarch64 utmp)")
    for off in range(0, len(data), _UTMP.size):
        (typ, _pad, pid, line, _id, user, host, _t, _e, sess, sec, usec, addr, _u) = _UTMP.unpack_from(data, off)
        if typ == 0:
            continue
        yield [epoch_utc(sec), _UT_TYPES.get(typ, str(typ)), _cstr(user), _cstr(line), _cstr(host), _ip(addr),
               pid, sess]


def task_logins(job: Job, t: Task):
    recs = files(job, r"^var/(log|run)/(wtmp|btmp|utmp)(\.\d+|-\d{8})?(\.gz)?$") + \
        files(job, r"^run/utmp$")
    lastlog = one(job, "/var/log/lastlog")
    if not recs and not lastlog:
        raise SkipTask("no wtmp/btmp/utmp/lastlog collected")
    out = job.cat_dir("account")
    n, bad = 0, []
    with writer(out / job.name("Logins"), ["Timestamp", "TimeZone", "Source", "RecordType", "User", "Terminal",
                                            "Host", "IP", "PID", "Session", "Meaning"]) as w:
        for p in sorted(recs, key=_rotation_key):
            src = re.sub(r"(\.\d+|-\d{8})?(\.gz)?$", "", p.name)
            meaning = {"btmp": "FAILED login attempt", "wtmp": "login/logout/boot history",
                       "utmp": "currently logged in (at collection time)"}.get(src, "")
            try:
                for r in parse_utmp(p):
                    w.writerow([r[0], "UTC", rel(job, p)] + r[1:] + [meaning])
                    n += 1
            except (ValueError, OSError, EOFError) as e:
                bad.append(str(e))
    nl = 0
    if lastlog:
        names = {u["uid"]: u["user"] for u in users(job)}
        rec = struct.Struct("<i32s256s")  # 292 bytes per UID
        with writer(out / job.name("LastLog"), ["User", "UID", "LastLogin", "TimeZone", "Terminal", "Host"]) as w, \
                open(lastlog, "rb") as fh:
            uid = 0
            limit = 512 * 1024 * 1024  # sparse file: UID * 292 bytes - stop at very high UIDs
            while fh.tell() < limit:
                b = fh.read(rec.size * 4096)
                if not b:
                    break
                for off in range(0, len(b) - rec.size + 1, rec.size):
                    tm, line, host = rec.unpack_from(b, off)
                    if tm > 0:
                        w.writerow([names.get(str(uid), ""), uid, epoch_utc(tm), "UTC", _cstr(line), _cstr(host)])
                        nl += 1
                    uid += 1
    msg = f"{n:,} login records, {nl} lastlog entries"
    if bad:
        raise TaskWarning(msg + " - " + "; ".join(bad))
    return msg


# =============================================================================== syslog / auth
SYSLOG_RX = (r"^var/log/(syslog|messages|kern\.log|daemon\.log|user\.log|cron|cron\.log|maillog|mail\.log|"
             r"auth\.log|secure|boot\.log|ufw\.log|firewalld|sudo\.log)(\.\d+|-\d{8})?(\.gz)?$")
AUTH_FILE_RX = re.compile(r"^(auth\.log|secure|sudo\.log)")


def task_syslog(job: Job, t: Task):
    logs = sorted(files(job, SYSLOG_RX), key=_rotation_key)
    if not logs:
        raise SkipTask("no text syslog files (journald-only host?)")
    clk = clock(job)
    ev_dir = job.cat_dir("evtx")
    timeline = postproc._SortedSpill(ev_dir, key=lambda r: r[0])
    na = unparsed = 0
    with writer(job.cat_dir("account") / job.name("Auth_Events"), AUTH_HEADER) as aw:
        for i, p in enumerate(logs):
            t.progress, t.detail = i / len(logs), rel(job, p)
            parser = SyslogParser(clk, clk.ref_local(p))
            src = rel(job, p)
            authfile = bool(AUTH_FILE_RX.match(p.name))
            for line in iter_lines(p):
                r = parser.parse(line)
                if r is None:
                    if line.strip():
                        unparsed += 1
                    continue
                ts, tzl, host, proc, pid, msg = r
                timeline.append([ts, tzl, host, proc, pid, msg[:4000], src])
                if authfile or proc.startswith(("sshd", "sudo", "su", "useradd", "usermod", "userdel", "groupadd",
                                                "passwd", "chpasswd", "systemd-logind")):
                    a = auth_event(proc, msg)
                    if a:
                        aw.writerow(auth_row(ts, tzl, host, proc, pid, msg, src, *a))
                        na += 1
    with writer(ev_dir / job.name("Syslog_Timeline"), ["Timestamp", "TimeZone", "Host", "Process", "PID",
                                                         "Message", "SourceLog"]) as w:
        timeline.write_sorted(w)
    note = "" if clk.tz else f" (time zone unknown - times are {clk.local_label})"
    return f"{timeline.n:,} lines from {len(logs)} logs, {na:,} auth events, {unparsed:,} unparsed{note}"


def task_journal(job: Job, t: Task):
    jfiles = files(job, r"^(var/log|run/log)/journal/.+\.journal~?$")
    if not jfiles:
        raise SkipTask("no systemd journal files collected")
    jc = shutil.which("journalctl")
    if not jc:
        raise SkipTask("journalctl not installed on the analysis machine (apt install systemd) - "
                       f"{len(jfiles)} journal files left unparsed")
    stage = job.work / "_staging" / "journal"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    out_dir = job.cat_dir("evtx")
    n = na = 0
    dirs = sorted({p.parent for p in jfiles})
    export = journal_export(job)  # syslog-format text copy for ChopChopGo (it cannot read journal files offline)
    export.parent.mkdir(parents=True, exist_ok=True)
    with writer(out_dir / job.name("Journal"), ["Timestamp", "TimeZone", "Host", "Identifier", "PID", "UID",
                                                 "Comm", "Exe", "Unit", "Priority", "Message", "SourceDir"]) as w, \
            writer(job.cat_dir("account") / job.name("Auth_Events_Journal"), AUTH_HEADER) as aw, \
            open(export, "w", encoding="utf-8", errors="backslashreplace") as xf:
        for i, d in enumerate(dirs):
            t.progress = i / len(dirs)
            js = stage / f"j{i}.json"
            job.run(t, [jc, "--directory", str(d), "-o", "json", "--no-pager", "-q"], stdout_file=js,
                    log_name="journalctl", ok_codes=(0, 1))
            src = rel(job, d)
            t.detail = f"converting {src}"
            with open(js, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(e, dict):
                        continue
                    msg = e.get("MESSAGE", "")
                    if isinstance(msg, list):  # binary message: list of byte values
                        msg = bytes(x for x in msg if isinstance(x, int) and 0 <= x < 256).decode("utf-8", "replace")
                    msg = str(msg or "")
                    try:
                        ts = epoch_utc(int(e.get("__REALTIME_TIMESTAMP", 0)) / 1e6)
                    except (TypeError, ValueError):
                        ts = ""
                    ident = str(e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or "")
                    host, pid = str(e.get("_HOSTNAME", "")), str(e.get("_PID") or e.get("SYSLOG_PID") or "")
                    w.writerow([ts, "UTC", host, ident, pid, e.get("_UID", ""), e.get("_COMM", ""), e.get("_EXE", ""),
                                e.get("_SYSTEMD_UNIT", ""), e.get("PRIORITY", ""), msg[:4000], src])
                    if ts:
                        xf.write(f"{ts.replace(' ', 'T')}+0000 {host or '-'} {ident or '-'}"
                                 f"{f'[{pid}]' if pid else ''}: {msg.replace(chr(10), ' ')}\n")
                    n += 1
                    a = auth_event(ident, msg)
                    if a:
                        aw.writerow(auth_row(ts, "UTC", host, ident, pid, msg, src, *a))
                        na += 1
            js.unlink(missing_ok=True)
    shutil.rmtree(stage, ignore_errors=True)
    return f"{n:,} journal entries from {len(jfiles)} files, {na:,} auth events"


def journal_export(job: Job) -> Path:
    return job.work / "journal_export" / "journal_syslog.log"


# =============================================================================== Sigma hunting (Linux)
SIGMA_HEADER = ["Timestamp", "TimeZone", "Level", "RuleTitle", "RuleID", "Tags", "Details", "Engine", "SourceLog"]


def _stage(job: Job, name: str) -> Path:
    d = job.work / "_staging" / name
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    return d


def _plain_copy(src: Path, dst: Path) -> Path:
    """Decompress .gz, else hard-link (no extra disk space) or copy."""
    if src.name.endswith(".gz"):
        dst = dst.with_name(dst.name[:-3])
        with gzip.open(src, "rb") as s, open(dst, "wb") as d:
            shutil.copyfileobj(s, d, 4 << 20)
        return dst
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)
    return dst


def _keyword_literals(rules_dir: Path) -> list[str] | None:
    """Every literal string of every rule's detection lists. A line can only match a keyword rule when it
    contains at least one of them, so filtering on them changes nothing in the result. Returns None (no
    pre-filter, full scan) as soon as a rule uses field selections or anything else not understood here."""
    import fnmatch
    import yaml

    def literal(s) -> str:
        seg = max(re.split(r"(?<!\\)[*?]", str(s)), key=len)
        return seg.replace("\\*", "*").replace("\\?", "?")

    lits: set[str] = set()
    for f in rules_dir.rglob("*.yml"):
        try:
            det = (yaml.safe_load(f.read_text(encoding="utf-8", errors="replace")) or {}).get("detection") or {}
        except yaml.YAMLError:
            return None
        cond = str(det.get("condition", "")).strip()
        blocks: dict[str, list[str]] = {}  # name -> literals; a line matching the block contains one of them
        for k, v in det.items():
            if k in ("condition", "timeframe"):
                continue
            if isinstance(v, dict) and set(v) == {"|all"} and isinstance(v["|all"], list):
                vals = [literal(s) for s in v["|all"]]  # every item must match -> the longest one alone suffices
                blocks[k] = [max(vals, key=len)] if vals else []
            elif isinstance(v, list) and all(isinstance(s, (str, int)) for s in v):
                blocks[k] = [literal(s) for s in v]  # any item may match -> all of them
            else:
                return None  # field selections etc.: no safe pre-filter
        if not cond or any(not x for b in blocks.values() for x in b):
            return None
        if re.search(r"\bor\b|\b1 of\b|\bany of\b|\(|\|", cond):
            needed = [n for n in blocks if not re.search(rf"\bnot\s+{re.escape(n)}\b", cond)]  # union is safe
        else:  # AND of terms: any one positive term is required -> use the most selective
            pos = []
            for term in (x.strip() for x in cond.split(" and ")):
                if term.startswith("not "):
                    continue
                m = re.fullmatch(r"all of (\S+)", term)
                names = fnmatch.filter(blocks, m.group(1)) if m else ([term] if term in blocks else None)
                if not names:
                    return None
                pos += names
            if not pos:
                return None
            needed = [max(pos, key=lambda n: min(len(x) for x in blocks[n]))]
        for n in needed:
            lits.update(blocks[n])
    return sorted(lits) or None


def _count_lines(p: Path) -> int:
    n = 0
    with open(p, "rb") as fh:
        while b := fh.read(16 << 20):
            n += b.count(b"\n")
    return n


def _filter_lines(src: Path, dst: Path, lits: list[str]) -> tuple[int, int]:
    """Lines of src containing any literal (case-insensitive) -> dst. Returns (kept, total).
    GNU `grep -F` (multi-string matcher) is used when available - far faster than Python regex on GB-sized
    journal exports; the Python loop is the fallback."""
    plain = src
    if src.name.endswith(".gz"):
        plain = _plain_copy(src, dst.with_name(dst.name + ".src.gz"))
    grep = shutil.which("grep")
    try:
        if grep:
            pats = dst.with_name(dst.name + ".patterns")
            pats.write_bytes(b"\n".join(x.encode() for x in lits) + b"\n")
            with open(dst, "wb") as out:
                r = subprocess.run([grep, "-F", "-i", "-a", "-f", str(pats), str(plain)], stdout=out,
                                   stderr=subprocess.DEVNULL, env={**os.environ, "LC_ALL": "C"})
            pats.unlink(missing_ok=True)
            if r.returncode in (0, 1):  # 1 = no line matched
                return _count_lines(dst), _count_lines(plain)
        rx = re.compile(b"|".join(re.escape(x.encode()) for x in lits), re.I)
        kept = n = 0
        with open(plain, "rb") as s, open(dst, "wb") as d:
            for line in s:
                n += 1
                if rx.search(line):
                    d.write(line)
                    kept += 1
        return kept, n
    finally:
        if plain is not src:
            plain.unlink(missing_ok=True)


def _split_lines(p: Path, prefix: Path, chunk: int) -> list[Path]:
    """[p] when small, else pieces of ~chunk bytes cut at line boundaries (prefix.000, prefix.001, ...)."""
    if p.stat().st_size <= chunk:
        return [p]
    parts, n = [], 0
    with open(p, "rb") as src:
        while True:
            part = prefix.with_name(f"{prefix.name}.{n:03d}.log")
            written = 0
            with open(part, "wb") as dst:
                for line in src:
                    dst.write(line)
                    written += len(line)
                    if written >= chunk:
                        break
            if not written:
                part.unlink()
                break
            parts.append(part)
            n += 1
    return parts


def _rule_levels(rules_dir: Path) -> dict[str, str]:
    """Sigma rule id -> level from the rule YAML files (simple field scan, no YAML parser needed)."""
    out = {}
    for f in rules_dir.rglob("*.yml"):
        txt = read_text(f, 65536)
        i, lv = re.search(r"^id:\s*(\S+)", txt, re.M), re.search(r"^level:\s*(\S+)", txt, re.M)
        if i and lv:
            out[i.group(1).strip("'\"")] = lv.group(1)
    return out


def task_chopchopgo(job: Job, t: Task):
    """ChopChopGo (the Linux counterpart of Chainsaw): Sigma 'builtin' rules on syslog-format logs and on the
    text export of the collected systemd journal."""
    tb = job.tb
    if not tb.chopchopgo.exists():
        raise SkipTask("ChopChopGo not installed (setup.sh)")
    logs = sorted(files(job, SYSLOG_RX), key=_rotation_key)
    exp = journal_export(job)
    if exp.is_file() and exp.stat().st_size:
        logs.append(exp)
    if not logs:
        raise SkipTask("no syslog-format logs and no journal export")
    stage = _stage(job, "chopchopgo")
    clk = clock(job)
    rows, per_rule = [], {}
    levels = _rule_levels(tb.chopchopgo_rules)  # ChopChopGo's output has no severity - take it from the rule
    # ChopChopGo is single-threaded (~0.5 MB/s with all rules): big logs (a journal export can be GBs) are split
    # at line boundaries and the pieces are scanned in parallel
    chunk = int(module_opt(job.cfg, "chopchopgo", "chunk_mb", 64)) * 1024 * 1024
    par = max(1, int(module_opt(job.cfg, "chopchopgo", "parallel", 0)) or min(8, max(2, (os.cpu_count() or 4) // 2)))
    lits = _keyword_literals(tb.chopchopgo_rules)
    prefilter = lits or None
    work: list[tuple[Path, Path, str]] = []  # (file to scan, original log, label)
    kept = total = 0
    for i, p in enumerate(logs):
        src = "journal (export)" if p == exp else rel(job, p)
        t.detail = f"preparing {src}"
        if prefilter is not None:  # keep only lines that can match any rule -> identical detections, far less input
            plain = stage / f"{i}_filtered.log"
            k, n = _filter_lines(p, plain, prefilter)
            kept, total = kept + k, total + n
            if k:
                work.append((plain, p, src))
            continue
        plain = p if not p.name.endswith(".gz") else _plain_copy(p, stage / f"{i}_{p.name}")
        work += [(c, p, src) for c in _split_lines(plain, stage / f"{i}_part", chunk)]
    if prefilter is not None:
        job.log(f"[{t.key}] keyword pre-filter ({len(lits)} rule literals): {kept:,} of {total:,} lines scanned")
    done = [0]
    lock = threading.Lock()

    def scan(item):
        f, _orig, src = item
        out = f.with_suffix(f.suffix + ".json")
        job.run(t, [str(tb.chopchopgo), "-target", "syslog", "-file", str(f), "-rules", str(tb.chopchopgo_rules),
                    "-out", "json"], cwd=tb.chopchopgo.parent, stdout_file=out, log_name="chopchopgo", ok_codes=None)
        with lock:
            done[0] += 1
            t.progress, t.detail = done[0] / len(work), f"{done[0]}/{len(work)} pieces ({par} in parallel) - {src}"
        return out

    with ThreadPoolExecutor(max_workers=par) as ex:
        outs = list(ex.map(scan, work)) if work else []
    for (f, p, src), out in zip(work, outs):
        try:
            hits = json.loads(out.read_text(encoding="utf-8", errors="replace") or "null") or []
        except (ValueError, OSError):
            job.log(f"[{t.key}] unreadable ChopChopGo output for {src} ({f.name})", "warn")
            continue
        parser = SyslogParser(clk, clk.ref_local(p))
        for h in hits if isinstance(hits, list) else []:
            if not isinstance(h, dict):
                continue
            raw_ts, msg = str(h.get("Timestamp", "")), str(h.get("Message", ""))
            r = parser.parse(f"{raw_ts} - {msg}")  # rebuild a syslog line -> UTC like every other CSV
            ts, tzl = (r[0], r[1]) if r else (raw_ts, "as logged")
            title = str(h.get("Title", ""))
            per_rule[title] = per_rule.get(title, 0) + 1
            rows.append([ts, tzl, levels.get(str(h.get("ID", "")), ""), title, h.get("ID", ""),
                         ", ".join(h.get("Tags") or []), msg[:4000], "ChopChopGo", src])
    shutil.rmtree(stage, ignore_errors=True)
    rows.sort(key=lambda r: r[0])
    with writer(job.cat_dir("hunt") / job.name("Sigma_ChopChopGo"), SIGMA_HEADER) as w:
        w.writerows(rows)
    top = ", ".join(f"{k} ({v})" for k, v in sorted(per_rule.items(), key=lambda kv: -kv[1])[:3])
    scanned = f", {kept:,}/{total:,} lines matched a rule keyword" if prefilter is not None else ""
    return (f"{len(rows):,} detections, {len(per_rule)} rules from {len(logs)} logs{scanned}"
            + (f" - {top}" if top else ""))


def task_zircolite(job: Job, t: Task):
    """Zircolite: SigmaHQ Linux rules on auditd logs (and Sysmon for Linux events when present)."""
    tb = job.tb
    if not tb.zircolite.exists():
        raise SkipTask("Zircolite not installed (setup.sh)")
    if not tb.zircolite_rules.is_file():
        raise SkipTask(f"Zircolite Linux ruleset missing ({tb.zircolite_rules})")
    audit = files(job, r"^var/log/audit/audit\.log(\.\d+)?(\.gz)?$")
    sysmon = [p for p in files(job, SYSLOG_RX) if "Linux-Sysmon" in read_text(p, 8 * 1024 * 1024)]
    if not audit and not sysmon:
        raise SkipTask("no auditd logs or Sysmon for Linux events (Sigma Linux rules need one of them)")
    hunt = job.cat_dir("hunt")
    raw_dir = hunt / "Zircolite"
    raw_dir.mkdir(exist_ok=True)
    rows, per_rule, runs = [], {}, []
    for kind, srcs, flag, pattern in (("auditd", audit, "-AU", "audit.log*"), ("sysmon", sysmon, "-S", "*")):
        if not srcs:
            continue
        stage = _stage(job, f"zircolite_{kind}")
        origin = {}  # staged file name -> path in the evidence
        for i, p in enumerate(srcs):
            staged = _plain_copy(p, stage / (p.name if kind == "auditd" else f"{i}_{p.name}"))
            origin[staged.name] = rel(job, p)
        out = raw_dir / job.name(f"Zircolite_{kind}", "json")
        t.detail = f"{kind}: {len(srcs)} file(s)"
        job.run(t, [str(tb.zircolite), "-e", str(stage), flag, "-fp", pattern, "-r", str(tb.zircolite_rules),
                    "-o", str(out), "--timeline", str(raw_dir / job.name(f"Zircolite_{kind}_timeline")),
                    "--timezone", "UTC", "-l", str(job.logs / f"zircolite_{kind}_run.log")],
                cwd=tb.zircolite.parent, log_name=f"zircolite_{kind}")
        shutil.rmtree(stage, ignore_errors=True)
        runs.append(kind)
        try:
            dets = json.loads(out.read_text(encoding="utf-8", errors="replace")) if out.is_file() else []
        except ValueError:
            dets = []
        for d in dets if isinstance(dets, list) else []:
            title, level = str(d.get("title", "")), str(d.get("rule_level", ""))
            tags = ", ".join(d.get("tags") or [])
            for m in d.get("matches") or []:
                if not isinstance(m, dict):
                    continue
                details = " | ".join(f"{k}={v}" for k, v in m.items()
                                     if k not in ("timestamp", "OriginalLogfile", "row_id") and v not in ("", None))
                lf = str(m.get("OriginalLogfile", ""))
                rows.append([str(m.get("timestamp", "")), "UTC", level, title, d.get("id", ""), tags, details[:4000],
                             f"Zircolite ({kind})", origin.get(Path(lf).name, lf)])
                per_rule[title] = per_rule.get(title, 0) + 1
    rows.sort(key=lambda r: r[0])
    with writer(hunt / job.name("Sigma_Zircolite"), SIGMA_HEADER) as w:
        w.writerows(rows)
    lv = {}
    for r in rows:
        lv[r[2]] = lv.get(r[2], 0) + 1
    levels = ", ".join(f"{k} {v}" for k, v in sorted(lv.items(), key=lambda kv: -kv[1]))
    return f"{len(rows):,} detections, {len(per_rule)} rules ({', '.join(runs)})" + (f" - {levels}" if levels else "")


def task_ssh_summary(job: Job, t: Task):
    acc = job.cat_dir("account")
    srcs = [p for p in (acc / job.name("Auth_Events"), acc / job.name("Auth_Events_Journal")) if p.is_file()]
    stats: dict[str, dict] = {}
    for p in srcs:
        for r in postproc.iter_csv(p):
            ip = r.get("SourceIP", "")
            ev = r.get("EventType", "")
            if not ip or not ev.startswith("SSH_"):
                continue
            s = stats.setdefault(ip, {"ok": 0, "fail": 0, "users_ok": set(), "users_fail": set(),
                                      "first": r["Timestamp"], "last": r["Timestamp"], "methods": set(), "tz": set()})
            s["first"], s["last"] = min(s["first"], r["Timestamp"]), max(s["last"], r["Timestamp"])
            s["tz"].add(r.get("TimeZone", ""))
            if ev == "SSH_LOGIN_SUCCESS":
                s["ok"] += 1
                s["users_ok"].add(r.get("User", ""))
                s["methods"].add(r.get("Method", ""))
            elif ev in ("SSH_LOGIN_FAILED", "SSH_INVALID_USER", "SSH_MAX_AUTH_EXCEEDED"):
                s["fail"] += 1
                s["users_fail"].add(r.get("User", ""))
    if not stats:
        raise SkipTask("no SSH events in auth logs / journal")
    bf = 0
    with writer(job.cat_dir("remote") / job.name("SSH_Summary_by_IP"),
                ["SourceIP", "Successful", "Failed", "UsersSuccessful", "UsersTried", "Methods", "First", "Last",
                 "TimeZone", "Assessment"]) as w:
        for ip, s in sorted(stats.items(), key=lambda kv: (-kv[1]["ok"], -kv[1]["fail"])):
            assess = []
            if s["fail"] >= 20:
                assess.append("brute force")
                bf += 1
            if s["fail"] >= 20 and s["ok"]:
                assess.append("SUCCESS AFTER BRUTE FORCE")
            if len(s["users_fail"]) >= 5:
                assess.append("user enumeration / spraying")
            w.writerow([ip, s["ok"], s["fail"], ",".join(sorted(s["users_ok"])), len(s["users_fail"]),
                        ",".join(sorted(m for m in s["methods"] if m)), s["first"], s["last"],
                        ",".join(sorted(x for x in s["tz"] if x)), "; ".join(assess)])
    return f"{len(stats)} source IPs, {bf} brute-force sources"


# =============================================================================== audit
_AUDIT = re.compile(r"^(?:node=\S+ )?type=(?P<type>\S+) msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\): ?(?P<rest>.*)$")
_KV = re.compile(r'(\w+)=("(?:[^"]*)"|\S+)')
AUDIT_TYPES = {"USER_LOGIN", "USER_AUTH", "USER_ACCT", "USER_CMD", "ADD_USER", "DEL_USER", "ADD_GROUP",
               "DEL_GROUP", "USER_CHAUTHTOK", "USER_MGMT", "CRED_ACQ", "USER_START", "USER_END", "ANOM_ABEND",
               "ANOM_PROMISCUOUS", "SERVICE_START", "SERVICE_STOP", "SYSTEM_BOOT", "SYSTEM_SHUTDOWN",
               "CONFIG_CHANGE", "DAEMON_START", "AVC", "USER_AVC", "KERN_MODULE", "TTY", "USER_TTY"}


def _unhex(v: str) -> str:
    v = v.strip('"') if v.startswith('"') else v
    if re.fullmatch(r"(?:[0-9A-F]{2})+", v) and len(v) >= 2:
        try:
            return bytes.fromhex(v).decode("utf-8", "replace").replace("\0", " ")
        except ValueError:
            return v
    return v


def task_audit(job: Job, t: Task):
    logs = sorted(files(job, r"^var/log/audit/audit\.log(\.\d+)?(\.gz)?$"), key=_rotation_key)
    if not logs:
        raise SkipTask("auditd log not collected (auditd not installed?)")
    syscalls: dict[str, dict] = {}
    ne = nx = 0
    with writer(job.cat_dir("evtx") / job.name("Audit_Events"),
                ["Timestamp", "TimeZone", "Serial", "Type", "AUID", "UID", "Exe", "Terminal", "Host/Addr", "Result",
                 "Fields", "SourceLog"]) as aw, \
            writer(job.cat_dir("exec") / job.name("Audit_Execve"),
                   ["Timestamp", "TimeZone", "Serial", "CommandLine", "Exe", "Comm", "PID", "PPID", "AUID", "UID",
                    "TTY", "Key", "Suspicious", "SourceLog"]) as xw:
        for p in logs:
            src = rel(job, p)
            for line in iter_lines(p):
                m = _AUDIT.match(line)
                if not m:
                    continue
                typ, serial = m.group("type"), m.group("serial")
                kv = dict(_KV.findall(m.group("rest")))
                ts = epoch_utc(m.group("ts"))
                if typ == "SYSCALL":
                    syscalls[serial] = kv
                    if len(syscalls) > 5000:  # records of one event are adjacent - keep a small window
                        for k in list(syscalls)[:2500]:
                            del syscalls[k]
                elif typ == "EXECVE":
                    sc = syscalls.get(serial, {})
                    argc = int(kv.get("argc", "0") or 0) if kv.get("argc", "0").isdigit() else 0
                    args = [_unhex(kv.get(f"a{i}", "")) for i in range(argc)]
                    cmd = " ".join(args)
                    xw.writerow([ts, "UTC", serial, cmd, sc.get("exe", "").strip('"'), sc.get("comm", "").strip('"'),
                                 sc.get("pid", ""), sc.get("ppid", ""), sc.get("auid", ""), sc.get("uid", ""),
                                 sc.get("tty", ""), sc.get("key", "").strip('"'), suspicious(cmd), src])
                    nx += 1
                elif typ in AUDIT_TYPES:
                    msg = kv.get("msg", "")
                    inner = dict(_KV.findall(msg.strip("'"))) if msg else {}
                    allkv = {**kv, **inner}
                    aw.writerow([ts, "UTC", serial, typ, allkv.get("auid", ""), allkv.get("uid", ""),
                                 allkv.get("exe", "").strip('"'), allkv.get("terminal", ""),
                                 allkv.get("hostname", "") or allkv.get("addr", ""), allkv.get("res", ""),
                                 m.group("rest")[:2000], src])
                    ne += 1
    return f"{ne:,} audit events, {nx:,} EXECVE command lines"


# =============================================================================== shell history
HIST_RX = (r"(^|/)\.(bash|zsh|sh|ksh|ash|mksh)_history$|(^|/)\.zhistory$|(^|/)\.histfile$|"
           r"(^|/)\.local/share/fish/fish_history$|(^|/)\.(python|mysql|psql|sqlite|node_repl|rediscli)_history$|"
           r"(^|/)\.lesshst$|(^|/)\.viminfo$")


def _history_entries(p: Path) -> Iterator[tuple[str, str]]:
    """-> (UTC timestamp or '', command)."""
    name = p.name
    if name == "fish_history":
        cmd = None
        for line in iter_lines(p):
            if line.startswith("- cmd: "):
                if cmd is not None:
                    yield "", cmd
                cmd = line[7:]
            elif line.strip().startswith("when:") and cmd is not None:
                yield epoch_utc(line.split(":", 1)[1].strip()), cmd
                cmd = None
        if cmd is not None:
            yield "", cmd
        return
    if name == ".viminfo":  # only the command-line history part
        sect = False
        for line in iter_lines(p):
            if line.startswith("# Command Line History"):
                sect = True
            elif line.startswith("# ") and sect:
                break
            elif sect and line.startswith(":"):
                yield "", "vim " + line
        return
    ts = ""
    for line in iter_lines(p):
        if re.fullmatch(r"#\d{9,11}", line):  # bash HISTTIMEFORMAT marker
            ts = epoch_utc(line[1:])
            continue
        m = re.match(r"^: (\d{9,11}):\d+;(.*)$", line)  # zsh EXTENDED_HISTORY
        if m:
            yield epoch_utc(m.group(1)), m.group(2)
            continue
        if line.strip():
            yield ts, line
        ts = ""


def task_history(job: Job, t: Task):
    hist = files(job, HIST_RX)
    if not hist:
        raise SkipTask("no shell history files")
    raw = job.cat_dir("exec") / "Shell_History_Raw"
    raw.mkdir(exist_ok=True)
    n = flagged = 0
    with writer(job.cat_dir("exec") / job.name("Shell_History"),
                ["User", "Shell", "Line", "Timestamp", "TimeZone", "Command", "Suspicious", "HistoryFile",
                 "FileModified(UTC)"]) as w:
        for p in sorted(hist):
            r = rel(job, p)
            u = user_of(job, r) or "unknown"
            shutil.copy2(p, raw / r.strip("/").replace("/", "_"))
            shell = re.sub(r"^\.|_history$|history$", "", p.name) or p.name
            fm = mtime_utc(p)
            for i, (ts, cmd) in enumerate(_history_entries(p), 1):
                why = suspicious(cmd)
                flagged += bool(why)
                w.writerow([u, shell, i, ts, "UTC" if ts else "", cmd[:4000], why, r, fm])
                n += 1
    return f"{n:,} commands from {len(hist)} files, {flagged:,} flagged"


# =============================================================================== persistence
def _scope(path: str) -> str:
    if path.startswith(("/usr/lib/", "/lib/", "/usr/share/")):
        return "vendor (package)"
    if re.match(r"^/(home/[^/]+|root)/", path):
        return "user"
    return "admin (/etc, /var)"


def task_persistence(job: Job, t: Task):
    rows: list[list] = []

    def add(mech, p: Path, entry="", user="", extra=""):
        r = rel(job, p)
        # 'persistence setup' describes commands that *create* persistence - every row here already is one
        why = suspicious(entry, skip=("persistence setup",)) if entry else ""
        if extra:
            why = "; ".join(x for x in (extra, why) if x)
        rows.append([mech, r, _scope(r), user or user_of(job, r), entry.strip()[:2000], mtime_utc(p), why])

    def lines(p: Path):
        for line in read_text(p).splitlines():
            s = line.strip()
            if s and not s.startswith(("#", ";")):
                yield s

    # cron
    for p in files(job, r"^etc/crontab$|^etc/cron\.d/[^/]+$|^etc/anacrontab$"):
        for s in lines(p):
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):
                continue
            f = s.split(None, 6 if not s.startswith("@") else 2)
            user = (f[5] if len(f) > 6 else "") if not s.startswith("@") else (f[1] if len(f) > 2 else "")
            add("cron (system)", p, s, user)
    for p in files(job, r"^var/spool/cron/(crontabs/)?[^/]+$"):
        for s in lines(p):
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):
                add("cron (user crontab)", p, s, p.name)
    for p in files(job, r"^etc/cron\.(hourly|daily|weekly|monthly)/[^/]+$"):
        add("cron script", p, "", "root", suspicious(read_text(p, 65536), skip=("persistence setup",)))
    for p in files(job, r"^var/spool/(cron/)?at(jobs|spool)?/[^/.][^/]*$"):
        body = read_text(p, 65536).strip().splitlines()
        add("at job", p, body[-1] if body else "")  # the command is the last line of an at job file
    # systemd
    for p in files(job, r"^(etc|usr/lib|lib|run)/systemd/(system|user)/.+\.(service|timer|socket|path)$|"
                        r"^(home/[^/]+|root)/\.config/systemd/user/.+\.(service|timer)$"):
        r = rel(job, p)
        extra = "unit created in /etc (not from a package)" if r.startswith("/etc/systemd/") else ""
        execs = [s for s in lines(p) if re.match(r"^(Exec\w*|OnCalendar|OnBootSec|OnUnitActiveSec|ListenStream)=", s)]
        if not execs:
            add("systemd unit", p, "", "", extra)
        for s in execs:
            add("systemd unit", p, s, "", extra)
    # init / rc / shell startup
    for p in files(job, r"^etc/(rc\.local|rc\.d/rc\.local)$|^etc/init\.d/[^/]+$"):
        add("SysV init / rc.local", p, "", "root", suspicious(read_text(p, 262144)))
    for p in files(job, r"^etc/(profile|bash\.bashrc|bashrc|environment|zsh/zshrc|zshrc|zprofile)$|"
                        r"^etc/profile\.d/[^/]+$|^(home/[^/]+|root)/\.(bashrc|bash_profile|bash_login|bash_logout|"
                        r"profile|zshrc|zprofile|zlogin|zshenv|xprofile|xinitrc)$"):
        hits = [s for s in lines(p) if suspicious(s)]
        add("shell startup file", p, "", "", "")
        for s in hits:
            add("shell startup file", p, s)
    # preload / ld.so
    p = one(job, "/etc/ld.so.preload")
    if p:
        for s in lines(p):
            add("ld.so.preload", p, s, "root", "LD preload entry (userland rootkit technique)")
    for p in files(job, r"^etc/ld\.so\.conf\.d/[^/]+$"):
        add("ld.so.conf.d", p, " ".join(lines(p))[:500])
    # ssh keys
    for p in files(job, r"(^|/)\.ssh/authorized_keys2?$"):
        for s in lines(p):
            # command= (forced command) and environment= can hide a backdoor; from=/no-pty only restrict a key
            km = re.search(r"(ssh-(rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)\s", s)
            opts = s[:km.start()] if km else ""
            opt = "forced command / environment on key" if re.search(r"\b(command|environment)=", opts) else ""
            add("SSH authorized_keys", p, s[:120] + (" ... " + s.split()[-1] if len(s) > 120 else ""), "", opt)
    # sudoers
    for p in files(job, r"^etc/sudoers$|^etc/sudoers\.d/[^/]+$"):
        for s in lines(p):
            if s.startswith(("Defaults", "@include", "#include")):
                continue
            add("sudoers rule", p, s, "", "NOPASSWD sudo rule" if "NOPASSWD" in s else "")
    # udev, xdg autostart, motd, modules, pam
    for p in files(job, r"^(etc|usr/lib|lib)/udev/rules\.d/[^/]+\.rules$"):
        for s in lines(p):
            if "RUN+=" in s or "PROGRAM=" in s:
                add("udev rule", p, s)
    for p in files(job, r"^etc/xdg/autostart/[^/]+\.desktop$|^(home/[^/]+|root)/\.config/autostart/[^/]+\.desktop$"):
        for s in lines(p):
            if s.startswith("Exec="):
                add("XDG autostart", p, s)
    for p in files(job, r"^etc/update-motd\.d/[^/]+$"):
        add("update-motd script", p, "", "root", suspicious(read_text(p, 65536)))
    for p in files(job, r"^etc/modules$|^etc/modules-load\.d/[^/]+\.conf$"):
        for s in lines(p):
            add("kernel module autoload", p, s, "root")
    for p in files(job, r"^etc/pam\.d/[^/]+$"):
        for s in lines(p):
            if "pam_exec" in s or re.search(r"\s/(tmp|dev/shm|var/tmp|home)/\S+\.so", s):
                add("PAM module", p, s, "", "pam_exec / non-standard PAM module")
    if not rows:
        raise SkipTask("no persistence locations collected")
    flagged = sum(1 for r in rows if r[6])
    hdr = ["Mechanism", "Path", "Scope", "User", "Entry", "FileModified(UTC)", "Suspicious"]
    with writer(job.cat_dir("persist") / job.name("Persistence"), hdr) as w:
        w.writerows(rows)
    with writer(job.cat_dir("hunt") / job.name("Persistence_Suspicious"), hdr) as w:
        w.writerows(r for r in rows if r[6])
    return f"{len(rows):,} entries, {flagged} flagged"


# =============================================================================== file system (bodyfile)
def _bodyfile(job: Job) -> Path | None:
    b = uac_files(job, r"^bodyfile/bodyfile\.txt$")
    return b[0] if b else None


def task_fs_timeline(job: Job, t: Task):
    body = _bodyfile(job)
    if not body:
        raise SkipTask("no UAC bodyfile (bodyfile/bodyfile.txt)")
    dst = job.cat_dir("fs") / job.name("FileSystem_Timeline")
    if job.tb.mactime:
        t.detail = "sorting MACB events (mactime)"
        # start date: UAC writes 0 for an unknown birth time, which mactime would list as 0000-00-00 rows
        job.run(t, [job.tb.mactime, "-b", str(body), "-d", "-y", "-z", "UTC", "1970-01-02"],
                log_name="mactime_linux", stdout_file=dst)
        return f"{postproc.count_rows(dst):,} rows"
    t.tool = "python (mactime)"
    return f"{postproc.mactime_py(body, dst):,} rows"


_STD_SUID_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/",
                  "/usr/libexec/", "/usr/local/bin/", "/snap/", "/opt/google/", "/usr/share/")
_GTFO_SUID = re.compile(r"/(bash|sh|dash|zsh|ksh|python[\d.]*|perl|ruby|php[\d.]*|node|lua|vim?|nano|less|more|find|"
                        r"nmap|awk|gawk|cp|mv|tar|zip|env|tee|dd|socat|nc|ncat|wget|curl|docker|busybox|git|"
                        r"openssl|xxd|base64|systemctl|journalctl|gdb|strace|taskset|nice|timeout|ionice)$")
_HIDDEN_OK = {".build-id", ".keep", ".placeholder", ".gitignore", ".gitkeep", ".X11-unix", ".ICE-unix",
              ".font-unix", ".XIM-unix", ".Test-unix", ".dwz", ".debug", ".lock", ".pwd.lock", ".updated",
              ".gitattributes", ".hmac", ".cache", ".htaccess", ".well-known", ".java", ".packlist"}
_MINER = re.compile(r"kinsing|kdevtmpfsi|xmrig|xmr-stak|cryptonight|minerd|\.x?mr\b|ld-linux-x86-64-|watchbog|"
                    r"\btsm\b|\bkworkerds\b|\bdbused\b", re.I)


def file_findings(name: str, mode: str) -> list[str]:
    why = []
    target = ""
    if " -> " in name:
        name, target = name.split(" -> ", 1)
    comps = name.split("/")
    if target and re.search(r"(_history|\.histfile|\.zhistory)$", name) and target.strip("'\"") == "/dev/null":
        why.append("shell history linked to /dev/null")
    if mode[:1] == "-":
        perms = mode[1:10]
        if re.match(r"^/(tmp|var/tmp|dev/shm|run/shm)/", name) and "x" in perms.replace("s", "x"):
            why.append("executable in /tmp or /dev/shm")
        if name.startswith("/dev/") and not name.startswith(("/dev/shm/", "/dev/.udev", "/dev/mqueue/")):
            why.append("regular file in /dev")
        if len(perms) >= 6 and (perms[2] in "sS" or perms[5] in "sS"):
            if not name.startswith(_STD_SUID_DIRS):
                why.append("SUID/SGID outside system binary dirs")
            elif _GTFO_SUID.search(name):
                why.append("SUID/SGID on shell/interpreter/GTFOBin")
    if re.match(r"^/(tmp|var/tmp|dev/shm|usr|lib|lib64|bin|sbin|boot|etc|var/lib|opt)/", name):
        for c in comps[1:]:
            if c.startswith(".") and c not in _HIDDEN_OK and c not in (".", "..") and not c.startswith(".#"):
                why.append("hidden file/dir in system location")
                break
    if any(c and (c.strip() == "" or (set(c.strip()) == {"."} and len(c) > 2) or c != c.strip()) for c in comps[1:]):
        why.append("deceptive name (spaces / dots)")
    if _MINER.search(name):
        why.append("known miner/malware name")
    return why


def task_suspicious_files(job: Job, t: Task):
    body = _bodyfile(job)
    if not body:
        raise SkipTask("no UAC bodyfile")
    n = scanned = 0
    with writer(job.cat_dir("hunt") / job.name("Suspicious_Files"),
                ["Reason", "Path", "Mode", "UID", "GID", "Size", "Modified", "Accessed", "Changed", "Born",
                 "TimeZone"]) as w:
        for line in iter_lines(body):
            f = line.split("|")
            if len(f) < 11:
                continue
            if len(f) > 11:  # '|' inside the file name
                f = [f[0], "|".join(f[1:len(f) - 9])] + f[len(f) - 9:]
            scanned += 1
            why = file_findings(f[1], f[3])
            if why:
                w.writerow(["; ".join(why), f[1], f[3], f[4], f[5], f[6], epoch_utc(f[8]), epoch_utc(f[7]),
                            epoch_utc(f[9]), epoch_utc(f[10]), "UTC"])
                n += 1
    return f"{n:,} findings in {scanned:,} bodyfile entries"


# =============================================================================== packages
def task_packages(job: Job, t: Task):
    apps = job.cat_dir("apps")
    ni = nh = 0
    installed: list[list] = []
    status = one(job, "/var/lib/dpkg/status")
    if status:
        for para in read_text(status, 256 * 1024 * 1024).split("\n\n"):
            d = dict(re.findall(r"^([\w-]+): ?(.*)$", para, re.M))
            if d.get("Package"):
                installed.append(["", d.get("Package"), d.get("Version", ""), d.get("Architecture", ""),
                                  d.get("Status", ""), d.get("Installed-Size", ""), d.get("Maintainer", ""), "dpkg"])
    # rpm-based hosts (RHEL, Photon, SUSE, ...): UAC live response `rpm -q -a --queryformat` (installtime~name~ver)
    rpm_hist = []
    for p in uac_files(job, r"^live_response/packages/rpm_-q_-a_--queryformat[^/]*\.txt$"):
        for line in iter_lines(p):
            f = line.strip().split("~")
            if len(f) >= 3 and f[0].isdigit():
                ts = epoch_utc(f[0])
                installed.append([ts, f[1], "~".join(f[2:]), "", "installed", "", "", "rpm (UAC live response)"])
                rpm_hist.append([ts, "UTC", "rpm install (install time)", f[1], "~".join(f[2:]), "",
                                 "/live_response/packages/" + p.name])
    if installed:
        with writer(apps / job.name("Installed_Packages"), ["InstallTime(UTC)", "Package", "Version", "Architecture",
                                                            "Status", "InstalledSize", "Maintainer", "Source"]) as w:
            w.writerows(installed)
        ni = len(installed)
    nv = _rpm_verify(job)
    clk = clock(job)
    with writer(apps / job.name("Package_History"), ["Timestamp", "TimeZone", "Action", "Package", "Version",
                                                     "Details", "SourceLog"]) as w:
        rpm_hist.sort(key=lambda r: r[0])
        w.writerows(rpm_hist)
        nh += len(rpm_hist)
        for p in sorted(files(job, r"^var/log/dpkg\.log(\.\d+)?(\.gz)?$"), key=_rotation_key):
            for line in iter_lines(p):
                m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (install|upgrade|remove|purge) (\S+) (\S+) (\S+)", line)
                if m:
                    ts, tzl = clk.local(dt.datetime.strptime(m.group(1), TS_FMT))
                    w.writerow([ts, tzl, m.group(2), m.group(3), m.group(5), f"from {m.group(4)}", rel(job, p)])
                    nh += 1
        for p in sorted(files(job, r"^var/log/apt/history\.log(\.\d+)?(\.gz)?$"), key=_rotation_key):
            blk: dict = {}
            for line in list(iter_lines(p)) + [""]:
                if not line.strip():
                    if blk.get("Start-Date"):
                        try:
                            ts, tzl = clk.local(dt.datetime.strptime(blk["Start-Date"].strip(), "%Y-%m-%d  %H:%M:%S"))
                        except ValueError:
                            ts, tzl = blk["Start-Date"], clk.local_label
                        for act in ("Install", "Upgrade", "Remove", "Purge", "Reinstall", "Downgrade"):
                            if blk.get(act):
                                w.writerow([ts, tzl, f"apt {act.lower()}", blk[act][:2000], "",
                                            f"Commandline: {blk.get('Commandline', '')} "
                                            f"Requested-By: {blk.get('Requested-By', '')}".strip(), rel(job, p)])
                                nh += 1
                    blk = {}
                    continue
                k, _, v = line.partition(": ")
                blk[k] = v
        for p in sorted(files(job, r"^var/log/(yum\.log|dnf\.rpm\.log|dnf\.log)(\.\d+|-\d{8})?(\.gz)?$"),
                        key=_rotation_key):
            ref = clk.ref_local(p)
            for line in iter_lines(p):
                m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})([+-]\d{4}|Z)? \w+ (Installed|Upgraded|Erased|"
                             r"Removed|Reinstalled|Downgraded)\s*:\s*(\S+)", line)
                if m:
                    base = dt.datetime.fromisoformat(m.group(1))
                    tz = m.group(2)
                    if tz and tz != "Z":
                        off = dt.timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * (1 if tz[0] == "+" else -1)
                        ts, tzl = (base - off).strftime(TS_FMT), "UTC"
                    elif tz == "Z":
                        ts, tzl = base.strftime(TS_FMT), "UTC"
                    else:
                        ts, tzl = clk.local(base)
                    w.writerow([ts, tzl, m.group(3).lower(), m.group(4), "", "", rel(job, p)])
                    nh += 1
                    continue
                m = re.match(r"^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}:\d{2}:\d{2}) (Installed|Updated|Erased): (\S+)", line)
                if m:
                    r = SyslogParser(clk, ref).parse(f"{m.group(1)} {m.group(2)} {m.group(3)} h yum: x")
                    if r:
                        w.writerow([r[0], r[1], m.group(4).lower(), m.group(5), "", "", rel(job, p)])
                        nh += 1
    if not ni and not nh and not nv[0]:
        raise SkipTask("no dpkg/rpm/apt/yum/dnf package data")
    return (f"{ni:,} installed packages, {nh:,} history entries"
            + (f", rpm -V: {nv[0]:,} changed files, {nv[1]} flagged" if nv[0] else ""))


# rpm -V: SM5DLUGTP per file (S size, M mode, 5 digest, D device, L link, U user, G group, T mtime, P caps)
_RPMV = re.compile(r"^(?P<flags>missing|[SM5DLUGTP.?]{8,9})\s+(?P<attr>[cdglr]\s+)?(?P<path>/.*)$")
_BIN_DIRS = re.compile(r"^/(usr/)?(s?bin|lib(64|32|exec)?)/|^/usr/local/s?bin/|^/opt/[^/]+/(s?bin|lib)/")
_REGENERATED = re.compile(r"\.pyc$|/__pycache__/|^/lib/modules/[^/]+/modules\.|/ld\.so\.cache$|^/var/|"
                          r"/fonts/.*\.cache|/icon-theme\.cache$|/gconv-modules\.cache$|/mime/|\.hwdb$|/udev/hwdb|"
                          r"^/usr/lib/locale/")
# application config shipped under /usr/lib or /opt but rewritten at first boot / by the admin (e.g. vCenter)
_CONFIG_EXT = re.compile(r"\.(properties|xml|conf|cfg|cnf|ini|json|ya?ml|tpl|template|txt|spec|config)$", re.I)


_EXEC_DIRS = re.compile(r"^/(usr/)?(local/)?s?bin/|^/usr/libexec/|^/opt/[^/]+/s?bin/")


def _bodyfile_suid(job: Job, paths: set[str]) -> dict[str, str]:
    """path -> mode for those of `paths` that are SUID/SGID in the UAC bodyfile."""
    body = _bodyfile(job)
    out = {}
    if not body:
        return out
    for line in iter_lines(body):
        f = line.split("|")
        if len(f) >= 11 and f[1] in paths and len(f[3]) >= 7 and (f[3][3] in "sS" or f[3][6] in "sS"):
            out[f[1]] = f[3]
    return out


def _rpm_verify(job: Job) -> tuple[int, int]:
    """Package integrity from UAC's `rpm -V -a`: binaries/libraries whose content (5) or permissions (M)
    differ from the package are classic trojan / backdoor indicators."""
    src = uac_files(job, r"^live_response/packages/rpm_-V_-a\.txt$")
    if not src:
        return 0, 0
    rows, mode_changed = [], {}
    for line in iter_lines(src[0]):
        m = _RPMV.match(line.strip())
        if not m:
            continue
        flags, attr, path = m.group("flags"), (m.group("attr") or "").strip(), m.group("path")
        is_cfg = attr in ("c", "g") or bool(_CONFIG_EXT.search(path))  # config / ghost files change legitimately
        why = []
        if not is_cfg and not _REGENERATED.search(path) and _BIN_DIRS.search(path):
            if flags == "missing":
                why.append("package binary/library missing (deleted?)")
            else:
                if flags[2:3] == "5":
                    why.append("binary/library CONTENT differs from package (replaced / trojanized?)")
                if flags[:1] == "S" and flags[2:3] != "5":
                    why.append("binary/library size changed")
        row = [flags, attr, path, ""]
        rows.append((row, why))
        # Mode differences are very common and mostly harmless (umask, packaging, directories); only an
        # executable that is SUID/SGID *now* matters - decided with the bodyfile below
        if not is_cfg and flags[1:2] == "M" and _EXEC_DIRS.search(path):
            mode_changed[path] = row
    suid = _bodyfile_suid(job, set(mode_changed)) if mode_changed else {}
    for path, mode in suid.items():
        mode_changed[path][3] = f"mode differs from package and file is SUID/SGID now ({mode})"
    flagged = []
    for row, why in rows:
        row[3] = "; ".join(x for x in why + ([row[3]] if row[3] else []) if x)
        if row[3]:
            flagged.append(row)
    rows = [r for r, _ in rows]
    hdr = ["Flags", "FileType(c=config)", "Path", "Suspicious"]
    with writer(job.cat_dir("apps") / job.name("RPM_Verify"), hdr) as w:
        w.writerows(rows)
    with writer(job.cat_dir("hunt") / job.name("Package_Integrity_Suspicious"), hdr) as w:
        w.writerows(flagged)
    return len(rows), len(flagged)


# =============================================================================== web server logs
_WEB = re.compile(r'^(?P<vhost>\S+ )?(?P<ip>[0-9a-fA-F.:]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
                  r'"(?P<req>[^"]*)" (?P<status>\d{3}|-) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
WEB_RULES = [
    (re.compile(r"union(\s|\+|%20|/\*.*?\*/)+(all(\s|\+|%20)+)?select|'\s*(or|and)\s*'?\d|sleep\(\d|benchmark\(|"
                r"information_schema|xp_cmdshell|%27(%20|\+)or", re.I), "SQL injection"),
    (re.compile(r"\.\./|\.\.%2f|%2e%2e(/|%2f)|/etc/(passwd|shadow)|/proc/self/|c:\\\\windows", re.I), "path traversal / LFI"),
    (re.compile(r"[;|`]\s*(id|whoami|uname|cat|wget|curl|bash|sh|nc)\b|\$\(|%3B(id|whoami|wget|curl)|"
                r"(cmd|exec|command|execute|shell|c|e)=(id|whoami|uname|ls|cat|wget|curl|bash|nc|powershell)", re.I),
     "command injection / webshell command"),
    (re.compile(r"\$\{jndi:|%24%7Bjndi", re.I), "Log4Shell (JNDI)"),
    (re.compile(r"/(c99|r57|wso|b374k|shell|cmd|webshell|alfa|indoxploit|up|upload|x)\.(php|jsp|aspx?)\b|"
                r"\.(php|jsp)\?(cmd|exec|c|e)=", re.I), "possible webshell"),
    (re.compile(r"<script|%3Cscript|javascript:|onerror=", re.I), "XSS"),
    (re.compile(r"/(wp-login\.php|xmlrpc\.php|\.env|\.git/|phpmyadmin|actuator|cgi-bin/.*\.(sh|cgi)|"
                r"vendor/phpunit|boaform|HNAP1|\.aws/credentials)", re.I), "scan / exploit probe"),
]
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|wpscan|nuclei|feroxbuster|"
                        r"ffuf|hydra|acunetix|nessus|openvas|wfuzz|python-requests|curl/|wget/|go-http-client", re.I)


def task_weblogs(job: Job, t: Task):
    logs = sorted(files(job, r"^var/log/(apache2?|httpd|nginx|lighttpd|tomcat\d*)/[^/]*access[^/]*$|"
                             r"^var/log/(apache2?|httpd)/[^/]*_log(\.\d+)?(\.gz)?$"), key=_rotation_key)
    logs = [p for p in logs if "error" not in p.name]
    if not logs:
        raise SkipTask("no web server access logs")
    n = ns = 0
    per_ip: dict[str, list] = {}
    with writer(job.cat_dir("apps") / job.name("Web_Access"),
                ["Timestamp", "TimeZone", "ClientIP", "User", "Method", "URL", "Status", "Bytes", "Referer",
                 "UserAgent", "SourceLog"]) as w, \
            writer(job.cat_dir("hunt") / job.name("Web_Suspicious_Requests"),
                   ["Timestamp", "TimeZone", "ClientIP", "Reason", "Method", "URL", "Status", "UserAgent",
                    "SourceLog"]) as sw:
        for i, p in enumerate(logs):
            t.progress, t.detail = i / len(logs), rel(job, p)
            src = rel(job, p)
            for line in iter_lines(p):
                m = _WEB.match(line)
                if not m:
                    continue
                try:
                    ts = dt.datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC).strftime(TS_FMT)
                except ValueError:
                    ts = m.group("ts")
                req = m.group("req").split(" ")
                meth, url = (req[0], req[1]) if len(req) >= 2 else ("", m.group("req"))
                ua = m.group("ua") or ""
                ip, status = m.group("ip"), m.group("status")
                w.writerow([ts, "UTC", ip, m.group("user"), meth, url, status, m.group("size"),
                            m.group("ref") or "", ua, src])
                n += 1
                why = [r for rx, r in WEB_RULES if rx.search(url)]
                if SCANNER_UA.search(ua):
                    why.append("scanner / tool user agent")
                if meth == "POST" and re.search(r"/(uploads?|images?|tmp|files)/[^?]*\.(php\d?|phtml|jsp|aspx?)", url, re.I):
                    why.append("POST to script in upload dir (webshell?)")
                if why:
                    sw.writerow([ts, "UTC", ip, "; ".join(dict.fromkeys(why)), meth, url[:4000], status, ua, src])
                    ns += 1
                    per_ip.setdefault(ip, [0, ts, ts])
                    s = per_ip[ip]
                    s[0], s[1], s[2] = s[0] + 1, min(s[1], ts), max(s[2], ts)
    with writer(job.cat_dir("hunt") / job.name("Web_Suspicious_by_IP"), ["ClientIP", "SuspiciousRequests",
                                                                          "First", "Last"]) as w:
        for ip, s in sorted(per_ip.items(), key=lambda kv: -kv[1][0]):
            w.writerow([ip] + s)
    return f"{n:,} requests from {len(logs)} logs, {ns:,} suspicious from {len(per_ip)} IPs"


# =============================================================================== network / ssh
NET_CONFIG_RX = (r"^etc/(hosts|hostname|resolv\.conf|nsswitch\.conf|hosts\.(allow|deny)|network/interfaces|"
                 r"sysconfig/network(-scripts/ifcfg-[^/]+)?|iptables/rules\.v[46]|nftables\.conf|"
                 r"ssh/sshd_config|ssh/ssh_config|ssh/sshd_config\.d/[^/]+|wpa_supplicant/[^/]+\.conf)$|"
                 r"^etc/netplan/[^/]+\.ya?ml$|^etc/NetworkManager/system-connections/[^/]+$|"
                 r"^etc/sysconfig/(iptables|ip6tables)$|^etc/ufw/[^/]+\.rules$")


def task_network(job: Job, t: Task):
    cfg = files(job, NET_CONFIG_RX)
    n = postproc.copy_tree_files(cfg, _root(job), job.cat_dir("network") / "Network_Config")
    kh = files(job, r"(^|/)\.ssh/known_hosts2?$|^etc/ssh/ssh_known_hosts$")
    nk = 0
    with writer(job.cat_dir("remote") / job.name("SSH_Known_Hosts"),
                ["User", "Host", "Hashed", "KeyType", "KnownHostsFile", "FileModified(UTC)"]) as w:
        for p in kh:
            r = rel(job, p)
            for line in read_text(p).splitlines():
                f = line.split()
                if len(f) >= 2 and not line.startswith("#"):
                    hosts = f[0] if not f[0].startswith("@") else (f[1] if len(f) > 2 else "")
                    w.writerow([user_of(job, r), hosts, "yes" if hosts.startswith("|1|") else "",
                                f[1] if not f[0].startswith("@") else f[2], r, mtime_utc(p)])
                    nk += 1
    ak = files(job, r"(^|/)\.ssh/authorized_keys2?$")
    na = 0
    with writer(job.cat_dir("remote") / job.name("SSH_Authorized_Keys"),
                ["User", "KeyType", "Comment", "Options", "File", "FileModified(UTC)"]) as w:
        for p in ak:
            r = rel(job, p)
            for line in read_text(p).splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                m = re.search(r"(ssh-(rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)\s+\S+\s*(.*)$", s)
                opts = s[:m.start()].strip() if m else ""
                w.writerow([user_of(job, r), m.group(1) if m else "", m.group(3) if m else "", opts, r, mtime_utc(p)])
                na += 1
    if not (n or nk or na):
        raise SkipTask("no network configuration or SSH files")
    return f"{n} config files, {nk} known_hosts entries, {na} authorized keys"


# =============================================================================== UAC live response
def task_live_response(job: Job, t: Task):
    u = job.layout.uac
    if not u or not u.is_dir():
        raise SkipTask("no UAC output (live_response/)")
    live = job.cat_dir("live")
    copied, pairs = [], []
    for name in ("live_response", "hash_executables", "chkrootkit", "system"):
        if (u / name).is_dir():
            pairs += _tree_pairs(u / name, live / name)
            copied.append(name)
    for f in u.iterdir():
        if f.is_file() and not f.is_symlink() and (f.name == "uac.log" or f.name.startswith("hash_list")):
            pairs.append((f, live / f.name))
            copied.append(f.name)
    for sub, cat in (("network", "network"), ("packages", "apps")):  # small, handy next to the parsed results
        if (u / "live_response" / sub).is_dir():
            pairs += _tree_pairs(u / "live_response" / sub, job.cat_dir(cat) / f"live_response_{sub}")
    if not copied:
        raise SkipTask("UAC output has no live_response/hash_executables")
    _copy_parallel(pairs, t)
    return f"{', '.join(copied)} ({len(pairs):,} files)"


def _tree_pairs(src: Path, dst: Path) -> list[tuple[Path, Path]]:
    """(source, destination) for every regular file below src; symlinks are skipped (recorded at extraction)."""
    out = []
    for d, _dirs, fs in os.walk(src):
        for n in fs:
            s = Path(d) / n
            if not s.is_symlink():
                out.append((s, dst / s.relative_to(src)))
    return out


def _copy_parallel(pairs: list[tuple[Path, Path]], t: Task | None = None, workers: int = 16) -> None:
    """Copy many small files fast: output folders are often on /mnt/<drive> (9P), where every file costs
    several round trips - so copy contents only (no copystat) and keep many copies in flight."""
    for d in {dst.parent for _, dst in pairs}:
        d.mkdir(parents=True, exist_ok=True)
    done = [0]
    lock = threading.Lock()

    def cp(pair):
        try:
            shutil.copyfile(pair[0], pair[1])
        except OSError:
            pass
        if t is not None:
            with lock:
                done[0] += 1
                if done[0] % 200 == 0 or done[0] == len(pairs):
                    t.progress, t.detail = done[0] / len(pairs), f"copied {done[0]:,}/{len(pairs):,} files"

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(cp, pairs))


# =============================================================================== system info
def _os_release(job: Job) -> dict:
    txt = read_text(one(job, "/etc/os-release") or one(job, "/usr/lib/os-release"))
    return {k: v.strip().strip('"') for k, v in re.findall(r"^(\w+)=(.*)$", txt, re.M)}


def task_sysinfo(job: Job, t: Task):
    osr = _os_release(job)
    host = read_text(one(job, "/etc/hostname")).strip().splitlines()
    info: dict = {"ComputerName": host[0].strip() if host else "", "ProductName": osr.get("PRETTY_NAME", "")
                  or " ".join(x for x in (osr.get("NAME", ""), osr.get("VERSION", "")) if x),
                  "DisplayVersion": "", "OSId": osr.get("ID", ""), "OSVersionId": osr.get("VERSION_ID", "")}
    if not info["ProductName"]:  # os-release missing (often a symlink to an uncollected /usr/lib/os-release)
        lsb = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', read_text(one(job, "/etc/lsb-release")), re.M))
        info["ProductName"] = lsb.get("DISTRIB_DESCRIPTION", "")
        info["OSVersionId"] = info["OSVersionId"] or lsb.get("DISTRIB_RELEASE", "")
    if not info["ProductName"]:
        for f in ("/etc/photon-release", "/etc/redhat-release", "/etc/system-release", "/etc/centos-release",
                  "/etc/SuSE-release", "/etc/alpine-release", "/etc/debian_version"):
            v = read_text(one(job, f)).strip().splitlines()
            if v and v[0].strip():
                info["ProductName"] = v[0].strip() if "release" in f else f"Debian {v[0].strip()}"
                break
    tz = detect_timezone(job)
    info["TimeZone"] = tz
    for p in uac_files(job, r"^live_response/system/[^/]*uname[^/]*\.txt$"):
        v = read_text(p).strip().splitlines()
        if v:
            info["Kernel"] = v[0][:300]
            m = re.match(r"^\S+ \S+ (\S+)", v[0])
            info["Build"] = m.group(1) if m else v[0][:60]
            break
    for p in uac_files(job, r"^live_response/system/[^/]*uptime[^/]*\.txt$"):
        info["UptimeAtCollection"] = read_text(p).strip().splitlines()[0][:200] if read_text(p).strip() else ""
        break
    ips = []
    for p in uac_files(job, r"^live_response/network/[^/]*(ip_addr|ip_a|ifconfig)[^/]*\.txt$"):
        for m in re.finditer(r"inet6? (?:addr:)?([0-9a-fA-F.:]+)", read_text(p)):
            a = m.group(1)
            if a not in ips and not a.startswith(("127.", "::1")):
                ips.append(a)
    info["IPAddresses"] = ", ".join(ips)
    us = users(job)
    info["LoginAccounts"] = ", ".join(u["user"] for u in us if _INTERACTIVE.search(u["shell"]))
    uaclog = uac_files(job, r"^uac\.log$")
    extra = {"Source": str(job.item.path), "Collection type": job.item.kind,
             "Hostname (from file name)": job.item.host, "Collected at (host local)": job.item.stamp,
             "OS (from file name)": job.item.os}
    if uaclog:
        head = read_text(uaclog[0], 65536)
        for k, rx in (("UAC version", r"UAC \(Unix-like Artifacts Collector\) (\S+)|uac[ _]version[^\w]*(\S+)"),
                      ("UAC profile", r"[Pp]rofile[^:]*:\s*(\S+)"), ("UAC command", r"[Cc]ommand line:\s*(.+)")):
            m = re.search(rx, head)
            if m:
                extra[k] = next(g for g in m.groups() if g)
    job.sysinfo = info
    job._lx_clock = Clock(tz)
    d = job.cat_dir("info")
    lines = ["=" * 70, " SYSTEM INFORMATION (Linux / Unix)", "=" * 70]
    for k in ("ComputerName", "ProductName", "OSId", "OSVersionId", "Kernel", "TimeZone", "IPAddresses",
              "UptimeAtCollection", "LoginAccounts"):
        if info.get(k):
            lines.append(f" {k:<24}: {info[k]}")
    lines += ["", " COLLECTION"] + [f" {k:<24}: {v}" for k, v in extra.items() if v]
    if not tz:
        lines += ["", " NOTE: host time zone unknown - classic syslog times are kept in host local time"]
    (d / job.name("System_Info", "txt")).write_text("\n".join(lines) + "\n", encoding="utf-8")
    (d / job.name("System_Info", "json")).write_text(json.dumps({**info, "collection": extra}, indent=2,
                                                                 default=str), encoding="utf-8")
    if info["ComputerName"] and job.host and info["ComputerName"].split(".")[0].lower() != job.host.split(".")[0].lower():
        job.log(f"hostname in /etc/hostname ({info['ComputerName']}) differs from collection name ({job.host})",
                "warn", True)
    if not info["ProductName"] and not us:
        raise TaskWarning("no /etc/os-release or /etc/passwd - is this a Unix collection?")
    return f"{info['ComputerName'] or '?'} | {info['ProductName'] or '?'} | kernel {info.get('Build', '?')} | " \
           f"TZ {tz or 'unknown'}"


# =============================================================================== inventory / gaps
EXPECTED = [
    # name, category, base (root|uac), regex, note when missing
    ("os-release / distro release", "info", "root",
     r"^(etc|usr/lib)/os-release$|^etc/(lsb|photon|redhat|system|centos|SuSE|alpine)-release$|^etc/debian_version$", ""),
    ("/etc/passwd", "account", "root", r"^etc/passwd$", ""),
    ("/etc/shadow", "account", "root", r"^etc/shadow$", "password ages / locked accounts unknown"),
    ("/etc/group", "account", "root", r"^etc/group$", ""),
    ("sudoers", "account", "root", r"^etc/sudoers(\.d/.+)?$", ""),
    ("auth.log / secure", "account", "root", r"^var/log/(auth\.log|secure)", "journald-only host? see journal"),
    ("syslog / messages", "evtx", "root", r"^var/log/(syslog|messages)", "journald-only host? see journal"),
    ("systemd journal", "evtx", "root", r"^(var|run)/log/journal/.+\.journal~?$",
     "no persistent journal (Storage=volatile/auto without /var/log/journal) or not collected"),
    ("wtmp", "account", "root", r"^var/log/wtmp", ""),
    ("btmp", "account", "root", r"^var/log/btmp", "failed-login history unavailable"),
    ("lastlog", "account", "root", r"^var/log/lastlog$|^var/lib/lastlog/", ""),
    ("auditd log", "evtx", "root", r"^var/log/audit/audit\.log", "auditd not installed - no EXECVE history"),
    ("Shell history", "exec", "root", r"(^|/)\.(bash|zsh|sh)_history$|fish_history$|\.zhistory$", ""),
    ("Crontabs", "persist", "root", r"^(etc/crontab|etc/cron\.d/|var/spool/cron/)", ""),
    ("systemd units", "persist", "root", r"^(etc|usr/lib|lib)/systemd/system/", ""),
    ("SSH authorized_keys", "remote", "root", r"/\.ssh/authorized_keys2?$", "no key-based SSH access configured"),
    ("SSH server config", "remote", "root", r"^etc/ssh/sshd_config$", ""),
    ("Package database", "apps", "root", r"^var/lib/dpkg/status$|^var/lib/rpm/", ""),
    ("Package logs", "apps", "root", r"^var/log/(dpkg\.log|apt/history\.log|yum\.log|dnf)", ""),
    ("Web server logs", "apps", "root", r"^var/log/(apache2?|httpd|nginx)/", "no web server on this host"),
    ("UAC bodyfile", "fs", "uac", r"^bodyfile/bodyfile\.txt$", "no file system timeline possible (bodyfile artifact not run)"),
    ("UAC live response (processes)", "live", "uac", r"^live_response/process/", "live_response artifacts not run"),
    ("UAC live response (network)", "live", "uac", r"^live_response/network/", ""),
    ("UAC hash_executables", "live", "uac", r"^hash_executables/", ""),
    ("uac.log", "info", "uac", r"^uac\.log$", ""),
]


def task_inventory(job: Job, t: Task):
    from .modules import file_index
    root_rels = [r for r, _ in file_index(_root(job))]
    uac_rels = [r for r, _ in file_index(job.layout.uac)] if job.layout.uac and job.layout.uac.is_dir() else []
    rows, gaps = [], []
    for name, cat, base, rx, note in EXPECTED:
        r = re.compile(rx)
        n = sum(1 for x in (root_rels if base == "root" else uac_rels) if r.search(x))
        rows.append([name, cat, n, note if not n else ""])
        if not n and not (base == "uac" and not job.layout.uac):
            if name.startswith(("Web server", "SSH authorized", "auditd", "Package logs")):
                gaps.append(f"[INFO] {name}: {note or 'not present'}")
            else:
                gaps.append(f"[MISSING] {name}: {note or 'not present in collection'}")
    notes = []
    for p in uac_files(job, r"^uac\.log$"):
        for line in iter_lines(p):
            if re.search(r"\b(error|fail(ed)?|denied|cannot|not found)\b", line, re.I):
                notes.append(f"[UAC] {line[:250]}")
                if len(notes) >= 50:
                    break
    d = job.cat_dir("info")
    with writer(d / job.name("Artifact_Inventory"), ["Artifact", "Category", "FilesFound", "NoteIfMissing"]) as w:
        w.writerows(rows)
    if job.layout.symlinks:
        notes.append(f"[INFO] {len(job.layout.symlinks)} symlinks recorded (not extracted) - see links_manifest.csv "
                     f"in the work folder")
    txt = ["COLLECTION GAP REPORT (Linux / Unix)", "=" * 60, ""] + (gaps or ["No gaps detected for tracked artifacts."]) \
        + ["", "COLLECTOR LOG NOTES", "-" * 60] + (notes or ["none"])
    (d / job.name("Collection_Gaps", "txt")).write_text("\n".join(txt) + "\n", encoding="utf-8")
    missing = sum(1 for g in gaps if g.startswith("[MISSING]"))
    return f"{sum(1 for r in rows if r[2])}/{len(rows)} artifact types present, {missing} gaps"


# =============================================================================== activity timeline
def task_activity_timeline(job: Job, t: Task):
    """Key events from every parsed source in one sorted timeline (the Linux 'super timeline light')."""
    tl = postproc._SortedSpill(job.cat_dir("info"), key=lambda r: r[0])

    def src(cat, stem):
        p = job.cat_dir(cat) / job.name(stem)
        return postproc.iter_csv(p) if p.is_file() else []

    for stem in ("Auth_Events", "Auth_Events_Journal"):
        for r in src("account", stem):
            if r.get("EventType") in ("SESSION_START",):
                continue
            tl.append([r["Timestamp"], r["TimeZone"], stem.replace("_Events", ""), r["EventType"],
                       r.get("User", ""), r.get("SourceIP", ""),
                       r.get("Command") or r.get("TargetUser") or r.get("Message", "")[:300]])
    for r in src("account", "Logins"):
        if r.get("RecordType") in ("USER_PROCESS", "BOOT_TIME") or "btmp" in r.get("Source", ""):
            ev = "login failed (btmp)" if "btmp" in r.get("Source", "") else r["RecordType"].lower()
            tl.append([r["Timestamp"], "UTC", "wtmp/btmp", ev, r.get("User", ""), r.get("IP") or r.get("Host", ""),
                       r.get("Terminal", "")])
    for r in src("exec", "Shell_History"):
        if r.get("Timestamp"):
            tl.append([r["Timestamp"], "UTC", "shell history", "command" + (" (SUSPICIOUS)" if r.get("Suspicious") else ""),
                       r.get("User", ""), "", r.get("Command", "")[:500]])
    for r in src("exec", "Audit_Execve"):
        tl.append([r["Timestamp"], "UTC", "auditd", "execve" + (" (SUSPICIOUS)" if r.get("Suspicious") else ""),
                   r.get("AUID", ""), "", r.get("CommandLine", "")[:500]])
    for r in src("apps", "Package_History"):
        tl.append([r["Timestamp"], r["TimeZone"], "packages", r.get("Action", ""), "", "", r.get("Package", "")[:500]])
    for r in src("persist", "Persistence"):
        if r.get("Suspicious") or not r.get("Scope", "").startswith("vendor"):
            if r.get("FileModified(UTC)"):
                tl.append([r["FileModified(UTC)"], "UTC", "persistence", f"{r['Mechanism']} file modified"
                           + (" (SUSPICIOUS)" if r.get("Suspicious") else ""), r.get("User", ""), "",
                           f"{r['Path']} {r.get('Entry', '')[:300]}"])
    for r in src("hunt", "Suspicious_Files"):
        tl.append([r["Modified"], "UTC", "file system", f"suspicious file modified ({r['Reason']})", r.get("UID", ""),
                   "", r.get("Path", "")])
    for stem in ("Sigma_ChopChopGo", "Sigma_Zircolite"):
        for r in src("hunt", stem):
            tl.append([r["Timestamp"], r["TimeZone"], f"Sigma ({r['Engine']})",
                       f"{r.get('Level') or 'rule'}: {r['RuleTitle']}", "", "", r.get("Details", "")[:400]])
    for r in src("hunt", "Web_Suspicious_Requests"):
        tl.append([r["Timestamp"], "UTC", "web", f"suspicious request ({r['Reason']})", "", r.get("ClientIP", ""),
                   f"{r.get('Method', '')} {r.get('URL', '')[:400]} -> {r.get('Status', '')}"])
    if not tl.n:
        raise SkipTask("no timestamped events parsed")
    with writer(job.cat_dir("info") / job.name("Activity_Timeline"),
                ["Timestamp", "TimeZone", "Source", "Event", "User", "Remote", "Details"]) as w:
        tl.write_sorted(w)
    return f"{tl.n:,} events"


# =============================================================================== graph
def build_processing(job: Job) -> None:
    from .modules import task_summary, task_velociraptor
    cfg = job.cfg
    tasks: list[Task] = []

    def T(key, name, tool, cat, fn, deps=None, pool="normal", soft=False, module=None):
        if module and not module_enabled(cfg, module):
            return
        tasks.append(Task(key, name, tool, cat, fn, deps or [], pool, soft))

    T("sysinfo", "System information (Linux)", "python", "info", task_sysinfo)
    T("inventory", "Artifact inventory & collection gaps", "python", "info", task_inventory, deps=["sysinfo"], soft=True)
    after = ["sysinfo"]  # host time zone is needed to convert syslog times
    T("accounts", "User accounts (passwd/shadow/group)", "python", "account", task_accounts, module="linux_accounts")
    T("logins", "Login records (wtmp/btmp/lastlog)", "python", "account", task_logins, module="linux_logins")
    T("syslog", "Syslog & auth logs", "python", "evtx", task_syslog, deps=after, soft=True, pool="heavy",
      module="linux_syslog")
    T("journal", "systemd journal", "journalctl", "evtx", task_journal, deps=after, soft=True, pool="heavy",
      module="linux_journal")
    T("ssh_summary", "SSH logins by source IP", "python", "remote", task_ssh_summary, deps=["syslog", "journal"],
      soft=True, module="linux_syslog")
    T("audit", "auditd log (EXECVE, logins)", "python", "evtx", task_audit, module="linux_audit")
    T("history", "Shell history", "python", "exec", task_history, module="linux_history")
    T("persistence", "Persistence (cron, systemd, rc, keys...)", "python", "persist", task_persistence,
      module="linux_persistence")
    T("fs_timeline", "File system timeline (bodyfile)", "mactime", "fs", task_fs_timeline, pool="heavy",
      module="linux_fs_timeline")
    T("suspicious_files", "Suspicious files (bodyfile)", "python", "hunt", task_suspicious_files,
      module="linux_suspicious_files")
    T("packages", "Installed packages & history", "python", "apps", task_packages, deps=after, soft=True,
      module="linux_packages")
    T("weblogs", "Web server access logs", "python", "apps", task_weblogs, module="linux_weblogs")
    T("network", "Network config & SSH keys", "python", "network", task_network, module="linux_network")
    T("live_response", "UAC live response", "python", "live", task_live_response, module="uac_live_response")
    # Sigma hunting - the Linux counterparts of Chainsaw / Hayabusa
    T("chopchopgo", "ChopChopGo Sigma hunt (syslog/journal)", "ChopChopGo", "hunt", task_chopchopgo,
      deps=["sysinfo", "journal"], soft=True, pool="heavy", module="chopchopgo")
    T("zircolite", "Zircolite Sigma hunt (auditd)", "Zircolite", "hunt", task_zircolite, pool="heavy",
      module="zircolite")
    if job.layout.velo_results:
        T("velociraptor", "Velociraptor live response results", "python", "live", task_velociraptor,
          module="velociraptor")
    T("activity_timeline", "Activity timeline (all sources)", "python", "info", task_activity_timeline,
      deps=[x.key for x in tasks if x.key not in ("sysinfo", "inventory")], soft=True)
    keys = [x.key for x in tasks]
    T("summary", "Processing summary report", "python", "info", task_summary, deps=keys, soft=True)
    job.add(*tasks)
