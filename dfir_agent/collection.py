"""Collection discovery, decryption, extraction and normalisation.

Supported inputs
  * Velociraptor offline collector zip (optionally password protected -> inner data.zip, AES)
  * Velociraptor collection already unzipped (folder with uploads/ + log.json)
  * KAPE / generic triage folder (drive folders such as C/Windows/...)

Every collection is normalised to:
  <work>/files/<DRIVE>/...        decoded, Windows-safe file names, original mtimes
  <work>/velociraptor/results/    Velociraptor artifact results (JSONL)
  <work>/velociraptor/meta/       log.json, collection_context.json, requests.json, uploads.json
  <work>/velociraptor/sparse_idx/ sparse index sidecars (.idx) after files were rebuilt
"""
from __future__ import annotations

import calendar
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import struct
import tarfile
import time
import urllib.parse
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import pyzipper

COLLECTION_RX = re.compile(
    r"Collection-(?P<host>.+?)-(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2}[_+\-0-9Z]*)", re.I)
# UAC (Unix-like Artifacts Collector): uac-<hostname>-<os>-<YYYYMMDDHHMMSS>[.tar.gz|.tar|.zip]
UAC_OS = ("aix", "esxi", "freebsd", "linux", "macos", "netbsd", "netscaler", "openbsd", "solaris")
UAC_RX = re.compile(rf"^uac-(?P<host>.+)-(?P<os>{'|'.join(UAC_OS)})-(?P<ts>\d{{14}})", re.I)
_TAR_RX = re.compile(r"\.(tar\.gz|tgz|tar)$", re.I)
IN_PLACE = {"kape_dir", "uac_dir"}  # processed where they are, never extracted or deleted
META_FILES = {"log.json", "log.json.index", "collection_context.json", "requests.json",
              "uploads.json", "uploads.json.index"}
# '/' and '\\' are included: a URL-decoded component (e.g. '%2Fetc' or '..%2F..') must never add path levels
_BAD_CHARS = re.compile(r'[<>:"|?*/\\\x00-\x1f]')
_DRIVE_RX = re.compile(r"^(?:\\\\[.?]\\)?([A-Za-z]):?$")
_VSS_RX = re.compile(r"HarddiskVolumeShadowCopy(\d+)", re.I)
CHUNK = 4 * 1024 * 1024


class PasswordError(Exception):
    pass


@dataclass
class InputItem:
    path: Path
    kind: str            # velo_zip | velo_dir | kape_dir | uac_tar | uac_zip | uac_dir
    host: str
    stamp: str = ""
    password: str | None = None
    encrypted: bool = False
    os: str = ""         # UAC: OS name from the file name (linux, macos, ...)

    @property
    def label(self) -> str:
        return f"{self.host}_{self.stamp}" if self.stamp else self.host


@dataclass
class Layout:
    root: Path                         # normalised work root
    files: Path                        # <root>/files
    drives: dict[str, Path] = field(default_factory=dict)
    system_drive: str | None = None
    velo_results: Path | None = None
    velo_meta: Path | None = None
    sparse_rebuilt: list[str] = field(default_factory=list)
    os: str = "windows"                # windows | linux (any Unix-like root file system)
    rootfs: Path | None = None         # Unix: the collected '/' (UAC [root], Velociraptor uploads)
    uac: Path | None = None            # UAC: live_response/, bodyfile/, hash_executables/, uac.log
    symlinks: dict[str, str] = field(default_factory=dict)  # '/etc/localtime' -> link target (not created)


# --------------------------------------------------------------------------- discovery
def _host_from_name(p: Path) -> tuple[str, str]:
    m = COLLECTION_RX.search(p.name)
    if m:
        return m.group("host"), m.group("ts").rstrip("_")
    return re.sub(r"\.(zip|7z)$", "", p.name, flags=re.I), ""


def _is_velo_dir(d: Path) -> bool:
    return (d / "uploads").is_dir() or ((d / "log.json").is_file() and (d / "results").is_dir())


def _is_kape_dir(d: Path) -> bool:
    for c in d.iterdir():
        if c.is_dir() and re.fullmatch(r"[A-Za-z](%3A|_|:)?", c.name) and (c / "Windows").exists():
            return True
    return (d / "Windows" / "System32").is_dir()


def _is_collection_zip(p: Path) -> bool:
    try:
        with pyzipper.AESZipFile(p) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    return "data.zip" in names or any(n.startswith(("uploads/", "results/")) for n in names[:50]) \
        or "collection_context.json" in names


def _uac_names(names: Iterable[str]) -> bool:
    for i, n in enumerate(names):
        n = n[2:] if n.startswith("./") else n
        if n == "uac.log" or n.startswith(("[root]/", "live_response/", "bodyfile/")):
            return True
        if i > 2000:
            break
    return False


def _is_uac_dir(d: Path) -> bool:
    return (d / "[root]").is_dir() or ((d / "uac.log").is_file() and (d / "live_response").is_dir())


def _is_uac_archive(p: Path) -> str | None:
    """'uac_tar' / 'uac_zip' when p is a UAC output archive (checked by content, not only by name)."""
    if _TAR_RX.search(p.name):
        try:
            with tarfile.open(p, "r|*") as tf:  # stream mode: uac.log is the first member
                return "uac_tar" if _uac_names(m.name for m in tf) else None
        except (tarfile.TarError, OSError, EOFError):
            return None
    if p.suffix.lower() == ".zip":
        try:
            with pyzipper.AESZipFile(p) as z:
                return "uac_zip" if _uac_names(z.namelist()) else None
        except (zipfile.BadZipFile, OSError):
            return None
    return None


def _uac_item(p: Path, kind: str) -> InputItem:
    base = _TAR_RX.sub("", re.sub(r"\.zip$", "", p.name, flags=re.I))
    m = UAC_RX.match(base)
    if m:
        return InputItem(p, kind, m.group("host"), m.group("ts"), os=m.group("os").lower())
    return InputItem(p, kind, base, "")


def _classify_file(p: Path) -> InputItem | None:
    kind = _is_uac_archive(p) if (_TAR_RX.search(p.name) or p.suffix.lower() == ".zip") else None
    if kind:
        return _uac_item(p, kind)
    if p.suffix.lower() == ".zip" and _is_collection_zip(p):
        h, s = _host_from_name(p)
        return InputItem(p, "velo_zip", h, s)
    return None


def discover(paths: Iterable[str]) -> list[InputItem]:
    items: list[InputItem] = []
    for raw in paths:
        p = Path(win_to_wsl(raw)).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"input not found: {raw}")
        if p.is_file():
            it = _classify_file(p)
            if it:
                items.append(it)
            continue
        if _is_uac_dir(p):
            items.append(_uac_item(p, "uac_dir"))
        elif _is_velo_dir(p):
            h, s = _host_from_name(p)
            items.append(InputItem(p, "velo_dir", h, s))
        elif _is_kape_dir(p):
            items.append(InputItem(p, "kape_dir", p.name))
        else:  # container folder -> scan one level for collections
            for c in sorted(p.iterdir()):
                if c.is_file():
                    it = _classify_file(c)
                    if it:
                        items.append(it)
                elif c.is_dir() and _is_uac_dir(c):
                    items.append(_uac_item(c, "uac_dir"))
                elif c.is_dir() and (_is_velo_dir(c) or _is_kape_dir(c)):
                    h, s = _host_from_name(c)
                    items.append(InputItem(c, "velo_dir" if _is_velo_dir(c) else "kape_dir", h, s))
    # de-duplicate labels
    seen: dict[str, int] = {}
    for it in items:
        n = seen.get(it.label, 0)
        seen[it.label] = n + 1
        if n:
            it.stamp = f"{it.stamp}_{n}" if it.stamp else str(n)
    return items


def win_to_wsl(p: str) -> str:
    """Accept Windows style paths (D:\\x\\y) when running inside WSL."""
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p)
    if m and os.name != "nt":
        return f"/mnt/{m.group(1).lower()}/" + m.group(2).replace("\\", "/")
    return p


# --------------------------------------------------------------------------- passwords
def needs_password(item: InputItem) -> bool:
    if item.kind not in ("velo_zip", "uac_zip"):  # UAC: zip -P (tar archives have no password)
        return False
    with pyzipper.AESZipFile(item.path) as z:
        return any(i.flag_bits & 0x1 for i in z.infolist())


def check_password(item: InputItem, pwd: str) -> bool:
    """A wrong password can pass the header check (ZipCrypto: 1 in 256, AES: 1 in 65536) and then fail
    while decompressing - or produce garbage. Small entries are read completely so the CRC/HMAC is
    verified too; any decode error counts as a wrong password."""
    with pyzipper.AESZipFile(item.path) as z:
        enc = [i for i in z.infolist() if i.flag_bits & 0x1]
        info = min(enc, key=lambda i: (i.file_size == 0, i.file_size))  # smallest non-empty entry
        z.setpassword(pwd.encode())
        try:
            with z.open(info) as fh:
                if info.file_size <= 16 * 1024 * 1024:
                    while fh.read(CHUNK):
                        pass
                else:
                    fh.read(64 * 1024)
            return True
        except (RuntimeError, zipfile.BadZipFile, zlib.error, ValueError, EOFError):
            return False


# --------------------------------------------------------------------------- name mapping
def _safe(component: str) -> str:
    """One Windows-safe path component; never empty, '.', '..' or containing a separator."""
    c = _BAD_CHARS.sub("_", component).rstrip(" .")
    return c or "_"


def _safe_posix(component: str) -> str:
    """Unix path component kept as collected, except NUL and the '.'/'..' directory references."""
    c = component.replace("\x00", "_")
    return "_" if c in ("", ".", "..") else c


def _inside(p: Path, root: Path) -> bool:
    """True when p stays below root (lexically - the target does not exist yet)."""
    return os.path.normpath(p).startswith(os.path.normpath(root) + os.sep)


def map_upload(components: list[str]) -> list[str] | None:
    """['uploads','auto','C:','Windows',...] -> ['C','Windows',...]"""
    if len(components) < 3 or components[0] != "uploads":
        return None
    dev = components[2]
    m = _DRIVE_RX.match(dev)
    if m:
        top = m.group(1).upper()
    else:
        v = _VSS_RX.search(dev)
        top = f"VSS{v.group(1)}" if v else _safe(dev.strip("\\/.?"))
    return [top] + [_safe(c) for c in components[3:]]


def _components(name: str) -> list[str]:
    # Velociraptor URL-encodes each path component; '/' is the separator
    return [urllib.parse.unquote(c) for c in name.split("/") if c != ""]


# --------------------------------------------------------------------------- extraction
class Extractor:
    """Decrypt + extract a collection into a normalised layout with progress callbacks."""

    def __init__(self, item: InputItem, work: Path, hash_files: bool = True,
                 max_sparse_expand: int = 8 * 1024 ** 3,
                 progress: Callable[[int, int, str], None] | None = None,
                 log: Callable[[str], None] | None = None):
        self.item, self.work = item, work
        self.hash_files = hash_files
        self.max_sparse = max_sparse_expand
        self.progress = progress or (lambda done, total, msg: None)
        self.log = log or (lambda m: None)
        self.manifest: list[tuple[str, str, int, str, str]] = []
        self.links: list[tuple[str, str, str]] = []  # (archive path, type, target) - links are recorded, not created

    @property
    def is_uac(self) -> bool:
        return self.item.kind.startswith("uac")

    # -- public
    def run(self) -> Layout:
        lay = Layout(root=self.work, files=self.work / "files")
        done_marker = self.work / ".extracted"
        in_place = self.item.kind in IN_PLACE
        if in_place:  # KAPE / unpacked UAC folders are processed where they are
            lay.files = self.item.path / "[root]" if self.item.kind == "uac_dir" else self.item.path
            if self.item.kind == "uac_dir":
                lay.uac = self.item.path
        elif done_marker.exists():
            self.log("extraction marker found - reusing previously extracted files")
            self.progress(1, 1, "reused")
        elif self.item.kind in ("velo_zip", "uac_zip"):
            self._extract_zip(lay)
        elif self.item.kind == "velo_dir":
            self._extract_velo_dir(lay)
        elif self.item.kind == "uac_tar":
            self._extract_tar(lay)
        if not in_place and not done_marker.exists():
            if not self.is_uac:
                self._rebuild_sparse(lay)
            self._write_manifest()
            self._write_links()
            done_marker.write_text(_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        self._finalise_layout(lay)
        return lay

    # -- tar (UAC)
    def _extract_tar(self, lay: Layout) -> None:
        """Stream a UAC tar/tar.gz. Only regular files and directories are written: symlinks are recorded
        (their targets are absolute paths of the evidence host) and hard links become copies."""
        total = self.item.path.stat().st_size or 1
        last = 0.0
        with open(self.item.path, "rb") as raw, tarfile.open(fileobj=raw, mode="r|*") as tf:
            for m in tf:
                now = time.monotonic()
                if now - last > 0.2:
                    last = now
                    self.progress(min(raw.tell(), total), total, "extracting")
                if m.isdir():
                    dst = self._target(m.name, lay)
                    if dst:
                        dst.mkdir(parents=True, exist_ok=True)
                    continue
                if m.issym() or m.islnk():
                    self.links.append((m.name, "symlink" if m.issym() else "hardlink", m.linkname))
                    if m.islnk():
                        src, dst = self._target(m.linkname, lay), self._target(m.name, lay)
                        if src and dst and src.is_file() and not src.is_symlink():
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(src, dst)
                    continue
                if not m.isfile():  # devices, FIFOs
                    continue
                if m.issparse() and m.size > self.max_sparse:
                    self.log(f"sparse file not expanded ({m.size / 1048576:.0f} MB apparent size): {m.name}")
                    continue
                dst = self._target(m.name, lay)
                if dst is None:
                    continue
                dst.parent.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha256() if self.hash_files else None
                src = tf.extractfile(m)
                with open(dst, "wb") as out:
                    while b := src.read(CHUNK):
                        out.write(b)
                        if h:
                            h.update(b)
                try:
                    os.utime(dst, (m.mtime, m.mtime))
                except (OverflowError, ValueError, OSError):
                    pass
                self.manifest.append((m.name, str(dst.relative_to(self.work)), m.size,
                                      h.hexdigest() if h else "", _utc_str(m.mtime)))
        self.progress(total, total, "extracted")

    def _write_links(self) -> None:
        if not self.links:
            return
        import csv
        with open(self.work / "links_manifest.csv", "w", newline="", encoding="utf-8",
                  errors="backslashreplace") as fh:
            w = csv.writer(fh)
            w.writerow(["ArchivePath", "LinkType", "Target"])
            w.writerows(self.links)

    # -- zip
    def _extract_zip(self, lay: Layout) -> None:
        tmp = self.work / "_tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        with pyzipper.AESZipFile(self.item.path) as outer:
            if self.item.password:
                outer.setpassword(self.item.password.encode())
            names = outer.namelist()
            if "data.zip" in names:
                info = outer.getinfo("data.zip")
                inner_path = tmp / "data.zip"
                self.log(f"decrypting data.zip ({info.file_size / 1048576:.0f} MB)")
                with outer.open(info) as src, open(inner_path, "wb") as dst:
                    copied = 0
                    while True:
                        b = src.read(CHUNK)
                        if not b:
                            break
                        dst.write(b)
                        copied += len(b)
                        # decryption is ~35% of the extraction stage
                        self.progress(int(copied * 0.35), info.file_size, "decrypting")
                with zipfile.ZipFile(inner_path) as inner:
                    self._extract_entries(inner, lay, base_frac=0.35)
                inner_path.unlink(missing_ok=True)
            else:
                self._extract_entries(outer, lay, base_frac=0.0)
        shutil.rmtree(tmp, ignore_errors=True)

    def _extract_entries(self, z: zipfile.ZipFile, lay: Layout, base_frac: float) -> None:
        infos = [i for i in z.infolist() if not i.is_dir()]
        total = sum(i.file_size for i in infos) or 1
        done = 0
        last = 0.0
        for info in infos:
            if (info.external_attr >> 16) & 0o170000 == 0o120000:  # Unix symlink: content = target path
                with z.open(info) as src:
                    self.links.append((info.filename, "symlink",
                                       src.read(4096).decode("utf-8", "surrogateescape")))
                continue
            rel = self._target(info.filename, lay)
            if rel is None:
                continue
            dst = rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256() if self.hash_files else None
            with z.open(info) as src, open(dst, "wb") as out:
                while True:
                    b = src.read(CHUNK)
                    if not b:
                        break
                    out.write(b)
                    if h:
                        h.update(b)
                    done += len(b)
                    now = time.monotonic()
                    if now - last > 0.2:
                        last = now
                        frac = base_frac + (1 - base_frac) * done / total
                        self.progress(int(frac * 1000), 1000, "extracting")
            ts = _zip_mtime(info)
            if ts:
                try:
                    os.utime(dst, (ts, ts))
                except (OverflowError, ValueError, OSError):
                    pass
            self.manifest.append((info.filename, str(dst.relative_to(self.work)), info.file_size,
                                  h.hexdigest() if h else "", _utc_str(ts) if ts else ""))
        self.progress(1000, 1000, "extracted")

    # -- unzipped velociraptor folder
    def _extract_velo_dir(self, lay: Layout) -> None:
        src_root = self.item.path
        files = [p for p in src_root.rglob("*") if p.is_file()]
        total = sum(p.stat().st_size for p in files) or 1
        done = 0
        for p in files:
            rel = p.relative_to(src_root).as_posix()
            dst = self._target(rel, lay)
            if dst is None:
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256() if self.hash_files else None
            with open(p, "rb") as s, open(dst, "wb") as d:
                while b := s.read(CHUNK):
                    d.write(b)
                    if h:
                        h.update(b)
            shutil.copystat(p, dst, follow_symlinks=False)
            done += p.stat().st_size
            self.progress(done, total, "copying")
            self.manifest.append((rel, str(dst.relative_to(self.work)), p.stat().st_size,
                                  h.hexdigest() if h else "", ""))

    def _target(self, name: str, lay: Layout) -> Path | None:
        p = self._target_unchecked(name, lay)
        if p is not None and not _inside(p, self.work):
            self.log(f"skipped archive entry escaping the work folder: {name!r}")
            return None
        return p

    def _target_unchecked(self, name: str, lay: Layout) -> Path | None:
        if self.is_uac:
            # UAC: no URL encoding; '[root]/...' is the collected file system, everything else is UAC output
            comps = [_safe_posix(c) for c in name.split("/") if c not in ("", ".")]
            if not comps:
                return None
            if comps[0] == "[root]":
                return lay.files.joinpath(*comps[1:]) if len(comps) > 1 else lay.files
            return self.work.joinpath("uac", *comps)
        comps = _components(name)
        if not comps:
            return None
        if comps[0] == "uploads":
            mapped = map_upload(comps)
            return lay.files.joinpath(*mapped) if mapped else None
        if comps[0] == "results":
            return self.work / "velociraptor" / "results" / _safe("_".join(comps[1:]))
        if len(comps) == 1 and comps[0] in META_FILES:
            return self.work / "velociraptor" / "meta" / comps[0]
        return self.work / "velociraptor" / "other" / Path(*[_safe(c) for c in comps])

    # -- sparse files (.idx sidecars)
    def _rebuild_sparse(self, lay: Layout) -> None:
        if not lay.files.exists():
            return
        idx_dir = self.work / "velociraptor" / "sparse_idx"
        for idx in list(lay.files.rglob("*.idx")):
            try:
                if idx.stat().st_size > 16 * 1024 * 1024:
                    continue
                head = idx.read_bytes()[:16]
                if not head.startswith(b'{"ranges"'):
                    continue
                ranges = json.loads(idx.read_text())["ranges"]
            except (OSError, ValueError, KeyError):
                continue
            data = idx.with_suffix("")
            dest_idx = idx_dir / idx.relative_to(lay.files)
            dest_idx.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(idx), dest_idx)
            if not data.exists() or not ranges:
                continue
            last = ranges[-1]
            orig_size = last.get("original_offset", 0) + last.get("length", 0)
            name = data.name.lower()
            if name.endswith("$j") or orig_size > self.max_sparse:
                # $UsnJrnl:$J is mostly leading sparse space (tens of GB); the compacted
                # stream is parsed correctly by MFTECmd, so keep it as collected.
                self.log(f"sparse file kept compacted: {data.relative_to(lay.files)} "
                         f"(original {orig_size / 1048576:.0f} MB)")
                continue
            if data.stat().st_size == orig_size:
                continue
            rebuilt = data.with_name(data.name + ".rebuild")
            with open(data, "rb") as s, open(rebuilt, "wb") as d:
                for r in ranges:
                    flen = r.get("file_length", 0)
                    if not flen:
                        continue
                    s.seek(r.get("file_offset", 0))
                    d.seek(r.get("original_offset", 0))
                    remaining = flen
                    while remaining:
                        b = s.read(min(CHUNK, remaining))
                        if not b:
                            break
                        d.write(b)
                        remaining -= len(b)
                d.truncate(orig_size)
            st = data.stat()
            os.replace(rebuilt, data)
            os.utime(data, (st.st_atime, st.st_mtime))
            lay.sparse_rebuilt.append(str(data.relative_to(lay.files)))
        if lay.sparse_rebuilt:
            self.log(f"rebuilt {len(lay.sparse_rebuilt)} sparse files to original layout")
            (self.work / "velociraptor" / "sparse_rebuilt.txt").write_text("\n".join(lay.sparse_rebuilt))

    def _write_manifest(self) -> None:
        if not self.manifest:
            return
        import csv
        mf = self.work / "extraction_manifest.csv"
        # Unix file names need not be valid UTF-8 (tarfile keeps them as surrogate escapes)
        with open(mf, "w", newline="", encoding="utf-8", errors="backslashreplace") as fh:
            w = csv.writer(fh)
            w.writerow(["ArchivePath", "ExtractedPath", "Size", "SHA256_AsCollected", "ArchiveMTime"])
            w.writerows(self.manifest)

    def _finalise_layout(self, lay: Layout) -> None:
        if (self.work / "velociraptor" / "results").is_dir():
            lay.velo_results = self.work / "velociraptor" / "results"
        if (self.work / "velociraptor" / "meta").is_dir():
            lay.velo_meta = self.work / "velociraptor" / "meta"
        if not lay.files.exists():
            return
        for d in sorted(lay.files.iterdir()):
            if d.is_dir():
                letter = d.name[0].upper() if re.fullmatch(r"[A-Za-z](%3A|_)?", d.name) else d.name
                lay.drives[letter] = d
        for letter, d in lay.drives.items():
            if find_ci(d, "Windows/System32/config/SYSTEM"):
                lay.system_drive = letter
                break
        if lay.system_drive is None and find_ci(lay.files, "Windows/System32/config/SYSTEM"):
            lay.drives = {"C": lay.files}
            lay.system_drive = "C"
        if lay.system_drive is None and (self.is_uac or _looks_unix(lay.files)):
            # UAC collections, or Velociraptor collections of Linux/macOS hosts (uploads/auto/etc/...)
            lay.os = "linux"
            lay.rootfs = lay.files
            lay.drives = {"/": lay.files}
            if lay.uac is None and (self.work / "uac").is_dir():
                lay.uac = self.work / "uac"
            lay.symlinks = self._load_links()

    def _load_links(self) -> dict[str, str]:
        """Symlinks inside the collected file system: '/etc/localtime' -> '/usr/share/zoneinfo/...'."""
        out: dict[str, str] = {}
        mf = self.work / "links_manifest.csv"
        if mf.is_file():
            import csv
            with open(mf, encoding="utf-8", errors="replace", newline="") as fh:
                for r in csv.DictReader(fh):
                    name = r.get("ArchivePath", "")
                    name = name[2:] if name.startswith("./") else name
                    if name.startswith("[root]/") and r.get("LinkType") == "symlink":
                        out["/" + name[len("[root]/"):]] = r.get("Target", "")
        elif self.item.kind == "uac_dir" and self.item.path.joinpath("[root]").is_dir():
            root = self.item.path / "[root]"
            for d, dirs, files in os.walk(root):
                for n in files + dirs:
                    p = Path(d) / n
                    if p.is_symlink():
                        try:
                            out["/" + p.relative_to(root).as_posix()] = os.readlink(p)
                        except OSError:
                            pass
        return out


def _looks_unix(files: Path) -> bool:
    return files.is_dir() and (files / "etc").is_dir() and not (files / "Windows").exists()


def _utc_str(ts: float) -> str:
    try:
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, ValueError, OSError):
        return ""


def _zip_mtime(info: zipfile.ZipInfo) -> float | None:
    """UTC mtime: prefer the extended-timestamp extra field (0x5455), else DOS time as UTC."""
    extra = info.extra or b""
    i = 0
    while i + 4 <= len(extra):
        hid, size = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4:i + 4 + size]
        if hid == 0x5455 and len(body) >= 5 and body[0] & 1:
            return float(struct.unpack_from("<I", body, 1)[0])
        i += 4 + size
    if info.date_time[0] <= 1980:
        return None
    try:
        return float(calendar.timegm(info.date_time + (0, 0, 0)))
    except (OverflowError, ValueError):
        return None


def find_ci(base: Path, rel: str) -> Path | None:
    """Case-insensitive path resolution (Linux is case sensitive, Windows evidence is not)."""
    cur = base
    for part in rel.strip("/").split("/"):
        if not cur.is_dir():
            return None
        direct = cur / part
        if direct.exists():
            cur = direct
            continue
        lp = part.lower()
        nxt = next((c for c in cur.iterdir() if c.name.lower() == lp), None)
        if nxt is None:
            return None
        cur = nxt
    return cur
