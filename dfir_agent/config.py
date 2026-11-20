"""Configuration loading (config.yaml next to the project, optionally overridden with --config)."""
from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

PROJECT_DIR = Path(__file__).resolve().parent.parent

# Output folder per artifact category (SANS "Windows Forensic Analysis" style)
CATEGORIES = {
    "info":     "00_Case_Info",
    "exec":     "01_Evidence_of_Execution",
    "fileopen": "02_File_and_Folder_Opening",
    "deleted":  "03_Deleted_Files",
    "fs":       "04_File_System",
    "evtx":     "05_Event_Logs",
    "registry": "06_Registry",
    "browser":  "07_Browser_Activity",
    "account":  "08_Account_Usage",
    "network":  "09_Network_Activity",
    "usb":      "10_External_Devices_USB",
    "persist":  "11_Persistence",
    "remote":   "12_Remote_Access",
    "live":     "13_Live_Response",
    "hunt":     "14_Threat_Hunting",
    "apps":     "15_Application_Artifacts",
}

DEFAULTS: dict = {
    "general": {
        "workers": 0,               # 0 = auto
        "heavy_task_limit": 2,      # concurrent memory-heavy tasks (~2 GB RAM each)
        "extract_limit": 2,         # concurrent collection extractions
        "keep_extracted": True,
        "hash_extracted": True,
        "max_sparse_expand_gb": 8,
        "work_dir": "~/dta-work",   # empty -> <output>/<host>/_extracted
    },
    "tools": {
        "dta_home": "~/.dfir-triage-agent",
        "ez_dir": "../Eric Zimmerman Tools/net",
        "ez_windows_only": ["SrumECmd", "SumECmd"],
        "recmd_batch": "Kroll_Batch.reb",
    },
    "collection": {"passwords": []},
    "modules": {},
    "event_log_views": [],
    "registry_routes": {},
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: str | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    files = [PROJECT_DIR / "config.yaml"]
    if path:
        files.append(Path(path))
    for f in files:
        if f.is_file():
            cfg = _merge(cfg, yaml.safe_load(f.read_text(encoding="utf-8")) or {})
    t = cfg["tools"]
    if os.environ.get("DTA_HOME"):  # same override setup.sh / installer.py honour
        t["dta_home"] = os.environ["DTA_HOME"]
    t["dta_home"] = str(Path(os.path.expanduser(t["dta_home"])))
    ez = Path(os.path.expanduser(t["ez_dir"]))
    t["ez_dir"] = str(ez if ez.is_absolute() else (PROJECT_DIR / ez).resolve())
    return cfg


def module_enabled(cfg: dict, name: str, default: bool = True) -> bool:
    return bool(cfg.get("modules", {}).get(name, {}).get("enabled", default))


def module_opt(cfg: dict, name: str, key: str, default=None):
    return cfg.get("modules", {}).get(name, {}).get(key, default)
