"""Basic system information from SYSTEM / SOFTWARE / SAM hives (python-registry)."""
from __future__ import annotations

import datetime as dt
import struct
from pathlib import Path

from Registry import Registry


def _val(key, name, default=None):
    try:
        return key.value(name).value()
    except Registry.RegistryValueNotFoundException:
        return default


def _sub(reg, path):
    try:
        return reg.open(path)
    except Registry.RegistryKeyNotFoundException:
        return None


def _filetime(b) -> str:
    try:
        ft = struct.unpack("<Q", bytes(b)[:8])[0] if not isinstance(b, int) else b
        if not ft:
            return ""
        return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ft // 10)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (struct.error, OverflowError, TypeError):
        return ""


def collect(system: Path | None, software: Path | None) -> dict:
    info: dict = {"ComputerName": "", "Interfaces": [], "Users": []}
    if system and system.is_file():
        reg = Registry.Registry(str(system))
        sel = _sub(reg, "Select")
        cur = _val(sel, "Current", 1) if sel else 1
        cs = f"ControlSet{cur:03d}"
        info["CurrentControlSet"] = cs
        k = _sub(reg, f"{cs}\\Control\\ComputerName\\ComputerName")
        if k:
            info["ComputerName"] = _val(k, "ComputerName", "")
        k = _sub(reg, f"{cs}\\Control\\TimeZoneInformation")
        if k:
            info["TimeZone"] = _val(k, "TimeZoneKeyName", "") or _val(k, "StandardName", "")
            bias = _val(k, "ActiveTimeBias")
            if isinstance(bias, int):
                bias = bias - (1 << 32) if bias > 0x7FFFFFFF else bias
                info["UTCOffset"] = f"UTC{'+' if bias <= 0 else '-'}{abs(bias) // 60:02d}:{abs(bias) % 60:02d}"
        k = _sub(reg, f"{cs}\\Control\\Windows")
        if k:
            info["LastShutdown"] = _filetime(_val(k, "ShutdownTime", b""))
        k = _sub(reg, f"{cs}\\Services\\Tcpip\\Parameters")
        if k:
            info["Domain"] = _val(k, "Domain", "") or _val(k, "DhcpDomain", "")
            info["Hostname(Tcpip)"] = _val(k, "Hostname", "")
        k = _sub(reg, f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces")
        if k:
            for iface in k.subkeys():
                ip = _val(iface, "IPAddress") or _val(iface, "DhcpIPAddress")
                if isinstance(ip, list):
                    ip = ", ".join(x for x in ip if x)
                if not ip or ip in ("0.0.0.0",):
                    continue
                info["Interfaces"].append({
                    "Interface": iface.name(),
                    "IPAddress": ip,
                    "DhcpServer": _val(iface, "DhcpServer", ""),
                    "DefaultGateway": ", ".join(g for g in (_val(iface, "DhcpDefaultGateway", []) or
                                                             _val(iface, "DefaultGateway", []) or []) if g),
                    "Domain": _val(iface, "DhcpDomain", "") or _val(iface, "Domain", ""),
                    "LastWrite": iface.timestamp().strftime("%Y-%m-%d %H:%M:%S UTC"),
                })
    if software and software.is_file():
        reg = Registry.Registry(str(software))
        k = _sub(reg, "Microsoft\\Windows NT\\CurrentVersion")
        if k:
            build = str(_val(k, "CurrentBuild", "") or _val(k, "CurrentBuildNumber", ""))
            product = _val(k, "ProductName", "")
            if build.isdigit() and int(build) >= 22000 and "Windows 10" in product:
                product = product.replace("Windows 10", "Windows 11")  # ProductName is stale on Win11
            info["ProductName"] = product
            info["EditionID"] = _val(k, "EditionID", "")
            info["DisplayVersion"] = _val(k, "DisplayVersion", "") or _val(k, "ReleaseId", "")
            ubr = _val(k, "UBR")
            info["Build"] = f"{build}.{ubr}" if ubr is not None else build
            inst = _val(k, "InstallDate")
            if isinstance(inst, int) and inst:
                info["InstallDate"] = dt.datetime.fromtimestamp(inst, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            info["RegisteredOwner"] = _val(k, "RegisteredOwner", "")
            info["RegisteredOrganization"] = _val(k, "RegisteredOrganization", "")
        k = _sub(reg, "Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        if k:
            for p in k.subkeys():
                info["Users"].append({"SID": p.name(), "ProfilePath": _val(p, "ProfileImagePath", ""),
                                      "KeyLastWrite": p.timestamp().strftime("%Y-%m-%d %H:%M:%S UTC")})
    return info


def render_text(info: dict, extra: dict) -> str:
    lines = ["=" * 70, " SYSTEM INFORMATION", "=" * 70]
    for k in ("ComputerName", "Domain", "ProductName", "EditionID", "DisplayVersion", "Build", "InstallDate",
              "RegisteredOwner", "RegisteredOrganization", "TimeZone", "UTCOffset", "LastShutdown",
              "CurrentControlSet"):
        if info.get(k):
            lines.append(f" {k:<24}: {info[k]}")
    if info.get("Interfaces"):
        lines += ["", " NETWORK INTERFACES"]
        for i in info["Interfaces"]:
            lines.append(f"  - {i['IPAddress']:<18} gw={i['DefaultGateway'] or '-':<16} dhcp={i['DhcpServer'] or '-':<16} "
                         f"domain={i['Domain'] or '-'}  ({i['Interface']}, last write {i['LastWrite']})")
    if info.get("Users"):
        lines += ["", " USER PROFILES"]
        for u in info["Users"]:
            lines.append(f"  - {u['SID']:<48} {u['ProfilePath']}")
    lines += ["", " COLLECTION"]
    for k, v in extra.items():
        lines.append(f" {k:<24}: {v}")
    return "\n".join(lines) + "\n"
