# DFIR Triage Agent

Automated triage processing for DFIR collections. It runs inside **WSL** (Ubuntu, Kali, ...) and processes
one or many **Velociraptor offline-collector** (KAPE `_SANS_Triage`) collections and **UAC** (Unix-like Artifacts
Collector) Linux collections **concurrently**. A live, colored dashboard shows the progress of every tool, and
results are sorted **per artifact category**. Linux processing is described in section 3a.

```
 ██████╗ ███████╗██╗██████╗
 ██╔══██╗██╔════╝██║██╔══██╗   T R I A G E   A G E N T
 ██║  ██║█████╗  ██║██████╔╝
 ██║  ██║██╔══╝  ██║██╔══██╗
 ██████╔╝██║     ██║██║  ██║
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝
```

## 1. Install or update (same command on a new machine or an existing one)

Copy the `DFIR-Triage-Agent` folder to the machine (optionally with your `Eric Zimmerman Tools` folder next to
it), then run inside WSL:

```bash
cd /mnt/d/Tools/DFIR-Triage-Agent    # wherever you copied the project
./setup.sh              # interactive: asks before any sudo/apt
./setup.sh -y           # non-interactive (accept defaults)
```

The only requirement is `python3`; `setup.sh` installs it with apt if it is missing. Everything else is done by
`installer.py`, which uses only the standard library. It checks the machine, installs whatever is missing, and
verifies every download. Running it again is safe: it only updates components that have a newer version.

| Component | Source (official) | How it is validated |
|---|---|---|
| Python libraries: rich, pyzipper, python-registry, PyYAML, numpy + Pillow (RDP cache reconstruction), psutil (CPU monitor) | PyPI | see "Python environment" below |
| .NET 10 runtime for Linux (runs the EZ tools) | Microsoft release metadata (`builds.dotnet.microsoft.com`) | **SHA-512** from Microsoft metadata |
| .NET 10 runtime for Windows (SrumECmd/SumECmd) | the installed one, else a private copy in `%LOCALAPPDATA%\DFIR-Triage-Agent` (no admin) | **SHA-512** |
| Eric Zimmerman tools | your folder (`tools.ez_dir`) if complete, else `download.ericzimmermanstools.com/net/` | **Authenticode signature = ZimTech LLC** (checked for your folder too) |
| Hayabusa (static musl build) | github.com/Yamato-Security/hayabusa releases | **SHA-256** = GitHub asset digest |
| Chainsaw + mappings/rules | github.com/WithSecureOpenSource/chainsaw releases | **SHA-256** = GitHub asset digest |
| Sigma rules (core) | github.com/SigmaHQ/sigma releases | **SHA-256** = GitHub asset digest |
| ChopChopGo (Sigma for Linux syslog/journald, bundled rules) | github.com/M00NLIG7/ChopChopGo releases | **SHA-256** = GitHub asset digest |
| Zircolite (Sigma for auditd / Sysmon for Linux, self-contained build + SigmaHQ Linux ruleset) | github.com/wagga40/Zircolite releases | **SHA-256** = GitHub asset digest |
| bmc-tools | github.com/ANSSI-FR/bmc-tools | pinned commit |
| RegRipper **4.0** (386 plugins) + Parse::Win32Registry | github.com/keydet89/RegRipper4.0 + CPAN | pinned commit; CPAN **SHA-256** |
| sleuthkit (`mactime`), perl | Ubuntu apt (only after you confirm) | apt; if skipped, a built-in Python `mactime` is used |

**Python environment (`--python`):**
- `auto` (default): if the current `python3` already has every library, it is reused. Otherwise an isolated venv
  is created in `~/.dfir-triage-agent/venv`, with pip bootstrapped from bootstrap.pypa.io when Ubuntu lacks
  `python3-venv`.
- `venv`: always use an isolated venv.
- `current`: install the missing libraries for the current Python (`pip --user`).

The choice is recorded in `~/.dfir-triage-agent/env.json`. `./dfir-triage` and `python3 dfir-triage.py` always use
that interpreter.

**Other options:** `--update-ez` downloads the latest EZ tools (signature-verified) instead of using your folder.
`--regripper 3` keeps RegRipper 3.0. `--no-system-packages` never calls sudo/apt. `--force` reinstalls everything.
At the end, setup links `dfir-triage` into `~/.local/bin`, so you can run it from any folder (open a new WSL
terminal first). If you move the project folder, run `setup.sh` again. `--no-link` skips this step.
`DTA_HOME=/path` installs to a different location. Versions, sources and hashes are recorded in
`~/.dfir-triage-agent/versions.json`.

SrumECmd and SumECmd need the Windows ESE libraries, so they run through WSL interop. Dirty databases are
recovered or repaired on a Windows-local scratch copy (`%LOCALAPPDATA%\Temp\DFIR-Triage-Agent`), because ESE
cannot repair databases on `\\wsl.localhost` paths. A database that still cannot be opened marks the task as
failed.

## 2. Run

From WSL (`./dfir-triage` and `python3 dfir-triage.py` are equivalent; both use the interpreter chosen by setup):
```bash
./dfir-triage -i /mnt/d/Evidence/Collection-HOST-2026-10-19T15_47_49_03_00.zip -o /mnt/d/Cases/IR-001
./dfir-triage -i /mnt/d/Evidence/ -o /mnt/d/Cases/IR-001            # every collection in the folder, concurrently
./dfir-triage -i a.zip -i b.zip -o /mnt/d/Cases/IR-001 -w 8 --heavy 3
```
From Windows PowerShell or Windows Terminal (Windows paths are accepted):
```powershell
.\dfir-triage.ps1 -i "D:\Evidence\Collection-HOST-....zip" -o "D:\Cases\IR-001"
.\dfir-triage.ps1 --setup
```

| Option | Meaning |
|---|---|
| `-i PATH` (repeatable) | collection zip, unzipped Velociraptor folder, KAPE folder, or a folder of collections |
| `-o DIR` | case output folder; one sub-folder per collection `<HOST>_<timestamp>` |
| `-p PASS` / `--password-file F` | zip password(s). Tried in order: CLI, file, `config.yaml`, `infected`, then an interactive prompt |
| `-w N`, `--heavy N` | max parallel tool processes / max parallel memory-heavy tasks (~2 GB RAM each) |
| `--work-dir DIR` | where collections are extracted (default `~/dta-work`, the WSL disk, 6-10x faster than `/mnt/d`) |
| `--skip a,b` | skip modules, e.g. `--skip regripper,chainsaw` |
| `--no-keep-extracted` | delete the extracted collection after processing |
| `--no-live` | plain colored line output (logs/CI) instead of the live dashboard |

**Dashboard.** With a single collection, every task is shown with its category, tool, progress bar, elapsed time
and the tool's latest output line. With multiple collections, you get a fleet overview (one row per collection)
plus an "Active tasks" table across all collections. Both views adapt to the window size, and an event feed
plus a worker/heavy/extract counter sit at the bottom. **Ctrl+C** stops all running tools.

**CPU monitoring.** The status line shows the CPU used by the agent and every tool it started (% of the machine
and cores in use, with a short history sparkline), the overall system CPU, and the agent's memory. A CPU column
shows each running tool's share. The final report gives average/peak CPU and peak memory, and every collection
gets `_logs/resource_usage.csv` (one sample per second). Tools run through Windows interop (SrumECmd, SumECmd)
run on the Windows side and are not counted.

## 3. Output layout (per collection)

```
<HOST>_<timestamp>/
  00_Case_Info/                 System_Info.txt/json, Artifact_Inventory.csv, Collection_Gaps.txt, Processing_Summary
  01_Evidence_of_Execution/     Prefetch, Amcache, ShimCache, SRUM/, BAM/UserAssist/RunMRU (Registry_Plugins/),
                                PowerShell event views + PSReadLine history, ProgramExecution_Timeline.csv
  02_File_and_Folder_Opening/   LNK, JumpLists, ShellBags/, Windows_Timeline/ (ActivitiesCache), RecentDocs/OpenSave MRU
  03_Deleted_Files/             RecycleBin ($I)
  04_File_System/               <V>_MFT.csv  (normal $MFT processing)
                                <V>_MFT.body + <V>_FileSystem_Timeline.csv  (mactime MACB timeline, UTC)
                                <V>_UsnJrnl.csv (full paths resolved with $MFT), <V>_LogFile.csv, <V>_SDS.csv, <V>_Boot.csv
  05_Event_Logs/                EventLogs_All.csv (EvtxECmd, every event) + log-cleared/power view
  06_Registry/                  RECmd Kroll batch (all hives), Plugins/, RegRipper/
  07_Browser_Activity/          SQLECmd Chromium/Firefox tables, TypedURLs, registry browser settings
  08_Account_Usage/             Logon/account event view, Hayabusa logon summary, SAM accounts
  09_Network_Activity/          SRUM network usage/connections, network/share events, NetworkList, Netstat
  10_External_Devices_USB/      USB registry, PnP/partition events, setupapi device installs + raw logs
  11_Persistence/               Services/Tasks/WMI events, Scheduled tasks (parsed XML, "Suspicious" flag), Autoruns
  12_Remote_Access/             RDP/WinRM events, RDP bitmap cache tiles + collage (RDP_Bitmap_Cache/),
                                reconstructed screen fragments (RDP_Reconstructed/, open <HOST>_RDP_Reconstruction.html),
                                TeamViewer/AnyDesk/AMMYY/... logs
  13_Live_Response/             Velociraptor Pslist / Netstat / Services / Autoruns results as CSV
  14_Threat_Hunting/            Hayabusa timeline + HTML summary, Chainsaw Sigma hunts, Defender events/logs, (THOR)
  15_Application_Artifacts/     Installed software, cloud storage, Windows Search index, other SQLite databases
  _logs/                        processing.log + one log per tool (full command line + tool output)
```
**RDP bitmap cache reconstruction.** bmc-tools extracts the 64x64 cache tiles. The `rdp_reconstruct` step then
rebuilds screen fragments from them, the way a jigsaw solver does. It compares every tile border with every
other one, keeps only mutual best matches that clearly beat the runner-up, and assembles them on a grid without
overlaps, strongest matches first. Holes that are surrounded on at least three sides are then filled with the
best-fitting tile. Flat, single-colour borders are never used as evidence for a match. Each cache file gets PNG
fragments (largest first) and a `*_fragments.csv` that maps every grid cell to its source tile file and says
whether the tile was matched or filled. All fragments are shown in `<HOST>_RDP_Reconstruction.html`. You can tune
the step in `config.yaml` (`modules.rdp_reconstruct`: `max_mse`, `ratio`, `min_tiles`). Results are leads, not
proof: check important fragments against the original tiles. RdpCacheStitcher (BSI) is useful for manual
follow-up, but it is not installed automatically because its releases publish no checksum.

The extracted collection (decoded file names, original timestamps, `extraction_manifest.csv` with a SHA-256
per file) is kept in `~/dta-work/<HOST>_<timestamp>/`. From Windows it is at
`\\wsl.localhost\Ubuntu-22.04\home\<user>\dta-work`.

## 3a. Linux / Unix collections (UAC)

**Accepted inputs** (found by content, also inside a folder of collections; mix freely with Windows ones):

| Input | Notes |
|---|---|
| `uac-<host>-<os>-<YYYYMMDDHHMMSS>.tar.gz` / `.tar` | UAC default output. Host, OS and collection time come from the name. |
| `uac-...zip` (optionally `-P` password) | Passwords are tried like Velociraptor ones (`-p`, `--password-file`, config, prompt). |
| Unpacked UAC folder (`[root]/`, `live_response/`, `uac.log`) | Processed in place, never copied or deleted. |
| Velociraptor collection of a Linux host | Detected by `etc/` in the uploads; gets the same Linux modules. |

**Extraction is defensive:** only regular files and folders are written. Symlinks are *recorded*, not created
(`links_manifest.csv` in the work folder), because their targets are absolute paths that would otherwise point
into the analysis machine. Hard links become copies, `..`/absolute entry names cannot leave the work folder,
and huge sparse files (e.g. `lastlog` on hosts with high UIDs) are not expanded beyond `max_sparse_expand_gb`.
.NET and the EZ tools are **not** required for UAC-only runs.

**Time zones.** Binary records (wtmp/btmp/lastlog, journal, auditd, bodyfile) are UTC. Classic syslog lines
have no year and no zone: the year is inferred from the log file's modification time (rotated files spanning
New Year are handled), and times are converted to UTC with the host zone from `/etc/timezone`, the
`/etc/localtime` link or `timedatectl` output. If the zone is unknown, times stay host-local. Every CSV has a
`TimeZone` column that says which applies.

| Folder | Linux output |
|---|---|
| `00_Case_Info/` | System_Info (OS, kernel, zone, IPs, UAC version), Artifact_Inventory, Collection_Gaps (+ uac.log errors), **Activity_Timeline.csv** (all sources merged, sorted) |
| `01_Evidence_of_Execution/` | Shell_History.csv (bash/zsh/fish/... with timestamps when recorded, "Suspicious" flag) + raw copies, Audit_Execve.csv (auditd command lines, hex args decoded) |
| `04_File_System/` | FileSystem_Timeline.csv from the UAC bodyfile (mactime, UTC) |
| `05_Event_Logs/` | Syslog_Timeline.csv (syslog/messages/auth/secure/kern/cron, rotated + .gz), Journal.csv (needs `journalctl`), Audit_Events.csv |
| `08_Account_Usage/` | Users.csv (UID 0 duplicates, empty/weak hashes - type only, never the hash, sudo/docker/lxd groups), Logins.csv (wtmp/btmp/utmp), LastLog.csv, Auth_Events*.csv (SSH, sudo, su, useradd/usermod, passwd) |
| `09_Network_Activity/` | Network_Config/ copies (hosts, resolv, interfaces, netplan, sshd_config, firewall rules), live_response network output |
| `11_Persistence/` | Persistence.csv: cron/anacron/at, systemd units+timers (vendor vs. /etc), rc.local/init.d, shell rc files, ld.so.preload, authorized_keys, sudoers, udev RUN+=, XDG autostart, motd, modules-load, PAM pam_exec |
| `12_Remote_Access/` | SSH_Summary_by_IP.csv (brute force, *success after brute force*, spraying), SSH_Authorized_Keys.csv, SSH_Known_Hosts.csv |
| `13_Live_Response/` | UAC live_response/, hash_executables/, uac.log |
| `14_Threat_Hunting/` | **Sigma_ChopChopGo.csv** and **Sigma_Zircolite.csv** (see below), **Package_Integrity_Suspicious.csv** (rpm hosts: package binaries/libraries/scripts whose content differs from the package, that are missing, or whose mode changed *and* are SUID/SGID now per the bodyfile; config files and regenerated caches are ignored), Suspicious_Files.csv (bodyfile: executables in /tmp and /dev/shm, SUID outside system dirs or on GTFOBins, hidden/deceptive names, history linked to /dev/null, miner names), Persistence_Suspicious.csv, Web_Suspicious_Requests.csv + by IP |
| `15_Application_Artifacts/` | Installed_Packages.csv (dpkg, or rpm from UAC's `rpm -qa` with install times), Package_History.csv (dpkg.log, apt history, yum/dnf, rpm install times), RPM_Verify.csv (UAC `rpm -V -a`), Web_Access.csv (Apache/nginx) |

**Sigma hunting on Linux (the counterparts of Chainsaw and Hayabusa).**

| Tool | Runs on | Rules | Output |
|---|---|---|---|
| ChopChopGo | every syslog-format log (syslog, messages, auth.log, secure, kern, cron; rotated `.gz` decompressed first) **and** a text export of the collected systemd journal | its bundled Sigma "builtin" rules (sshd, syslog, cron, ld.so.preload, history clearing, reverse shells, ...) | `14_Threat_Hunting/<HOST>_Sigma_ChopChopGo.csv` |
| Zircolite | auditd logs (`/var/log/audit/audit.log*`) and, when found in syslog, Sysmon for Linux events | SigmaHQ `rules_linux.json` shipped with the release | `<HOST>_Sigma_Zircolite.csv` + raw JSON and timeline in `14_Threat_Hunting/Zircolite/` |

Both CSVs share one layout (`Timestamp, TimeZone, Level, RuleTitle, RuleID, Tags, Details, Engine, SourceLog`)
with UTC times, and every detection is also added to `Activity_Timeline.csv`. ChopChopGo cannot read journal
files from a collection (its journald mode uses the live systemd API), so the journal task writes a
syslog-format export (`journal_export/` in the work folder) that ChopChopGo scans instead; that needs
`journalctl` on the analysis machine.

ChopChopGo is single-threaded and slow on big inputs (about 0.1 MB/s on a 3.3-million-line journal), so the
agent first keeps only the lines that contain a literal string required by at least one rule (GNU `grep -F`,
seconds for GBs). Every bundled rule is a keyword rule, so this cannot change the result: a line without any
required literal cannot match. On a 3.3-million-line journal, 291 lines remained and the hunt took 5 s instead of
more than 20 minutes. If a rule update ever brings field-based rules, the pre-filter switches itself
off and the logs are scanned in parallel 64 MB pieces instead (`modules.chopchopgo.chunk_mb` / `parallel`).

Most SigmaHQ Linux rules need **auditd** data: on hosts without auditd,
Zircolite is skipped and Sigma coverage is limited to ChopChopGo's syslog rules.

The "Suspicious" columns are leads for triage, not verdicts. The rules are in `dfir_agent/linux.py`
(`CMD_RULES`, `WEB_RULES`, `file_findings`). Each Linux module can be switched off in `config.yaml` (`linux_*`,
`chopchopgo`, `zircolite`, or `--skip chopchopgo,zircolite`).
Distributions: Debian/Ubuntu, RHEL family and SUSE, and VMware Photon OS (e.g. vCenter appliances) are recognised.
When `/etc/os-release` is a symlink whose target was not collected, `lsb-release` and the vendor release files are
used. Links recorded at extraction are followed *inside* the collection.
Not covered yet: reading the rpm database directly (the UAC `rpm` live-response outputs are used), macOS-specific
artifacts (unified logs, plists), container internals.

## 4. Design notes

* **Scope:** triage collections only. Disk-image mounting, memory analysis and antivirus scanning are out of scope;
  browser history comes from SQLECmd and event logs from EvtxECmd.
* **THOR:** the module is prepared but disabled. It runs only when `modules.thor.enabled: true`, a THOR binary is
  in `~/.dfir-triage-agent/tools/thor/`, and extended YARA rules are in `tools/thor/custom-signatures/yara/`.
  With built-in signatures only, it is skipped.
* **Windows processing:** concurrent multi-collection processing, per-artifact output, an `$MFT` bodyfile with a
  mactime file-system timeline, `$J` with full paths, `$LogFile`/`$SDS`/`$Boot` for every volume, Hayabusa and
  Chainsaw (Linux builds), event-log category views, scheduled-task XML parsing, setupapi USB parsing,
  Velociraptor live-response results, a collection gap report, and a program execution timeline that merges
  Amcache, ShimCache, Prefetch, UserAssist, BAM, RunMRU, RecentApps, SRUM and 4688/Sysmon-1 events.
* **Velociraptor specifics handled:** AES-encrypted `data.zip`, URL-encoded path names, NTFS stream names
  (`$UsnJrnl:$J` becomes `$UsnJrnl_$J`), and **sparse `.idx` sidecars**. Velociraptor stores hives, SRUDB.dat
  and WebCacheV01.dat compacted, so they are rebuilt to their original layout before parsing. `$J` is kept
  compacted because its original size is about 50 GB of zeros.
* **Collection gaps:** `Collection_Gaps.txt` compares what a collector should have uploaded with what it did, for
  example `Windows\appcompat\pca` (needs a wildcard target in `_SANS_Triage`), missing Volume Shadow Copies, a
  missing `$J`, or `$Recycle.Bin\$R*` content files.

## 5. Configuration

`config.yaml` holds worker limits, the EZ folder, the RECmd batch file (default `Kroll_Batch.reb`), candidate
passwords, per-module enable switches and THOR settings. Pass `--config my.yaml` to override only selected keys.

> Keep `work_dir` on the WSL disk (the default). Extracting under `/mnt/d/...` is 6-10x slower. Deep evidence
> paths can also exceed the Windows 260-character MAX_PATH, which breaks Explorer and Windows PowerShell 5.1.
> Delete such folders from WSL (`rm -rf`).
Event-log category views (channel and event ID lists) are in `dfir_agent/postproc.py` (`EVENT_VIEWS`), and
registry routing is in `RECMD_ROUTES` and `PLUGIN_ROUTES`.

## 6. Code map

| File | Role |
|---|---|
| `setup.sh` / `installer.py` | machine check, Python environment, verified tool installation/update |
| `dfir_agent/cli.py` | arguments, discovery, password handling, dashboard loop |
| `dfir_agent/collection.py` | discovery, decrypt/extract (Velociraptor zip, UAC tar/zip), path decoding, sparse-file rebuild, manifests |
| `dfir_agent/engine.py` | Task/Job model, subprocess streaming with live progress, concurrent scheduler |
| `dfir_agent/modules.py` | every Windows processing task (one function per artifact/tool) and the task graph |
| `dfir_agent/linux.py` | Linux/Unix (UAC) processing tasks, parsers, detection rules and the Linux task graph |
| `dfir_agent/postproc.py` | category routing, event views, timelines, inventory/gap report |
| `dfir_agent/ui.py` | logo, single/multi-collection dashboards, final report |
| `dfir_agent/tools.py` | tool discovery (dotnet vs. Windows interop), versions |

Adding a module means writing a `task_x(job, task)` function in `modules.py` and registering it with `T(...)`
in `build_processing`. Raising `SkipTask` or `TaskWarning` sets the task's status.

## 7. Roadmap (ideas for the next iteration)

WebCacheV01/ESE parsing on Linux (libesedb), AnyDesk/TeamViewer connection-log parsers, WMI persistence
(OBJECTS.DATA), a super-timeline (Plaso or a merged CSV), an HTML case report, a memory module (Volatility 3),
and Timesketch/Elastic export.

## 8. License and third-party tools

DFIR Triage Agent is released under the [MIT License](LICENSE).

It does not include any third-party tool. `setup.sh` downloads them from their official sources at install time
(checksum or signature verified, see section 1), and each one keeps its own license, which you accept by
installing it: Eric Zimmerman's tools, Hayabusa (AGPL-3.0), Chainsaw (GPL-3.0), SigmaHQ rules (Detection Rule
License), ChopChopGo, Zircolite, bmc-tools, RegRipper, sleuthkit, .NET, and THOR (Nextron, optional, installed
by you). Check the license of each tool before using it in your organisation.
