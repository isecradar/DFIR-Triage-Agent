#!/usr/bin/env python3
"""DFIR Triage Agent launcher.

setup.sh records the interpreter to use in ~/.dfir-triage-agent/env.json (the current Python when it already
had every library, otherwise an isolated venv). Started with any other interpreter, this script re-launches
itself with the recorded one, so `python3 dfir-triage.py` and `./dfir-triage` behave the same.
"""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = Path(os.environ.get("DTA_HOME", "~/.dfir-triage-agent")).expanduser()


def _target_python():
    try:
        return json.loads((HOME / "env.json").read_text()).get("python")
    except (OSError, ValueError):
        venv = HOME / "venv" / "bin" / "python"  # installations made before env.json existed
        return str(venv) if venv.exists() else None


target = _target_python()
if not target or not Path(target).exists():
    sys.exit(f"DFIR Triage Agent is not set up for this user - run: {HERE / 'setup.sh'}")
if Path(sys.executable).absolute() != Path(target).absolute() and not os.environ.get("DTA_NO_REEXEC"):
    os.environ["DTA_NO_REEXEC"] = "1"  # guard against loops
    os.execv(target, [target, str(Path(__file__).resolve()), *sys.argv[1:]])

sys.path.insert(0, str(HERE))
try:
    from dfir_agent.cli import main  # noqa: E402
except ModuleNotFoundError as e:
    sys.exit(f"Missing Python library ({e.name}) for {sys.executable} - re-run: {HERE / 'setup.sh'}")

if __name__ == "__main__":
    sys.exit(main())
