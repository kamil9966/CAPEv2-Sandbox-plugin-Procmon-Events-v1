#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess

STATE_NAME = ".procmon-stability-current.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Remove optional Procmon capture stability fix")
    parser.add_argument("--root", default="/opt/CAPEv2")
    parser.add_argument("--restart", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    state = root / STATE_NAME
    if not state.is_file():
        raise SystemExit(f"No {STATE_NAME} manifest found")
    manifest = json.loads(state.read_text(encoding="utf-8"))
    backup = Path(manifest["backup"])
    target = root / manifest["target"]
    if not backup.is_file():
        raise SystemExit(f"Backup is missing: {backup}")
    shutil.copy2(backup, target)
    state.unlink()
    print("Restored:", target)
    if args.restart:
        subprocess.run(["sudo", "systemctl", "restart", "cape", "cape-processor", "cape-web"], cwd=root, check=True)
    else:
        print("Restart when ready: sudo systemctl restart cape cape-processor cape-web")


if __name__ == "__main__":
    main()
