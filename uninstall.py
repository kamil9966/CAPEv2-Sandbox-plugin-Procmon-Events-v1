#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess

STATE_NAME = ".cape-procmon-ui-current.json"


def run(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Uninstall CAPE Procmon Investigation UI")
    parser.add_argument("--root", default="/opt/CAPEv2")
    parser.add_argument("--restart", action="store_true")
    parser.add_argument("--clear-cache", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    state = root / STATE_NAME
    if not state.is_file():
        raise SystemExit(f"No {STATE_NAME} manifest found.")

    manifest = json.loads(state.read_text(encoding="utf-8"))
    backup = Path(manifest["backup_dir"])
    if not backup.is_dir():
        raise SystemExit(f"Backup directory is missing: {backup}")

    for item in manifest["files"]:
        dst = root / item["path"]
        src = backup / item["path"]
        if item["existed"]:
            if not src.exists():
                raise SystemExit(f"Backup file is missing: {src}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        elif dst.exists():
            dst.unlink()

    state.unlink()

    if args.clear_cache:
        cache = Path("/tmp/cape-procmon-ui")
        if cache.is_dir():
            shutil.rmtree(cache)
            print("Removed cache:", cache)

    print("Restored CAPE WebUI from:", backup)
    if args.restart:
        run(["sudo", "systemctl", "restart", "cape-web"], root)
        run(["systemctl", "is-active", "cape-web"], root)
    else:
        print("Restart: sudo systemctl restart cape-web")


if __name__ == "__main__":
    main()
