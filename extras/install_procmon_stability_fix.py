#!/usr/bin/env python3
"""Optional legacy CAPE Procmon auxiliary stability patch.

This is intentionally separate from the WebUI extension. It patches the guest
analyzer's Procmon auxiliary only when the expected older CAPE source matches
exactly. Newer CAPE versions may already contain equivalent fixes; in that
case this installer will refuse to modify the file.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess
import sys

STATE_NAME = ".procmon-stability-current.json"

OLD_CLASS = '''class Procmon(Auxiliary, Thread):
    """Allow procmon to be run on the side."""
'''
NEW_CLASS = '''class Procmon(Auxiliary, Thread):
    """Allow procmon to be run on the side."""

    # Stop Procmon after lower-priority auxiliary collectors such as EVTX.
    # This limits the blast radius of a slow Procmon shutdown/export.
    stop_priority = -100
'''

OLD_RUN = '''        # Start process monitor in the background.
        subprocess.Popen(
            (
                self.procmon_exe,
                "/AcceptEula",
                "/Quiet",
                "/Minimized",
                "/BackingFile",
                self.procmon_pml,
            ),
            startupinfo=self.startupinfo,
            shell=True,
        )

        # Try to avoid race conditions by waiting until at least something
        # has been written to the log file.
        while not os.path.exists(self.procmon_pml) or not os.path.getsize(self.procmon_pml):
            time.sleep(0.1)

        return True
'''

NEW_RUN = '''        # Load CAPE's PMC at capture start. With "Drop Filtered Events"
        # enabled in the PMC this prevents a huge unfiltered backing file.
        subprocess.Popen(
            (
                self.procmon_exe,
                "/AcceptEula",
                "/Quiet",
                "/Minimized",
                "/LoadConfig",
                self.procmon_pmc,
                "/BackingFile",
                self.procmon_pml,
            ),
            startupinfo=self.startupinfo,
            shell=False,
        )

        deadline = time.time() + 20
        while not os.path.exists(self.procmon_pml) or not os.path.getsize(self.procmon_pml):
            if time.time() >= deadline:
                logging.error("Procmon failed to create a non-empty PML within 20 seconds")
                try:
                    subprocess.run(
                        (self.procmon_exe, "/Terminate", "/Quiet"),
                        startupinfo=self.startupinfo,
                        shell=False,
                        timeout=10,
                        check=False,
                    )
                except Exception:
                    pass
                return False
            time.sleep(0.2)

        logging.info("Procmon capture started: %s", self.procmon_pml)
        return True
'''

NEW_STOP = '''    def stop(self) -> bool:
        if not self.enabled:
            return False

        try:
            try:
                result = subprocess.run(
                    (self.procmon_exe, "/Terminate", "/Quiet"),
                    startupinfo=self.startupinfo,
                    shell=False,
                    timeout=12,
                    check=False,
                )
                if result.returncode:
                    logging.warning("Procmon /Terminate returned code %s", result.returncode)
            except subprocess.TimeoutExpired:
                logging.error("Procmon /Terminate timed out; forcing procmon.exe closed")
                subprocess.run(
                    ("taskkill.exe", "/F", "/IM", "procmon.exe"),
                    startupinfo=self.startupinfo,
                    shell=False,
                    timeout=8,
                    check=False,
                )

            time.sleep(1)
            if not os.path.exists(self.procmon_pml):
                logging.error("Procmon PML does not exist: %s", self.procmon_pml)
                return False
            pml_size = os.path.getsize(self.procmon_pml)
            if not pml_size:
                logging.error("Procmon PML is empty")
                return False
            logging.info("Procmon PML size before conversion: %d bytes", pml_size)

            if os.path.exists(self.procmon_xml):
                try:
                    os.unlink(self.procmon_xml)
                except OSError:
                    pass

            try:
                result = subprocess.run(
                    (
                        self.procmon_exe,
                        "/AcceptEula",
                        "/Quiet",
                        "/OpenLog",
                        self.procmon_pml,
                        "/LoadConfig",
                        self.procmon_pmc,
                        "/SaveAs",
                        self.procmon_xml,
                        "/SaveApplyFilter",
                    ),
                    startupinfo=self.startupinfo,
                    shell=False,
                    timeout=30,
                    check=False,
                )
                if result.returncode:
                    logging.warning("Procmon conversion returned code %s", result.returncode)
            except subprocess.TimeoutExpired:
                logging.error("Procmon PML->XML conversion exceeded 30 seconds; skipping Procmon result")
                try:
                    subprocess.run(
                        ("taskkill.exe", "/F", "/IM", "procmon.exe"),
                        startupinfo=self.startupinfo,
                        shell=False,
                        timeout=8,
                        check=False,
                    )
                except Exception:
                    pass
                return False

            if not os.path.exists(self.procmon_xml):
                logging.error("Procmon conversion produced no XML: %s", self.procmon_xml)
                return False
            xml_size = os.path.getsize(self.procmon_xml)
            if not xml_size:
                logging.error("Procmon XML is empty")
                return False

            logging.info("Procmon XML ready: %d bytes", xml_size)
            upload_to_host(self.procmon_xml, "aux/procmon.xml")
            logging.info("Procmon XML uploaded successfully")
            return True
        except Exception as e:
            logging.error(e, exc_info=True)
            return False
'''


def run(cmd: list[str], root: Path) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=root, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Install optional CAPE Procmon capture stability fix")
    parser.add_argument("--root", default="/opt/CAPEv2")
    parser.add_argument("--restart", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    target = root / "analyzer/windows/modules/auxiliary/procmon.py"
    state = root / STATE_NAME
    if state.exists():
        raise SystemExit(f"{STATE_NAME} already exists; optional stability fix appears installed")
    if not target.is_file():
        raise SystemExit(f"Not found: {target}")

    text = target.read_text(encoding="utf-8")
    if OLD_CLASS not in text or OLD_RUN not in text:
        raise SystemExit(
            "Refusing to patch: this CAPE Procmon auxiliary does not match the tested legacy source. "
            "Your CAPE version may already contain equivalent fixes."
        )
    stop_at = text.find("    def stop(self) -> bool:")
    if stop_at < 0:
        raise SystemExit("Refusing to patch: stop() not found")

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = root / ".procmon-stability-backups" / stamp
    backup_dir.mkdir(parents=True, exist_ok=False)
    backup = backup_dir / "procmon.py"
    shutil.copy2(target, backup)

    try:
        text = text.replace(OLD_CLASS, NEW_CLASS, 1)
        text = text.replace(OLD_RUN, NEW_RUN, 1)
        stop_at = text.find("    def stop(self) -> bool:")
        text = text[:stop_at] + NEW_STOP + "\n"
        target.write_text(text, encoding="utf-8")

        run(["poetry", "run", "python3", "-m", "py_compile", str(target.relative_to(root))], root)
        if (root / ".git").exists():
            run(["git", "diff", "--check", "--", str(target.relative_to(root))], root)

        manifest = {"backup": str(backup), "target": str(target.relative_to(root)), "installed_at": stamp}
        state.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print("OK: optional Procmon stability fix installed")
        print("Backup:", backup)
        if args.restart:
            run(["sudo", "systemctl", "restart", "cape", "cape-processor", "cape-web"], root)
        else:
            print("Restart when ready: sudo systemctl restart cape cape-processor cape-web")
    except Exception:
        shutil.copy2(backup, target)
        print("ERROR: validation failed; original procmon.py restored", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
