#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
from contextlib import suppress
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

PROJECT_VERSION = "1.0.0"
MARKER = "CAPE-PROCMON-UI"
STATE_NAME = ".cape-procmon-ui-current.json"

VIEW_BLOCK = r'''# CAPE-PROCMON-UI: view
@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@require_task_visibility
def procmon_events(request, task_id):
    # Paginated/searchable Procmon view backed by aux/procmon.xml.
    xml_path = procmon_xml_path(task_id)
    if not path_exists(xml_path):
        raise PermissionDenied

    event_seq = request.GET.get("event_seq")
    if event_seq:
        try:
            event = load_procmon_event(xml_path, event_seq)
        except Exception:
            log.exception("Failed to load Procmon event %s for task %s", event_seq, task_id)
            event = None
        return render(
            request,
            "analysis/procmon/event_card.html",
            {"event": event, "id": int(task_id)},
        )

    try:
        procmon_page = load_procmon_page(xml_path, request.GET)
    except Exception:
        log.exception("Failed to render Procmon Events for task %s", task_id)
        procmon_page = {
            "error": "Failed to parse Procmon XML. Check cape-web logs.",
            "events": [],
        }

    return render(
        request,
        "analysis/procmon/index.html",
        {"procmon_page": procmon_page, "id": int(task_id)},
    )
'''


def fail(message: str) -> None:
    raise RuntimeError(message)


def run(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(str(x) for x in cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def current_git_commit(root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return proc.stdout.strip()
    except Exception:
        return ""


def replace_or_add_procmon_import(text: str) -> str:
    marker = f"# {MARKER}: import"
    desired = (
        marker
        + "\nfrom analysis.procmon_view import (\n"
        + "    load_procmon_event,\n"
        + "    load_procmon_page,\n"
        + "    procmon_xml_path,\n"
        + ")\n"
    )

    if marker in text:
        lines = text.splitlines(keepends=True)
        marker_idx = next(i for i, line in enumerate(lines) if marker in line)
        start = marker_idx
        i = marker_idx + 1
        if i >= len(lines) or not lines[i].lstrip().startswith("from analysis.procmon_view import"):
            fail("views.py: Procmon import marker exists but import block is not recognized")

        if "(" in lines[i] and ")" not in lines[i]:
            i += 1
            while i < len(lines) and ")" not in lines[i]:
                i += 1
            if i >= len(lines):
                fail("views.py: unterminated Procmon import block")
        end = i + 1
        return "".join(lines[:start]) + desired + "".join(lines[end:])

    anchor = "from analysis.central_views import scoped_analysis_query as _scoped_analysis_query"
    if anchor not in text:
        fail("views.py: central_views import anchor not found; CAPE WebUI layout may have changed")
    return text.replace(anchor, anchor + "\n" + desired.rstrip("\n"), 1)


def add_has_procmon(text: str) -> str:
    marker = f"# {MARKER}: report-presence"
    if marker in text:
        return text

    candidates = [
        re.compile(
            r'(?P<indent>[ \t]*)evtx_path\s*=\s*os\.path\.join\('
            r'CUCKOO_ROOT,\s*"storage",\s*"analyses",\s*str\(task_id\),\s*"evtx",\s*"evtx\.zip"\)\s*\n'
            r'(?P=indent)if\s+path_exists\(evtx_path\):\s*\n'
            r'(?P=indent)[ \t]+report\["has_evtx"\]\s*=\s*True\s*\n'
        ),
        re.compile(
            r'(?P<indent>[ \t]*)if\s+path_exists\(evtx_path\):\s*\n'
            r'(?P=indent)[ \t]+report\["has_evtx"\]\s*=\s*True\s*\n'
        ),
    ]

    for pattern in candidates:
        match = pattern.search(text)
        if not match:
            continue
        indent = match.group("indent")
        addition = (
            match.group(0)
            + f"{indent}# {MARKER}: report-presence\n"
            + f"{indent}procmon_path = procmon_xml_path(task_id)\n"
            + f"{indent}if path_exists(procmon_path):\n"
            + f"{indent}    try:\n"
            + f'{indent}        report["has_procmon"] = os.path.getsize(procmon_path) > 0\n'
            + f"{indent}    except OSError:\n"
            + f'{indent}        report["has_procmon"] = False\n'
        )
        return text[: match.start()] + addition + text[match.end() :]

    fail("views.py: EVTX report-presence anchor not found; refusing to guess")


def replace_or_add_view(text: str) -> str:
    marker = f"# {MARKER}: view"
    if marker not in text:
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            fail(f"views.py is not valid Python before patching: {exc}")
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "procmon_events" for node in tree.body):
            fail("views.py already defines procmon_events without our marker; refusing to overwrite it")
        return text.rstrip() + "\n\n" + VIEW_BLOCK.rstrip() + "\n"

    lines = text.splitlines(keepends=True)
    marker_idx = next(i for i, line in enumerate(lines) if marker in line)
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        fail(f"views.py is not valid Python before view replacement: {exc}")

    node = next(
        (
            n
            for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "procmon_events"
        ),
        None,
    )
    if node is None or not getattr(node, "end_lineno", None):
        fail("views.py: Procmon view marker exists but procmon_events() was not found")

    # AST line numbers are 1-based and end_lineno is inclusive. Start at our
    # marker so decorators and the previous function implementation are replaced.
    end_index = node.end_lineno
    if marker_idx + 1 > node.lineno:
        fail("views.py: unexpected Procmon marker/function order")

    prefix = "".join(lines[:marker_idx]).rstrip() + "\n\n"
    suffix = "".join(lines[end_index:]).lstrip("\n")
    return prefix + VIEW_BLOCK.rstrip() + "\n\n" + suffix


def patch_views(text: str) -> str:
    text = replace_or_add_procmon_import(text)
    text = add_has_procmon(text)
    text = replace_or_add_view(text)
    return text


def patch_urls(text: str) -> str:
    marker = f"# {MARKER}: route"
    if marker in text:
        if "procmon_events" not in text:
            fail("urls.py: route marker exists but procmon_events route is missing")
        return text

    if "name=\"procmon_events\"" in text or "name='procmon_events'" in text:
        fail("urls.py already has a procmon_events route without our marker")

    patterns = [
        re.compile(
            r'(?P<line>^[ \t]*re_path\(r"\^load_evtx_channel/\(\?P<task_id>\\d\+\)/\$",\s*'
            r'views\.load_evtx_channel,\s*name="load_evtx_channel"\),\s*$)',
            re.MULTILINE,
        ),
        re.compile(
            r'(?P<line>^[ \t]*re_path\([^\n]*load_evtx_channel[^\n]*\),\s*$)',
            re.MULTILINE,
        ),
    ]

    for pattern in patterns:
        match = pattern.search(text)
        if match:
            line = match.group("line")
            indent = re.match(r"^[ \t]*", line).group(0)
            addition = (
                line
                + "\n"
                + indent
                + f"# {MARKER}: route\n"
                + indent
                + 're_path(r"^procmon_events/(?P<task_id>\\d+)/$", views.procmon_events, name="procmon_events"),'
            )
            return text[: match.start()] + addition + text[match.end() :]

    fail("urls.py: load_evtx_channel route anchor not found; refusing to guess")


def patch_report(text: str) -> str:
    nav_marker = f"{{# {MARKER}: nav #}}"
    pane_marker = f"{{# {MARKER}: pane #}}"
    etw_anchor = "{% if analysis.has_etw and config.display_etw %}"

    if nav_marker not in text:
        positions = [m.start() for m in re.finditer(re.escape(etw_anchor), text)]
        if len(positions) < 2:
            fail("report.html: expected two ETW anchors for nav and tab pane")
        nav = (
            f"{nav_marker}\n"
            "{% if analysis.has_procmon %}\n"
            '<li class="nav-item">\n'
            '<a class="nav-link" id="procmon-tab" href="#procmon"\n'
            '   data-bs-toggle="tabajax"\n'
            '   data-url="/analysis/procmon_events/{{analysis.info.id}}/"\n'
            '   role="tab" aria-controls="procmon" aria-selected="false">\n'
            '  <i class="fas fa-microscope me-2"></i>Procmon Events\n'
            "</a>\n"
            "</li>\n"
            "{% endif %}\n\n"
        )
        text = text[: positions[0]] + nav + text[positions[0] :]

    if pane_marker not in text:
        positions = [m.start() for m in re.finditer(re.escape(etw_anchor), text)]
        if len(positions) < 2:
            fail("report.html: ETW tab-pane anchor not found after nav patch")
        pane = (
            f"{pane_marker}\n"
            "{% if analysis.has_procmon %}\n"
            '<div class="tab-pane fade" id="procmon">\n'
            "</div>\n"
            "{% endif %}\n\n"
        )
        text = text[: positions[1]] + pane + text[positions[1] :]

    return text


def restore(root: Path, backup: Path, manifest: dict) -> None:
    for item in manifest["files"]:
        dst = root / item["path"]
        src = backup / item["path"]
        if item["existed"]:
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        elif dst.exists():
            dst.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description="Install CAPEv2 Procmon Investigation UI")
    parser.add_argument("--root", default="/opt/CAPEv2", help="CAPEv2 source root")
    parser.add_argument("--restart", action="store_true", help="Restart cape-web after successful install")
    parser.add_argument("--skip-checks", action="store_true", help="Skip CAPE/Django validation checks")
    args = parser.parse_args()

    project = Path(__file__).resolve().parent
    root = Path(args.root).resolve()
    state = root / STATE_NAME

    payload_view = project / "src/procmon_view.py"
    payload_index = project / "templates/index.html"
    payload_card = project / "templates/event_card.html"
    selftest = project / "tests/selftest_backend.py"
    for payload in (payload_view, payload_index, payload_card, selftest):
        if not payload.is_file():
            fail(f"Distribution is incomplete; missing: {payload}")

    if state.exists():
        raise SystemExit(
            f"{STATE_NAME} already exists. This extension appears installed. "
            "Uninstall it first if you need a clean reinstall."
        )

    existing_files = [
        root / "web/analysis/views.py",
        root / "web/analysis/urls.py",
        root / "web/templates/analysis/report.html",
    ]
    managed_files = [
        root / "web/analysis/procmon_view.py",
        root / "web/templates/analysis/procmon/index.html",
        root / "web/templates/analysis/procmon/event_card.html",
    ]
    targets = existing_files + managed_files

    for path in existing_files:
        if not path.is_file():
            fail(f"Required CAPE file not found: {path}")
        if not os.access(path, os.W_OK):
            fail(f"Not writable as current user: {path}. Run as the CAPE source-tree owner.")

    previous_state = state.read_bytes() if state.exists() else None
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = root / ".procmon-ui-backups" / f"{stamp}-github-v{PROJECT_VERSION}"
    backup.mkdir(parents=True, exist_ok=False)

    manifest = {
        "extension": "cape-procmon-investigation-ui",
        "version": PROJECT_VERSION,
        "installed_at": stamp,
        "root": str(root),
        "git_commit": current_git_commit(root),
        "backup_dir": str(backup),
        "files": [],
    }

    try:
        for path in targets:
            rel = path.relative_to(root)
            existed = path.exists()
            manifest["files"].append({"path": str(rel), "existed": existed})
            if existed:
                dst = backup / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dst)

        views, urls, report = existing_files
        views.write_text(patch_views(views.read_text(encoding="utf-8")), encoding="utf-8")
        urls.write_text(patch_urls(urls.read_text(encoding="utf-8")), encoding="utf-8")
        report.write_text(patch_report(report.read_text(encoding="utf-8")), encoding="utf-8")

        managed_files[0].write_bytes(payload_view.read_bytes())
        managed_files[1].parent.mkdir(parents=True, exist_ok=True)
        managed_files[1].write_bytes(payload_index.read_bytes())
        managed_files[2].write_bytes(payload_card.read_bytes())

        (backup / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        state.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        if not args.skip_checks:
            run(
                [
                    "poetry", "run", "python3", "-m", "py_compile",
                    "web/analysis/views.py", "web/analysis/urls.py", "web/analysis/procmon_view.py",
                ],
                root,
            )
            run(["poetry", "run", "python3", "web/manage.py", "check"], root)
            run(
                [
                    "poetry", "run", "python3", "web/manage.py", "shell", "-c",
                    "from django.template.loader import get_template; "
                    "get_template('analysis/procmon/index.html'); "
                    "get_template('analysis/procmon/event_card.html'); "
                    "print('Procmon templates: OK')",
                ],
                root,
            )
            run(["poetry", "run", "python3", str(selftest), "--cape-root", str(root)], root)

            if (root / ".git").exists():
                run(
                    [
                        "git", "diff", "--check", "--",
                        "web/analysis/views.py",
                        "web/analysis/urls.py",
                        "web/templates/analysis/report.html",
                        "web/analysis/procmon_view.py",
                        "web/templates/analysis/procmon/index.html",
                        "web/templates/analysis/procmon/event_card.html",
                    ],
                    root,
                )

        print()
        print(f"OK: CAPE Procmon Investigation UI v{PROJECT_VERSION} installed")
        print("Backup:", backup)
        print("No CAPE database migration is required.")
        if args.restart:
            run(["sudo", "systemctl", "restart", "cape-web"], root)
            run(["systemctl", "is-active", "cape-web"], root)
        else:
            print("Restart: sudo systemctl restart cape-web")

    except Exception:
        print("ERROR: installation failed; restoring previous CAPE files...", file=sys.stderr)
        restore(root, backup, manifest)
        with suppress(Exception):
            if previous_state is None:
                state.unlink()
            else:
                state.write_bytes(previous_state)
        print("Rollback complete. Backup preserved at", backup, file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
