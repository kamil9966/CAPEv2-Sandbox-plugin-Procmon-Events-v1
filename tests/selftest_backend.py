#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description="Self-test the installed CAPE Procmon backend")
    parser.add_argument("--cape-root", default="/opt/CAPEv2")
    args = parser.parse_args()

    root = Path(args.cape_root).resolve()
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "web"))

    from analysis.procmon_view import load_procmon_event, load_procmon_page  # noqa: E402

    xml = r'''<?xml version="1.0" encoding="UTF-8"?>
<procmon>
  <processlist>
    <process>
      <ProcessIndex>105</ProcessIndex>
      <ProcessId>4408</ProcessId>
      <ParentProcessId>3124</ParentProcessId>
      <ParentProcessIndex>104</ParentProcessIndex>
      <Integrity>High</Integrity>
      <Owner>Ivan</Owner>
      <Is64bit>1</Is64bit>
      <ProcessName>powershell.exe</ProcessName>
      <ImagePath>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</ImagePath>
      <CommandLine>powershell.exe -ExecutionPolicy Bypass -File C:\Temp\a.ps1</CommandLine>
    </process>
    <process>
      <ProcessIndex>104</ProcessIndex>
      <ProcessId>3124</ProcessId>
      <ProcessName>EXCEL.EXE</ProcessName>
    </process>
  </processlist>
  <eventlist>
    <event>
      <ProcessIndex>105</ProcessIndex>
      <Time_of_Day>18:03:21.4</Time_of_Day>
      <Process_Name>powershell.exe</Process_Name>
      <PID>4408</PID>
      <Operation>WriteFile</Operation>
      <Path>C:\Temp\x.bin</Path>
      <Result>SUCCESS</Result>
      <Detail>Length: 123</Detail>
      <CustomParameter>SecretPhrase</CustomParameter>
    </event>
  </eventlist>
</procmon>'''

    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        Path(path).write_text(xml, encoding="utf-8")
        checks = [
            ("powershell WriteFile", 1),
            ('"ExecutionPolicy Bypass"', 1),
            ('cmd:"ExecutionPolicy Bypass"', 1),
            ("operation:WriteFile", 1),
            ("Integrity:High", 1),
            ("CustomParameter:SecretPhrase", 1),
            (r"C:\Temp\x.bin", 1),
            ("parent:EXCEL.EXE", 1),
        ]
        for query, expected in checks:
            data = load_procmon_page(path, {"q": query, "page_size": "25"})
            assert data["total_events"] == expected, (query, data["total_events"])

        event = load_procmon_event(path, 1)
        assert event and event["parent_process_name"] == "EXCEL.EXE"
        assert "ExecutionPolicy Bypass" in event["command_line"]
        assert any(item["name"] == "CustomParameter" for item in event["raw_fields"])
        print("Procmon investigation backend self-test: OK")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
