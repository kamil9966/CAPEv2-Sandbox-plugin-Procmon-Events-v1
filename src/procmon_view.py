from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from contextlib import suppress

from lib.cuckoo.common.constants import CUCKOO_ROOT

SCHEMA_VERSION = "2"
DEFAULT_PAGE_SIZE = 100
ALLOWED_PAGE_SIZES = (25, 50, 100, 200)
MAX_QUERY_LENGTH = 512
MAX_RAW_VALUE_LENGTH = 65536
CACHE_DIR = os.path.join(tempfile.gettempdir(), "cape-procmon-ui")

FIELD_ALIASES = {
    "time": (
        "Time_of_Day",
        "Date___Time",
        "Date_Time",
        "Date_And_Time",
        "Date_and_Time",
        "Timestamp",
        "Time",
    ),
    "process_index": ("ProcessIndex", "Process_Index"),
    "process_name": ("Process_Name", "ProcessName"),
    "pid": ("PID", "Pid", "ProcessId"),
    "operation": ("Operation",),
    "path": ("Path",),
    "result": ("Result",),
    "detail": ("Detail",),
    "tid": ("TID", "Tid"),
    "duration": ("Duration",),
    "user": ("User", "Owner"),
    "command_line": ("Command_Line", "CommandLine"),
    "parent_pid": ("Parent_PID", "ParentPid", "ParentProcessId"),
    "image_path": ("Image_Path", "ImagePath"),
    "event_class": ("Event_Class", "EventClass"),
    "category": ("Category",),
    "integrity": ("Integrity",),
    "is_64bit": ("Is64bit", "Is64Bit"),
    "sequence": ("Sequence",),
}

PROCESS_ALIASES = {
    "process_index": ("ProcessIndex", "Process_Index"),
    "pid": ("ProcessId", "PID", "Pid"),
    "parent_pid": ("ParentProcessId", "Parent_PID", "ParentPid"),
    "parent_process_index": ("ParentProcessIndex",),
    "process_name": ("ProcessName", "Process_Name"),
    "image_path": ("ImagePath", "Image_Path"),
    "command_line": ("CommandLine", "Command_Line"),
    "user": ("Owner", "User"),
    "integrity": ("Integrity",),
    "is_64bit": ("Is64bit", "Is64Bit"),
    "session_id": ("SessionId", "Session_ID"),
    "create_time": ("CreateTime",),
    "finish_time": ("FinishTime",),
}

DB_COLUMNS = (
    "seq",
    "time",
    "process_index",
    "process_name",
    "pid",
    "operation",
    "path",
    "result",
    "detail",
    "tid",
    "duration",
    "user",
    "command_line",
    "parent_pid",
    "parent_process_name",
    "image_path",
    "event_class",
    "category",
    "integrity",
    "is_64bit",
    "raw_json",
    "search_text",
)

SEARCH_FIELD_MAP = {
    "process": "process_name",
    "proc": "process_name",
    "process_name": "process_name",
    "pid": "pid",
    "operation": "operation",
    "op": "operation",
    "path": "path",
    "result": "result",
    "detail": "detail",
    "cmd": "command_line",
    "command": "command_line",
    "commandline": "command_line",
    "command_line": "command_line",
    "parent": "parent_process_name",
    "parent_process": "parent_process_name",
    "parent_pid": "parent_pid",
    "ppid": "parent_pid",
    "user": "user",
    "owner": "user",
    "integrity": "integrity",
    "tid": "tid",
    "duration": "duration",
    "image": "image_path",
    "image_path": "image_path",
    "class": "event_class",
    "event_class": "event_class",
    "category": "category",
    "process_index": "process_index",
    "any": "search_text",
    "all": "search_text",
    "raw": "search_text",
}

TOKEN_RE = re.compile(
    r'''(?P<field>[A-Za-z_][A-Za-z0-9_.-]*):(?:"(?P<fdq>[^"]*)"|'(?P<fsq>[^']*)'|(?P<fbare>\S+))'''
    r'''|"(?P<dq>[^"]+)"|'(?P<sq>[^']+)'|(?P<bare>\S+)'''
)


def procmon_xml_path(task_id):
    return os.path.join(
        CUCKOO_ROOT,
        "storage",
        "analyses",
        str(int(task_id)),
        "aux",
        "procmon.xml",
    )


def _local_name(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _clean_text(value):
    value = str(value or "")
    if len(value) > MAX_RAW_VALUE_LENGTH:
        return value[:MAX_RAW_VALUE_LENGTH] + "…"
    return value


def _direct_fields(element):
    raw = {}
    for child in list(element):
        if list(child):
            continue
        raw[_local_name(child.tag)] = _clean_text(child.text or "")
    return raw


def _flatten_fields(element):
    """Flatten all scalar descendants into dotted XML field paths.

    Repeated keys are joined instead of discarded. This allows the global
    search to cover nested Procmon XML data (for example optional stack frames)
    without loading the entire XML document into memory.
    """

    raw = {}

    def add(key, value):
        value = _clean_text(value)
        if not value:
            return
        if key in raw:
            if value not in raw[key].split("\n"):
                raw[key] = _clean_text(raw[key] + "\n" + value)
        else:
            raw[key] = value

    def walk(node, prefix=""):
        children = list(node)
        if not children:
            key = prefix or _local_name(node.tag)
            add(key, node.text or "")
            return

        for child in children:
            name = _local_name(child.tag)
            child_prefix = f"{prefix}.{name}" if prefix else name
            walk(child, child_prefix)

    for child in list(element):
        walk(child, _local_name(child.tag))

    return raw


def _pick(raw, aliases):
    for name in aliases:
        if name in raw and raw[name] is not None:
            return str(raw[name])
    return ""


def _process_meta(element):
    direct = _direct_fields(element)
    meta = {field: _pick(direct, aliases) for field, aliases in PROCESS_ALIASES.items()}
    return meta


def _normalise_event(element, fallback_seq, processes):
    direct = _direct_fields(element)
    raw = _flatten_fields(element)

    row = {field: _pick(direct, aliases) for field, aliases in FIELD_ALIASES.items()}

    process_index = row.get("process_index", "")
    proc = processes.get(process_index, {}) if process_index else {}

    # Procmon keeps rich process properties in <processlist>, not necessarily
    # on every <event>. Enrich events by unique ProcessIndex so command line,
    # parent and integrity data are available in the UI and recursive search.
    for field in ("process_name", "pid", "user", "command_line", "parent_pid", "image_path", "integrity", "is_64bit"):
        if not row.get(field) and proc.get(field):
            row[field] = proc[field]

    parent_name = ""
    parent_index = proc.get("parent_process_index", "") if proc else ""
    if parent_index and parent_index in processes:
        parent_name = processes[parent_index].get("process_name", "")
    row["parent_process_name"] = parent_name

    try:
        seq = int(row.get("sequence") or fallback_seq)
    except (TypeError, ValueError):
        seq = fallback_seq
    row["seq"] = seq
    row.pop("sequence", None)

    # Add processlist context to the raw field card/search corpus.
    process_raw_names = {
        "process_index": "Process.ProcessIndex",
        "pid": "Process.ProcessId",
        "parent_pid": "Process.ParentProcessId",
        "parent_process_index": "Process.ParentProcessIndex",
        "process_name": "Process.ProcessName",
        "image_path": "Process.ImagePath",
        "command_line": "Process.CommandLine",
        "user": "Process.Owner",
        "integrity": "Process.Integrity",
        "is_64bit": "Process.Is64bit",
        "session_id": "Process.SessionId",
        "create_time": "Process.CreateTime",
        "finish_time": "Process.FinishTime",
    }
    for field, raw_name in process_raw_names.items():
        value = proc.get(field, "") if proc else ""
        if value:
            raw.setdefault(raw_name, _clean_text(value))
    if parent_name:
        raw.setdefault("Process.ParentProcessName", _clean_text(parent_name))

    # Store both XML parameter names and values. This makes queries like
    # ProcessIndex:105 or Integrity:High searchable even when the parameter is
    # not represented as a visible table column.
    search_parts = []
    for key, value in raw.items():
        if value:
            search_parts.append(f"{key}:{value}")
            search_parts.append(value)
    for field in (
        "time",
        "process_index",
        "process_name",
        "pid",
        "operation",
        "path",
        "result",
        "detail",
        "tid",
        "duration",
        "user",
        "command_line",
        "parent_pid",
        "parent_process_name",
        "image_path",
        "event_class",
        "category",
        "integrity",
        "is_64bit",
    ):
        value = row.get(field, "")
        if value:
            search_parts.append(str(value))

    row["raw_json"] = json.dumps(raw, ensure_ascii=False, separators=(",", ":"))
    row["search_text"] = "\n".join(search_parts).casefold()
    return row


def _iter_events(xml_path):
    seq = 0
    processes = {}

    # Procmon XML is processlist followed by eventlist. Streaming iterparse
    # keeps memory bounded even for hundreds of MB. We retain only compact
    # process metadata keyed by unique ProcessIndex.
    for _event, element in ET.iterparse(xml_path, events=("end",)):
        name = _local_name(element.tag).lower()

        if name == "process":
            meta = _process_meta(element)
            if meta.get("process_index"):
                processes[meta["process_index"]] = meta
            element.clear()
            continue

        # Module metadata is not needed for event correlation and can be large.
        if name == "module":
            element.clear()
            continue

        if name != "event":
            continue

        seq += 1
        yield _normalise_event(element, seq, processes)
        element.clear()


def _source_signature(xml_path):
    st = os.stat(xml_path)
    return str(st.st_mtime_ns), str(st.st_size)


def _cache_paths(xml_path):
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    digest = hashlib.sha256(
        os.path.realpath(xml_path).encode("utf-8", errors="surrogateescape")
    ).hexdigest()[:24]
    db_path = os.path.join(CACHE_DIR, f"{digest}.sqlite3")
    return db_path, db_path + ".lock"


def _meta(conn):
    try:
        return dict(conn.execute("SELECT key, value FROM meta"))
    except sqlite3.Error:
        return {}


def _index_is_fresh(db_path, xml_path):
    if not os.path.isfile(db_path):
        return False

    mtime_ns, size = _source_signature(xml_path)
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            meta = _meta(conn)
        return (
            meta.get("schema_version") == SCHEMA_VERSION
            and meta.get("source_mtime_ns") == mtime_ns
            and meta.get("source_size") == size
        )
    except sqlite3.Error:
        return False


def _build_index(xml_path, db_path):
    mtime_ns, source_size = _source_signature(xml_path)
    tmp_path = f"{db_path}.{os.getpid()}.tmp"
    with suppress(OSError):
        os.unlink(tmp_path)

    conn = sqlite3.connect(tmp_path)
    try:
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute(
            """
            CREATE TABLE events (
                seq INTEGER PRIMARY KEY,
                time TEXT,
                process_index TEXT,
                process_name TEXT,
                pid TEXT,
                operation TEXT,
                path TEXT,
                result TEXT,
                detail TEXT,
                tid TEXT,
                duration TEXT,
                user TEXT,
                command_line TEXT,
                parent_pid TEXT,
                parent_process_name TEXT,
                image_path TEXT,
                event_class TEXT,
                category TEXT,
                integrity TEXT,
                is_64bit TEXT,
                raw_json TEXT,
                search_text TEXT
            )
            """
        )
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        insert_sql = (
            "INSERT INTO events "
            "(seq,time,process_index,process_name,pid,operation,path,result,detail,tid,duration,"
            "user,command_line,parent_pid,parent_process_name,image_path,event_class,category,"
            "integrity,is_64bit,raw_json,search_text) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        )

        count = 0
        batch = []
        for row in _iter_events(xml_path):
            batch.append(tuple(row.get(col, "") for col in DB_COLUMNS))
            count += 1
            if len(batch) >= 2000:
                conn.executemany(insert_sql, batch)
                batch.clear()

        if batch:
            conn.executemany(insert_sql, batch)

        conn.execute("CREATE INDEX idx_procmon_pid ON events(pid)")
        conn.execute("CREATE INDEX idx_procmon_process ON events(process_name COLLATE NOCASE)")
        conn.execute("CREATE INDEX idx_procmon_operation ON events(operation COLLATE NOCASE)")
        conn.execute("CREATE INDEX idx_procmon_result ON events(result COLLATE NOCASE)")
        conn.execute("CREATE INDEX idx_procmon_process_index ON events(process_index)")
        conn.executemany(
            "INSERT INTO meta(key,value) VALUES (?,?)",
            (
                ("schema_version", SCHEMA_VERSION),
                ("source_mtime_ns", mtime_ns),
                ("source_size", source_size),
                ("event_count", str(count)),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, db_path)


def _ensure_index(xml_path):
    db_path, lock_path = _cache_paths(xml_path)
    if _index_is_fresh(db_path, xml_path):
        return db_path

    with open(lock_path, "a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            if not _index_is_fresh(db_path, xml_path):
                _build_index(xml_path, db_path)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    return db_path


def _clean_query(value):
    return str(value or "")[:MAX_QUERY_LENGTH].strip()


def _like_value(value, *, casefold=False):
    value = str(value or "")
    if casefold:
        value = value.casefold()
    value = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{value}%"


def _parse_search_expression(query):
    """Parse recursive search expression into AND-combined terms.

    Examples:
      powershell WriteFile
      "ExecutionPolicy Bypass"
      cmd:"-ExecutionPolicy Bypass"
      operation:RegSetValue path:\\Run
      Integrity:High        (unknown XML parameter -> raw recursive search)
    """

    query = _clean_query(query)
    if not query:
        return []

    terms = []
    for match in TOKEN_RE.finditer(query):
        field = match.group("field")
        if field:
            value = match.group("fdq")
            if value is None:
                value = match.group("fsq")
            if value is None:
                value = match.group("fbare") or ""
            value = _clean_query(value)
            if not value:
                continue

            mapped = SEARCH_FIELD_MAP.get(field.casefold())
            if mapped:
                terms.append((mapped, value))
            else:
                # Unknown field names are still useful: search the complete
                # flattened XML corpus for the canonical Field:Value pair.
                terms.append(("search_text", f"{field}:{value}"))
            continue

        value = match.group("dq") or match.group("sq") or match.group("bare") or ""
        value = _clean_query(value)
        if value:
            terms.append(("search_text", value))

    # If the expression did not tokenize (rare malformed quotes), preserve the
    # old literal-substring behavior instead of returning no matches.
    if not terms and query:
        terms.append(("search_text", query))
    return terms


def _build_where(filters):
    clauses = []
    params = []

    def contains(column, value):
        if value:
            clauses.append(f"{column} LIKE ? ESCAPE '\\' COLLATE NOCASE")
            params.append(_like_value(value))

    contains("process_name", filters["process"])
    contains("operation", filters["operation"])
    contains("result", filters["result"])
    contains("path", filters["path"])

    if filters["pid"]:
        clauses.append("pid = ?")
        params.append(filters["pid"])

    for column, value in _parse_search_expression(filters["q"]):
        if column == "search_text":
            clauses.append("search_text LIKE ? ESCAPE '\\'")
            params.append(_like_value(value, casefold=True))
        else:
            clauses.append(f"{column} LIKE ? ESCAPE '\\' COLLATE NOCASE")
            params.append(_like_value(value))

    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def _facets(conn):
    def top(column, limit):
        rows = conn.execute(
            f"SELECT {column}, COUNT(*) AS n FROM events "
            f"WHERE {column} IS NOT NULL AND {column} != '' "
            f"GROUP BY {column} ORDER BY n DESC, {column} COLLATE NOCASE LIMIT ?",
            (limit,),
        ).fetchall()
        return [{"value": row[0], "count": row[1]} for row in rows]

    return {
        "processes": top("process_name", 80),
        "operations": top("operation", 120),
        "results": top("result", 40),
    }


def _load_from_index(xml_path, page, page_size, filters, order):
    db_path = _ensure_index(xml_path)
    where, params = _build_where(filters)
    order_sql = "DESC" if order == "desc" else "ASC"

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        meta = _meta(conn)
        source_total = int(meta.get("event_count", "0") or 0)
        total = conn.execute("SELECT COUNT(*) FROM events" + where, params).fetchone()[0]

        total_pages = math.ceil(total / page_size) if total else 0
        page = min(max(page, 1), total_pages) if total_pages else 1
        offset = (page - 1) * page_size

        sql = (
            "SELECT seq,time,process_index,process_name,pid,operation,path,result,detail,tid,"
            "duration,user,command_line,parent_pid,parent_process_name,image_path,event_class,"
            "category,integrity,is_64bit FROM events"
            + where
            + f" ORDER BY seq {order_sql} LIMIT ? OFFSET ?"
        )
        events = [dict(row) for row in conn.execute(sql, (*params, page_size, offset))]
        facets = _facets(conn)

    return {
        "events": events,
        "page": page,
        "page_size": page_size,
        "total_events": total,
        "total_pages": total_pages,
        "source_total": source_total,
        "facets": facets,
        "cache": "sqlite",
    }


def _row_matches(row, filters):
    def contains(field, needle):
        return needle.casefold() in str(row.get(field, "")).casefold()

    if filters["process"] and not contains("process_name", filters["process"]):
        return False
    if filters["pid"] and str(row.get("pid", "")) != filters["pid"]:
        return False
    if filters["operation"] and not contains("operation", filters["operation"]):
        return False
    if filters["result"] and not contains("result", filters["result"]):
        return False
    if filters["path"] and not contains("path", filters["path"]):
        return False

    for column, value in _parse_search_expression(filters["q"]):
        if value.casefold() not in str(row.get(column, "")).casefold():
            return False

    return True


def _load_streaming(xml_path, page, page_size, filters, order):
    matched = []
    total = 0
    source_total = 0
    start = (page - 1) * page_size
    end = start + page_size

    if order == "desc":
        keep = max(page * page_size, page_size)
        ring = []
        for row in _iter_events(xml_path):
            source_total += 1
            if not _row_matches(row, filters):
                continue
            total += 1
            ring.append(row)
            if len(ring) > keep:
                del ring[: len(ring) - keep]
        ring.reverse()
        matched = ring[start:end]
    else:
        for row in _iter_events(xml_path):
            source_total += 1
            if not _row_matches(row, filters):
                continue
            if start <= total < end:
                matched.append(row)
            total += 1

    total_pages = math.ceil(total / page_size) if total else 0
    page = min(max(page, 1), total_pages) if total_pages else 1

    # The streaming path should not push large raw/search fields to the table.
    for row in matched:
        row.pop("raw_json", None)
        row.pop("search_text", None)

    return {
        "events": matched,
        "page": page,
        "page_size": page_size,
        "total_events": total,
        "total_pages": total_pages,
        "source_total": source_total,
        "facets": {"processes": [], "operations": [], "results": []},
        "cache": "stream",
        "warning": "Procmon cache could not be created; using the slower streaming XML fallback.",
    }


def load_procmon_event(xml_path, seq):
    if not os.path.isfile(xml_path) or os.path.getsize(xml_path) <= 0:
        return None

    try:
        seq = int(seq)
    except (TypeError, ValueError):
        return None
    if seq <= 0:
        return None

    try:
        db_path = _ensure_index(xml_path)
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM events WHERE seq = ?", (seq,)).fetchone()
        if row is None:
            return None
        event = dict(row)
    except (OSError, sqlite3.Error, ET.ParseError):
        event = None
        for row in _iter_events(xml_path):
            if int(row.get("seq", 0)) == seq:
                event = row
                break
        if event is None:
            return None

    try:
        raw = json.loads(event.get("raw_json") or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        raw = {}

    event["raw_fields"] = [
        {"name": key, "value": value}
        for key, value in raw.items()
        if value not in (None, "")
    ]

    # Compact JSON suitable for Copy Event. search_text is deliberately omitted.
    copy_event = {
        key: value
        for key, value in event.items()
        if key not in {"search_text", "raw_json", "raw_fields"} and value not in (None, "")
    }
    copy_event["raw_fields"] = raw
    event["json_text"] = json.dumps(copy_event, ensure_ascii=False, indent=2)
    return event


def load_procmon_page(xml_path, params):
    if not os.path.isfile(xml_path) or os.path.getsize(xml_path) <= 0:
        return {"error": "Procmon XML is missing or empty.", "events": []}

    try:
        page = max(int(params.get("page", 1)), 1)
    except (TypeError, ValueError):
        page = 1

    try:
        page_size = int(params.get("page_size", DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE

    if page_size not in ALLOWED_PAGE_SIZES:
        page_size = DEFAULT_PAGE_SIZE

    order = "desc" if str(params.get("order", "asc")).lower() == "desc" else "asc"

    filters = {
        "q": _clean_query(params.get("q", "")),
        "process": _clean_query(params.get("process", "")),
        "pid": _clean_query(params.get("pid", "")),
        "operation": _clean_query(params.get("operation", "")),
        "result": _clean_query(params.get("result", "")),
        "path": _clean_query(params.get("path", "")),
    }

    try:
        data = _load_from_index(xml_path, page, page_size, filters, order)
    except (OSError, sqlite3.Error, ET.ParseError):
        data = _load_streaming(xml_path, page, page_size, filters, order)

    data.update(filters)
    data["order"] = order
    data["allowed_page_sizes"] = ALLOWED_PAGE_SIZES
    data["file_size"] = os.path.getsize(xml_path)

    total_pages = data.get("total_pages", 0)
    current = data.get("page", 1)
    if total_pages:
        start = max(1, current - 2)
        stop = min(total_pages, current + 2)
        data["page_numbers"] = list(range(start, stop + 1))
        data["prev_page"] = max(1, current - 1)
        data["next_page"] = min(total_pages, current + 1)
        data["show_first"] = start > 1
        data["show_first_ellipsis"] = start > 2
        data["show_last"] = stop < total_pages
        data["show_last_ellipsis"] = stop < total_pages - 1
    else:
        data["page_numbers"] = []
        data["prev_page"] = 1
        data["next_page"] = 1
        data["show_first"] = False
        data["show_first_ellipsis"] = False
        data["show_last"] = False
        data["show_last_ellipsis"] = False

    return data
