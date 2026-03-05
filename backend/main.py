"""
╔══════════════════════════════════════════════════════════════════════════╗
║         FORENSIC CYBER TRIAGE TOOL (FCTT) — Python Backend              ║
║         Lead DFIR Architect · Production-Ready · SOC Grade               ║
╚══════════════════════════════════════════════════════════════════════════╝

Run:
    pip install -r requirements.txt
    python main.py
    # API Docs: http://127.0.0.1:8765/api/docs
"""

import asyncio
import hashlib
import json
import logging
import multiprocessing
import os
import struct
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ─── Optional heavy deps (graceful degradation) ───────────────────────────────
try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False
    logging.warning("pytsk3 not available — disk analysis will use fallback")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("yara-python not available — YARA matching disabled")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available — AI scoring disabled")

import sqlite3

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
log = logging.getLogger("fctt")

# ─── Constants ────────────────────────────────────────────────────────────────
CASES_DIR = Path("./cases")
CASES_DIR.mkdir(exist_ok=True)
SUPPORTED_EVIDENCE = {".dd", ".img", ".raw", ".vmem", ".pcap", ".log", ".evtx"}
MAX_CARVE_SIZE = 512 * 1024 * 1024
TOOL_VERSION = "1.0.0"

FILE_SIGNATURES = {
    b"\x4d\x5a":      ("PE_EXE",  100),
    b"\x7fELF":       ("ELF",     128),
    b"\xff\xd8\xff":  ("JPEG",     10),
    b"\x89PNG\r\n":   ("PNG",      50),
    b"%PDF":          ("PDF",     100),
    b"PK\x03\x04":    ("ZIP",      50),
    b"\x1f\x8b":      ("GZIP",     50),
}

# ─── Pydantic Models ──────────────────────────────────────────────────────────
class CaseCreate(BaseModel):
    case_number: str = Field(..., min_length=1, max_length=64)
    case_name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = ""
    investigators: List[str] = []
    acquisition_date: Optional[str] = None

class EvidenceItem(BaseModel):
    evidence_id: str
    filename: str
    file_size: int
    md5: str
    sha256: str
    acquisition_ts: str
    mount_mode: str = "READ_ONLY"
    evidence_type: str

class TriageRequest(BaseModel):
    case_id: str
    evidence_id: str
    plugins: List[str] = ["pslist", "netscan", "malfind", "dlllist"]
    enable_ai: bool = True
    enable_carving: bool = True

class TaskStatus(BaseModel):
    task_id: str
    status: str
    progress: float
    message: str
    result: Optional[Dict] = None

# ─── Database Schema ──────────────────────────────────────────────────────────
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id         TEXT PRIMARY KEY,
    case_number     TEXT NOT NULL,
    case_name       TEXT NOT NULL,
    description     TEXT,
    created_at      TEXT NOT NULL,
    status          TEXT DEFAULT 'Active'
);

CREATE TABLE IF NOT EXISTS investigators (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT NOT NULL REFERENCES cases(case_id),
    name            TEXT NOT NULL,
    added_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_id     TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(case_id),
    filename        TEXT NOT NULL,
    filepath        TEXT NOT NULL,
    file_size       INTEGER,
    md5             TEXT,
    sha256          TEXT,
    acquisition_ts  TEXT,
    mount_mode      TEXT DEFAULT 'READ_ONLY',
    evidence_type   TEXT,
    added_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS extracted_files (
    file_id         TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    evidence_id     TEXT,
    name            TEXT,
    full_path       TEXT,
    size            INTEGER,
    md5             TEXT,
    sha256          TEXT,
    inode           INTEGER,
    parent_inode    INTEGER,
    created_ts      TEXT,
    modified_ts     TEXT,
    accessed_ts     TEXT,
    changed_ts      TEXT,
    uid             INTEGER,
    gid             INTEGER,
    permissions     TEXT,
    allocated       INTEGER DEFAULT 1,
    file_type       TEXT,
    extracted_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_artifacts (
    artifact_id     TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    evidence_id     TEXT,
    plugin          TEXT NOT NULL,
    pid             INTEGER,
    process_name    TEXT,
    ppid            INTEGER,
    offset          TEXT,
    artifact_type   TEXT,
    raw_data        TEXT,
    risk_score      REAL DEFAULT 0,
    flags           TEXT,
    extracted_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS carved_files (
    carved_id       TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    evidence_id     TEXT,
    file_type       TEXT,
    start_offset    INTEGER,
    end_offset      INTEGER,
    size            INTEGER,
    md5             TEXT,
    sha256          TEXT,
    carved_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ioc_matches (
    ioc_id          TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    ioc_type        TEXT,
    indicator       TEXT,
    rule_name       TEXT,
    confidence      REAL,
    tags            TEXT,
    source_artifact TEXT,
    matched_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pcap_sessions (
    session_id      TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    evidence_id     TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    packet_count    INTEGER DEFAULT 0,
    byte_count      INTEGER DEFAULT 0,
    first_seen      TEXT,
    last_seen       TEXT,
    flags           TEXT,
    payload_preview TEXT,
    risk_score      REAL DEFAULT 0,
    tags            TEXT,
    analysed_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline_events (
    event_id        TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    event_type      TEXT,
    source          TEXT,
    description     TEXT,
    risk_score      REAL DEFAULT 0,
    related_pid     INTEGER,
    related_file    TEXT,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_risk_scores (
    score_id        TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    artifact_ref    TEXT,
    model_name      TEXT,
    score           REAL,
    classification  TEXT,
    features        TEXT,
    scored_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    entry_id        TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    actor           TEXT,
    target          TEXT,
    hash_before     TEXT,
    hash_after      TEXT,
    notes           TEXT,
    ts              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         TEXT,
    level           TEXT,
    module          TEXT,
    message         TEXT,
    ts              TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS fts_index USING fts5(
    case_id    UNINDEXED,
    file_id    UNINDEXED,
    name       UNINDEXED,
    full_path  UNINDEXED,
    source     UNINDEXED,
    content,
    tokenize = "unicode61"
);
"""

# ─── Utility ──────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _hash_file(filepath) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}

# ─── Database Layer ───────────────────────────────────────────────────────────
class CaseDatabase:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.case_dir = CASES_DIR / case_id
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.case_dir / "case.db"
        self._init_schema()

    def _init_schema(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            # DELETE journal mode — no -wal/-shm sidecar files on Windows
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA_SQL)
            # ── Schema migration: ensure extracted_files has all 20 columns ──
            try:
                cols = [r[1] for r in conn.execute("PRAGMA table_info(extracted_files)").fetchall()]
                expected = [
                    "file_id","case_id","evidence_id","name","full_path",
                    "size","md5","sha256","inode","parent_inode",
                    "created_ts","modified_ts","accessed_ts","changed_ts",
                    "uid","gid","permissions","allocated","file_type","extracted_at"
                ]
                missing = [c for c in expected if c not in cols]
                if missing:
                    conn.executescript("""
                        DROP TABLE IF EXISTS extracted_files;
                        CREATE TABLE extracted_files (
                            file_id         TEXT PRIMARY KEY,
                            case_id         TEXT NOT NULL,
                            evidence_id     TEXT,
                            name            TEXT,
                            full_path       TEXT,
                            size            INTEGER,
                            md5             TEXT,
                            sha256          TEXT,
                            inode           INTEGER,
                            parent_inode    INTEGER,
                            created_ts      TEXT,
                            modified_ts     TEXT,
                            accessed_ts     TEXT,
                            changed_ts      TEXT,
                            uid             INTEGER,
                            gid             INTEGER,
                            permissions     TEXT,
                            allocated       INTEGER DEFAULT 1,
                            file_type       TEXT,
                            extracted_at    TEXT NOT NULL
                        );
                    """)
                    log.info(f"Migrated extracted_files schema (added {missing})")
            except Exception as e:
                log.warning(f"Schema migration check failed: {e}")

            # ── FTS schema migration ──
            try:
                fts_cols = [r[1] for r in conn.execute("PRAGMA table_info(fts_index)").fetchall()]
                if "file_id" not in fts_cols or "full_path" not in fts_cols:
                    conn.executescript("""
                        DROP TABLE IF EXISTS fts_index;
                        CREATE VIRTUAL TABLE fts_index USING fts5(
                            case_id    UNINDEXED,
                            file_id    UNINDEXED,
                            name       UNINDEXED,
                            full_path  UNINDEXED,
                            source     UNINDEXED,
                            content,
                            tokenize = "unicode61"
                        );
                    """)
                    log.info("Migrated fts_index schema")
            except Exception as e:
                log.warning(f"FTS migration check failed: {e}")
            conn.commit()
        finally:
            if conn:
                conn.close()

    def execute(self, sql: str, params: tuple = ()) -> List[Dict]:
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            # Use DELETE journal mode (not WAL) so no -wal/-shm files are held open
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=NORMAL")
            cursor = conn.execute(sql, params)
            conn.commit()
            try:
                return [dict(row) for row in cursor.fetchall()]
            except Exception:
                return []
        except Exception as e:
            log.debug(f"DB execute error ({sql[:60]}): {e}")
            return []
        finally:
            if conn:
                conn.close()

    def log(self, level: str, module: str, message: str):
        self.execute(
            "INSERT INTO logs (case_id,level,module,message,ts) VALUES (?,?,?,?,?)",
            (self.case_id, level, module, message, _now())
        )

    def append_coc(self, action: str, actor: str, target: str,
                   notes: str = "", hash_before: str = "", hash_after: str = ""):
        self.execute(
            "INSERT INTO chain_of_custody VALUES (?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), self.case_id, action, actor,
             target, hash_before, hash_after, notes, _now())
        )

# ─── Engine 1: Case Initialization ───────────────────────────────────────────
class CaseInitializationEngine:
    def create_case(self, data: CaseCreate) -> Dict:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        db = CaseDatabase(case_id)
        db.execute(
            "INSERT INTO cases (case_id,case_number,case_name,description,created_at) VALUES (?,?,?,?,?)",
            (case_id, data.case_number, data.case_name, data.description, _now())
        )
        for inv in data.investigators:
            db.execute(
                "INSERT INTO investigators (case_id,name,added_at) VALUES (?,?,?)",
                (case_id, inv, _now())
            )
        db.append_coc("CASE_CREATED", ",".join(data.investigators) or "system",
                      case_id, f"Case initialized: {data.case_name}")
        db.log("INFO", "CaseInit", f"Case {case_id} created")
        evidence_dir = CASES_DIR / case_id / "evidence"
        evidence_dir.mkdir(exist_ok=True)
        log.info(f"Case created: {case_id}")
        return {
            "case_id": case_id,
            "case_number": data.case_number,
            "case_name": data.case_name,
            "db_path": str(db.db_path),
            "evidence_dir": str(evidence_dir),
            "created_at": _now(),
        }

    def list_cases(self) -> List[Dict]:
        results = []
        for case_dir in CASES_DIR.iterdir():
            if case_dir.is_dir():
                db_path = case_dir / "case.db"
                if db_path.exists():
                    db = CaseDatabase(case_dir.name)
                    rows = db.execute("SELECT * FROM cases WHERE case_id=?", (case_dir.name,))
                    results.extend(rows)
        return results

# ─── Engine 2: Evidence Ingestion ────────────────────────────────────────────
class EvidenceIngestionEngine:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db = CaseDatabase(case_id)
        self.evidence_dir = CASES_DIR / case_id / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    async def ingest(self, upload: UploadFile, investigator: str = "system") -> EvidenceItem:
        suffix = Path(upload.filename).suffix.lower()
        if suffix not in SUPPORTED_EVIDENCE:
            raise HTTPException(400, f"Unsupported evidence type: {suffix}")

        evidence_id = str(uuid.uuid4())
        dest_path = self.evidence_dir / f"{evidence_id}{suffix}"

        async with aiofiles.open(dest_path, "wb") as f:
            while chunk := await upload.read(65536):
                await f.write(chunk)

        loop = asyncio.get_event_loop()
        with ProcessPoolExecutor(max_workers=1) as pool:
            hashes = await loop.run_in_executor(pool, _hash_file, dest_path)

        file_size = dest_path.stat().st_size
        evidence_type = self._detect_type(suffix)
        ts = _now()

        item = EvidenceItem(
            evidence_id=evidence_id, filename=upload.filename,
            file_size=file_size, md5=hashes["md5"], sha256=hashes["sha256"],
            acquisition_ts=ts, evidence_type=evidence_type,
        )
        self.db.execute(
            "INSERT INTO evidence_items VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, self.case_id, upload.filename, str(dest_path),
             file_size, hashes["md5"], hashes["sha256"], ts, "READ_ONLY", evidence_type, ts)
        )
        self.db.append_coc("EVIDENCE_INGESTED", investigator, upload.filename,
                           hash_after=hashes["sha256"],
                           notes=f"Size: {file_size} bytes | MD5: {hashes['md5']}")
        self.db.execute(
            "INSERT INTO fts_index (case_id,content,source) VALUES (?,?,?)",
            (self.case_id, f"{upload.filename} {evidence_type} {hashes['sha256']}", "evidence")
        )
        log.info(f"Evidence ingested: {upload.filename} SHA256={hashes['sha256']}")
        return item

    def _detect_type(self, suffix: str) -> str:
        return {
            ".dd": "RAW_DISK", ".img": "RAW_DISK", ".raw": "RAW_DISK",
            ".vmem": "MEMORY_DUMP", ".pcap": "NETWORK_CAPTURE",
            ".log": "LOG_FILE", ".evtx": "EVENT_LOG",
        }.get(suffix, "UNKNOWN")

# ─── Engine 3: File System Walker ────────────────────────────────────────────
#
# Priority order:
#   1. pytsk3          — best, parses any TSK-supported FS natively
#   2. mmls + fls/icat — The Sleuth Kit CLI tools (apt install sleuthkit)
#   3. python-magic    — pure-Python FAT/NTFS/Ext parser (no deps needed)
#   4. raw carving     — last resort: scan image for file signatures
#
class FileSystemWalker:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db = CaseDatabase(case_id)

    # ── public entry point ────────────────────────────────────────
    def walk(self, image_path: str, evidence_id: str) -> List[Dict]:
        results: List[Dict] = []

        # 1. pytsk3
        if PYTSK3_AVAILABLE:
            try:
                results = self._walk_pytsk3(image_path, evidence_id)
                if results:
                    log.info(f"pytsk3 parsed {len(results)} entries")
                    return results
            except Exception as e:
                log.warning(f"pytsk3 failed: {e}")

        # 2. sleuthkit CLI  (fls)
        if self._has_tool("fls"):
            try:
                results = self._walk_fls(image_path, evidence_id)
                if results:
                    log.info(f"fls parsed {len(results)} entries")
                    return results
            except Exception as e:
                log.warning(f"fls failed: {e}")

        # 3. pure-Python filesystem parser
        try:
            results = self._walk_python(image_path, evidence_id)
            if results:
                log.info(f"Python parser found {len(results)} entries")
                return results
        except Exception as e:
            log.warning(f"Python FS parser failed: {e}")

        # 4. raw carving fallback — always produces something
        log.info("Using raw carving fallback for file listing")
        return self._walk_carve(image_path, evidence_id)

    # ── 1. pytsk3 ─────────────────────────────────────────────────
    def _walk_pytsk3(self, image_path: str, evidence_id: str) -> List[Dict]:
        results: List[Dict] = []
        img = pytsk3.Img_Info(image_path)
        # detect partition table; fall back to offset 0
        offsets = [0]
        try:
            pt = pytsk3.Volume_Info(img)
            offsets = [p.start * 512 for p in pt if p.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC]
        except Exception:
            pass
        for offset in offsets:
            try:
                fs = pytsk3.FS_Info(img, offset=offset)
                self._recurse_pytsk3(fs, fs.open_dir("/"), "/", results, evidence_id)
            except Exception:
                continue
        return results

    def _recurse_pytsk3(self, fs, directory, path, results, evidence_id):
        for entry in directory:
            try:
                if entry.info.name.name in (b".", b".."):
                    continue
                name = entry.info.name.name.decode("utf-8", errors="ignore") or \
                       entry.info.name.name.decode("latin-1", errors="ignore")
                meta = entry.info.meta
                if meta is None:
                    continue
                full_path = f"{path}{name}"
                r = self._make_record(
                    evidence_id=evidence_id, name=name, full_path=full_path,
                    size=meta.size, inode=meta.addr,
                    mtime=meta.mtime, atime=meta.atime,
                    ctime=meta.ctime, crtime=getattr(meta, "crtime", 0),
                    uid=meta.uid, gid=meta.gid, mode=meta.mode,
                    allocated=1 if (meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC) else 0,
                    file_type="DIR" if meta.type == pytsk3.TSK_FS_META_TYPE_DIR else "FILE",
                )
                results.append(r)
                self._save(r)
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR and len(results) < 100000:
                    self._recurse_pytsk3(fs, entry.as_directory(), f"{full_path}/", results, evidence_id)
            except Exception:
                continue

    # ── 2. sleuthkit CLI ──────────────────────────────────────────
    def _walk_fls(self, image_path: str, evidence_id: str) -> List[Dict]:
        """Run `fls -r -m / <image>` and parse its body file output."""
        results: List[Dict] = []
        offsets = self._mmls_offsets(image_path) or [""]
        for offset in offsets:
            cmd = ["fls", "-r", "-m", "/"]
            if offset:
                cmd += ["-o", str(offset)]
            cmd.append(image_path)
            try:
                # Use binary output so we control the decode ourselves
                out = subprocess.run(cmd, capture_output=True, text=False, timeout=120)
                # Decode as UTF-8, fallback to latin-1 for each line
                for raw_line in out.stdout.split(b"\n"):
                    try:
                        line = raw_line.decode("utf-8")
                    except UnicodeDecodeError:
                        line = raw_line.decode("latin-1")
                    r = self._parse_fls_line(line, evidence_id)
                    if r:
                        results.append(r)
                        self._save(r)
            except Exception as e:
                log.warning(f"fls partition offset {offset} failed: {e}")
        return results

    def _mmls_offsets(self, image_path: str) -> List[str]:
        """Return sector offsets of allocated partitions via mmls."""
        try:
            out = subprocess.run(["mmls", image_path], capture_output=True, text=True, timeout=30)
            offsets = []
            for line in out.stdout.splitlines():
                parts = line.split()
                # mmls output: 000: Meta / 001: Alloc  start_sector  ...
                if len(parts) >= 3 and parts[0].endswith(":"):
                    try:
                        offsets.append(parts[2])
                    except Exception:
                        pass
            return offsets[1:] if offsets else []
        except Exception:
            return []

    def _parse_fls_line(self, line: str, evidence_id: str) -> Optional[Dict]:
        """
        fls body-file format (mactime):
        0|/path/to/file|inode|permissions|uid|gid|size|atime|mtime|ctime|crtime
        """
        try:
            parts = line.strip().split("|")
            if len(parts) < 11:
                return None
            full_path = parts[1].lstrip("/")
            name = full_path.split("/")[-1] or full_path
            size = int(parts[6]) if parts[6].isdigit() else 0

            def ts(v: str) -> Optional[str]:
                try:
                    t = int(v)
                    if t > 0:
                        return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
                except Exception:
                    pass
                return None

            return self._make_record(
                evidence_id=evidence_id, name=name, full_path="/" + full_path,
                size=size, inode=int(parts[2]) if parts[2].isdigit() else 0,
                mtime=int(parts[8]) if parts[8].isdigit() else 0,
                atime=int(parts[7]) if parts[7].isdigit() else 0,
                ctime=int(parts[9]) if parts[9].isdigit() else 0,
                crtime=int(parts[10]) if parts[10].isdigit() else 0,
                uid=int(parts[4]) if parts[4].isdigit() else 0,
                gid=int(parts[5]) if parts[5].isdigit() else 0,
                mode=0, allocated=1, file_type="FILE",
                permissions=parts[3],
            )
        except Exception:
            return None

    # ── 3. pure-Python FS parser ──────────────────────────────────
    def _walk_python(self, image_path: str, evidence_id: str) -> List[Dict]:
        """
        Pure-Python parser for FAT16/FAT32/NTFS/Ext2-4.
        Reads MBR/GPT partition table, then dispatches to FS-specific parser.
        """
        results: List[Dict] = []
        with open(image_path, "rb") as f:
            # Read MBR
            mbr = f.read(512)
            if len(mbr) < 512:
                return results

            # Check MBR signature
            if mbr[510:512] != b"\x55\xAA":
                # No partition table — try offset 0 directly
                f.seek(0)
                results += self._parse_fs_at(f, 0, evidence_id)
                return results

            # Parse MBR partition table (4 entries at offset 446)
            partitions = []
            for i in range(4):
                entry = mbr[446 + i * 16: 446 + (i + 1) * 16]
                status = entry[0]
                ptype  = entry[4]
                lba    = struct.unpack_from("<I", entry, 8)[0]
                size   = struct.unpack_from("<I", entry, 12)[0]
                if size > 0 and ptype != 0x00:
                    partitions.append((lba * 512, ptype))

            if not partitions:
                # Try raw offset 0
                f.seek(0)
                results += self._parse_fs_at(f, 0, evidence_id)
            else:
                for offset, ptype in partitions:
                    try:
                        parsed = self._parse_fs_at(f, offset, evidence_id)
                        results += parsed
                    except Exception as e:
                        log.debug(f"Partition at {offset} (type {ptype:#x}): {e}")

        return results

    def _parse_fs_at(self, f, offset: int, evidence_id: str) -> List[Dict]:
        """Detect filesystem type at byte offset and dispatch to correct parser."""
        try:
            f.seek(offset)
            header = f.read(1024)
        except Exception:
            return []

        if len(header) < 512:
            return []

        # ── NTFS: OEM ID "NTFS    " at bytes 3–10 ─────────────────
        if header[3:11] == b"NTFS    ":
            log.info(f"Detected NTFS at offset {offset:#x}")
            return self._parse_ntfs(f, offset, header, evidence_id)

        # ── FAT: check multiple signatures ────────────────────────
        # FAT32 extended BPB: "FAT32   " at bytes 82–90
        # FAT16 extended BPB: "FAT16   " or "FAT12   " at bytes 54–62
        # Also check OEM name and BPB sanity (bytes_per_sector must be power of 2, 512–4096)
        bps = struct.unpack_from("<H", header, 11)[0]
        is_valid_bps = bps in (512, 1024, 2048, 4096)
        fat32_sig = header[82:87] == b"FAT32"
        fat16_sig = header[54:57] in (b"FAT", )   # covers FAT12/FAT16
        fat_boot  = header[510:512] == b"\x55\xAA"

        if (fat32_sig or fat16_sig) and is_valid_bps:
            log.info(f"Detected FAT{'32' if fat32_sig else '16/12'} at offset {offset:#x}")
            return self._parse_fat(f, offset, header, evidence_id)

        # Fallback FAT detection: valid BPB + boot signature + jump instruction
        jump_ok = header[0] in (0xEB, 0xE9)
        if jump_ok and is_valid_bps and fat_boot:
            log.info(f"Detected FAT (heuristic) at offset {offset:#x}")
            return self._parse_fat(f, offset, header, evidence_id)

        # ── Ext2/3/4: superblock magic 0xEF53 at partition+1024+56 ─
        try:
            f.seek(offset + 1024)
            sb = f.read(512)
            if len(sb) >= 58 and sb[56:58] == b"\x53\xEF":
                log.info(f"Detected Ext2/3/4 at offset {offset:#x}")
                return self._parse_ext(f, offset, sb, evidence_id)
        except Exception:
            pass

        log.debug(f"Unknown filesystem at offset {offset:#x} (header: {header[:16].hex()})")
        return []

    # ── FAT parser ────────────────────────────────────────────────
    def _parse_fat(self, f, offset: int, bpb: bytes, evidence_id: str) -> List[Dict]:
        """
        Fully recursive FAT12/16/32 parser.
        - Reads entire FAT table into RAM for O(1) cluster lookups
        - Follows cluster chains into every subdirectory recursively
        - Reconstructs LFN (long file names) from chained 0x0F entries
        - Records deleted entries (0xE5) as unallocated
        - Does NOT break on 0x00 mid-cluster (only stops per-cluster read)
        """
        results: List[Dict] = []
        try:
            bps  = struct.unpack_from("<H", bpb, 11)[0] or 512   # bytes per sector
            spc  = bpb[13] or 1                                    # sectors per cluster
            rsvd = struct.unpack_from("<H", bpb, 14)[0]           # reserved sectors
            nfat = bpb[16]                                          # number of FATs
            rde  = struct.unpack_from("<H", bpb, 17)[0]           # root dir entries (FAT16)
            fs16 = struct.unpack_from("<H", bpb, 22)[0]           # FAT size in sectors (FAT16)
            fs32 = struct.unpack_from("<I", bpb, 36)[0]           # FAT size in sectors (FAT32)
            fat_sz   = fs16 if fs16 else fs32
            is_fat32 = fs16 == 0
            csz      = bps * spc                                   # cluster size in bytes

            fat_start  = offset + rsvd * bps
            root_start = fat_start + nfat * fat_sz * bps          # FAT16 root dir start
            data_start = root_start + rde * 32                     # first data cluster (cluster 2)

            log.info(
                f"FAT{'32' if is_fat32 else '16/12'} detected: "
                f"bps={bps} spc={spc} csz={csz} rsvd={rsvd} "
                f"fat_sz={fat_sz} rde={rde} "
                f"fat_start={fat_start:#x} data_start={data_start:#x}"
            )

            # ── Load FAT table ────────────────────────────────────
            f.seek(fat_start)
            fat_bytes = f.read(fat_sz * bps)
            log.info(f"FAT table loaded: {len(fat_bytes)} bytes")

            # ── Cluster helpers ───────────────────────────────────
            def next_cluster(c: int) -> int:
                if is_fat32:
                    pos = c * 4
                    if pos + 4 > len(fat_bytes): return 0x0FFFFFFF
                    return struct.unpack_from("<I", fat_bytes, pos)[0] & 0x0FFFFFFF
                else:
                    pos = c * 2
                    if pos + 2 > len(fat_bytes): return 0xFFFF
                    return struct.unpack_from("<H", fat_bytes, pos)[0]

            def is_eof(c: int) -> bool:
                return (c >= 0x0FFFFFF8) if is_fat32 else (c >= 0xFFF8)

            def clus_to_off(c: int) -> int:
                # cluster 2 maps to data_start
                return data_start + (c - 2) * csz

            def read_chain(start: int) -> bytes:
                """Read all bytes of a cluster chain (for directory data)."""
                out = b""
                c, seen = start, set()
                while 2 <= c < 0x0FFFFFF0 and c not in seen:
                    seen.add(c)
                    try:
                        f.seek(clus_to_off(c))
                        out += f.read(csz)
                    except Exception:
                        break
                    c = next_cluster(c)
                    if is_eof(c):
                        break
                return out

            # ── Timestamp helper (defined before use) ────────────
            def fat_ts(date: int, time: int) -> int:
                try:
                    y  = ((date >> 9) & 0x7F) + 1980
                    mo = max((date >> 5) & 0x0F, 1)
                    d  = max(date & 0x1F, 1)
                    h  = (time >> 11) & 0x1F
                    mi = (time >> 5)  & 0x3F
                    s  = min((time & 0x1F) * 2, 59)
                    return int(datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp())
                except Exception:
                    return 0

            # ── Directory parser (recursive) ──────────────────────
            visited_clusters: set = set()   # prevent infinite loops on corrupt images

            def parse_dir(raw: bytes, path: str, depth: int):
                if depth > 20 or len(results) >= 200000:
                    return

                lfn: Dict[int, str] = {}
                pos = 0
                # Process every 32-byte slot; 0x00 only marks end within ONE cluster read,
                # so we must NOT break mid-stream when reading a multi-cluster chain.
                # We break only if this entry is 0x00 AND we have not crossed a cluster boundary.
                cluster_boundary = csz  # reset stop-on-null every cluster_size bytes

                while pos + 32 <= len(raw):
                    slot = raw[pos:pos + 32]
                    pos += 32

                    first_byte = slot[0]

                    # 0x00 = end of directory IN THIS CLUSTER
                    # Only stop if we haven't crossed to a new cluster yet.
                    if first_byte == 0x00:
                        # Advance to next cluster boundary and keep checking
                        remainder = pos % csz
                        if remainder == 0:
                            continue          # already at boundary, keep going
                        skip = csz - remainder
                        pos += skip           # jump to next cluster start
                        continue

                    # 0xE5 = deleted file
                    if first_byte == 0xE5:
                        attrs = slot[11]
                        if attrs != 0x0F:     # not an LFN slot
                            try:
                                n8 = slot[0:8].rstrip(b" \x00\xff").decode("ascii", errors="ignore")
                                nx = slot[8:11].rstrip(b" \x00\xff").decode("ascii", errors="ignore")
                                dn = "~" + n8 + ("." + nx if nx else "")
                                sz = struct.unpack_from("<I", slot, 28)[0]
                                mt = fat_ts(struct.unpack_from("<H", slot, 24)[0],
                                            struct.unpack_from("<H", slot, 22)[0])
                                r = self._make_record(
                                    evidence_id=evidence_id, name=dn,
                                    full_path=path + dn, size=sz, inode=0,
                                    mtime=mt, atime=mt, ctime=mt, crtime=mt,
                                    uid=0, gid=0, mode=0o644,
                                    allocated=0, file_type="FILE",
                                )
                                results.append(r); self._save(r)
                            except Exception:
                                pass
                        lfn = {}
                        continue

                    attrs = slot[11]

                    # LFN entry (attrs = 0x0F)
                    if attrs == 0x0F:
                        seq = first_byte & 0x1F
                        # LFN entry stores 13 UTF-16LE chars across 3 fields
                        chars = slot[1:11] + slot[14:26] + slot[28:32]
                        try:
                            decoded = chars.decode("utf-16-le", errors="ignore")
                            # Strip null terminator and 0xFFFF padding sentinels
                            part = decoded.split("\x00")[0].replace("\uFFFF", "").replace("\uFFFD", "")
                            if part:
                                lfn[seq] = part
                        except Exception:
                            pass
                        continue

                    # Volume label — skip
                    if attrs & 0x08:
                        lfn = {}
                        continue

                    # 8.3 entry
                    is_dir_e = bool(attrs & 0x10)
                    n8 = slot[0:8].rstrip(b" \x00\xff").decode("ascii", errors="ignore")
                    nx = slot[8:11].rstrip(b" \x00\xff").decode("ascii", errors="ignore")
                    short = n8 + ("." + nx if nx else "")

                    if lfn:
                        # LFN seq numbers: highest seq = start of filename, seq=1 = end
                        # Must sort DESCENDING to get correct order
                        name = "".join(v for _, v in sorted(lfn.items(), reverse=True)).rstrip("\x00\xff") or short
                        lfn = {}
                    else:
                        name = short

                    if not name.strip() or name in (".", ".."):
                        continue

                    sz = struct.unpack_from("<I", slot, 28)[0]

                    # ── Cluster number ────────────────────────────
                    # Bytes 26-27 = low word, bytes 20-21 = high word (FAT32 only)
                    clus_lo = struct.unpack_from("<H", slot, 26)[0]
                    clus_hi = struct.unpack_from("<H", slot, 20)[0] if is_fat32 else 0
                    first_clus = (clus_hi << 16) | clus_lo

                    mt = fat_ts(struct.unpack_from("<H", slot, 24)[0],
                                struct.unpack_from("<H", slot, 22)[0])
                    ct = fat_ts(struct.unpack_from("<H", slot, 16)[0],
                                struct.unpack_from("<H", slot, 14)[0])
                    at = fat_ts(struct.unpack_from("<H", slot, 18)[0], 0)

                    fp = path + name
                    r = self._make_record(
                        evidence_id=evidence_id, name=name,
                        full_path=fp, size=sz, inode=first_clus,
                        mtime=mt, atime=at, ctime=mt, crtime=ct,
                        uid=0, gid=0,
                        mode=0o755 if is_dir_e else 0o644,
                        allocated=1,
                        file_type="DIR" if is_dir_e else "FILE",
                    )
                    results.append(r); self._save(r)

                    # ── Recurse into subdirectory ──────────────────
                    if is_dir_e and first_clus >= 2 and first_clus not in visited_clusters:
                        visited_clusters.add(first_clus)
                        try:
                            sub_raw = read_chain(first_clus)
                            if sub_raw:
                                log.debug(
                                    f"Recursing into {fp!r} "
                                    f"(cluster {first_clus}, {len(sub_raw)} bytes)"
                                )
                                parse_dir(sub_raw, fp + "/", depth + 1)
                        except Exception as e:
                            log.debug(f"Subdir error '{name}': {e}")

            # ── Kick off from root ────────────────────────────────
            if is_fat32:
                root_clus = struct.unpack_from("<I", bpb, 44)[0]
                visited_clusters.add(root_clus)
                root_raw = read_chain(root_clus)
                log.info(f"FAT32 root cluster={root_clus}, chain={len(root_raw)} bytes")
            else:
                f.seek(root_start)
                root_raw = f.read(rde * 32)
                log.info(f"FAT16 root dir: {len(root_raw)} bytes ({rde} entries) at {root_start:#x}")

            parse_dir(root_raw, "/", 0)
            log.info(f"FAT parse complete: {len(results)} total entries")

        except Exception as e:
            import traceback
            log.warning(f"FAT parse error: {e}\n{traceback.format_exc()}")
        return results

    def _fat_datetime(self, date: int, time: int) -> int:
        try:
            y  = ((date >> 9) & 0x7F) + 1980
            mo = max((date >> 5) & 0x0F, 1)
            d  = max(date & 0x1F, 1)
            h  = (time >> 11) & 0x1F
            mi = (time >> 5)  & 0x3F
            s  = min((time & 0x1F) * 2, 59)
            return int(datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp())
        except Exception:
            return 0

    # ── NTFS parser ───────────────────────────────────────────────
    def _parse_ntfs(self, f, offset: int, boot: bytes, evidence_id: str) -> List[Dict]:
        """
        Full NTFS parser using $MFT.
        Pass 1: read every FILE record, extract name + parent inode + metadata.
        Pass 2: resolve full paths by walking parent references up to root (inode 5).
        """
        results: List[Dict] = []
        try:
            bytes_per_sector    = struct.unpack_from("<H", boot, 11)[0] or 512
            sectors_per_cluster = boot[13] or 8
            cluster_size        = bytes_per_sector * sectors_per_cluster
            mft_cluster         = struct.unpack_from("<q", boot, 48)[0]
            mft_offset          = offset + mft_cluster * cluster_size

            raw_cpr = struct.unpack_from("<i", boot, 64)[0]
            mft_record_size = (2 ** abs(raw_cpr)) if raw_cpr < 0 else max(raw_cpr * cluster_size, 1024)
            mft_record_size = max(mft_record_size, 1024)

            # ── Pass 1: collect all MFT records ───────────────────
            # mft_records[inode] = {name, parent_inode, size, mtime, ...}
            mft_records: Dict[int, Dict] = {}
            MAX_RECORDS = 200000

            for rec_num in range(MAX_RECORDS):
                try:
                    f.seek(mft_offset + rec_num * mft_record_size)
                    rec = f.read(mft_record_size)
                    if len(rec) < 48 or rec[0:4] != b"FILE":
                        if rec_num > 100 and rec[0:4] not in (b"FILE", b"BAAD"):
                            break  # past end of MFT
                        continue

                    # Apply fixup array so sector endings are correct
                    rec = bytearray(rec)
                    usa_offset = struct.unpack_from("<H", rec, 4)[0]
                    usa_count  = struct.unpack_from("<H", rec, 6)[0]
                    if usa_offset + usa_count * 2 <= len(rec):
                        seq_num = struct.unpack_from("<H", rec, usa_offset)[0]
                        for k in range(1, usa_count):
                            sec_end = k * bytes_per_sector - 2
                            if sec_end + 1 < len(rec):
                                rec[sec_end]     = rec[usa_offset + k * 2]
                                rec[sec_end + 1] = rec[usa_offset + k * 2 + 1]

                    flags = struct.unpack_from("<H", rec, 22)[0]
                    if not (flags & 0x01):  # not in-use
                        continue
                    is_dir = bool(flags & 0x02)

                    attr_off = struct.unpack_from("<H", rec, 20)[0]
                    name, parent_inode, size, mtime, ctime, atime, crtime = \
                        self._ntfs_parse_attrs(bytes(rec), attr_off, cluster_size, offset, f)

                    if not name:
                        continue

                    mft_records[rec_num] = {
                        "inode":        rec_num,
                        "name":         name,
                        "parent_inode": parent_inode,
                        "size":         size,
                        "mtime":        mtime,
                        "ctime":        ctime,
                        "atime":        atime,
                        "crtime":       crtime,
                        "is_dir":       is_dir,
                        "allocated":    1,
                    }
                except Exception:
                    continue

            log.debug(f"NTFS pass1: {len(mft_records)} records")

            # ── Pass 2: resolve full paths ─────────────────────────
            path_cache: Dict[int, str] = {5: "/"}  # inode 5 = root

            def resolve_path(inode: int, depth: int = 0) -> str:
                if inode in path_cache:
                    return path_cache[inode]
                if depth > 32 or inode not in mft_records:
                    return "/<unknown>/"
                rec = mft_records[inode]
                parent_path = resolve_path(rec["parent_inode"], depth + 1)
                full = parent_path.rstrip("/") + "/" + rec["name"]
                path_cache[inode] = full
                return full

            for inode, rec in mft_records.items():
                try:
                    parent_path = resolve_path(rec["parent_inode"])
                    full_path = parent_path.rstrip("/") + "/" + rec["name"]
                    r = self._make_record(
                        evidence_id=evidence_id,
                        name=rec["name"],
                        full_path=full_path,
                        size=rec["size"],
                        inode=inode,
                        mtime=rec["mtime"], atime=rec["atime"],
                        ctime=rec["ctime"], crtime=rec["crtime"],
                        uid=0, gid=0, mode=0,
                        allocated=rec["allocated"],
                        file_type="DIR" if rec["is_dir"] else "FILE",
                    )
                    results.append(r)
                    self._save(r)
                except Exception:
                    continue

            log.info(f"NTFS parsed {len(results)} entries")

        except Exception as e:
            log.warning(f"NTFS parse error: {e}")
        return results

    def _ntfs_parse_attrs(self, rec: bytes, attr_off: int,
                           cluster_size: int, part_offset: int, f) -> tuple:
        """
        Walk NTFS attribute list.
        Returns (name, parent_inode, size, mtime, ctime, atime, crtime).
        Prefers $FILE_NAME with namespace 1 (Win32) over namespace 2 (DOS).
        """
        name = ""
        name_ns = 99
        parent_inode = 5
        size = 0
        mtime = ctime = atime = crtime = 0
        off = attr_off

        while off + 8 <= len(rec):
            attr_type = struct.unpack_from("<I", rec, off)[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack_from("<I", rec, off + 4)[0]
            if attr_len < 8 or off + attr_len > len(rec):
                break

            non_res = rec[off + 8]

            # $STANDARD_INFORMATION = 0x10
            if attr_type == 0x10 and not non_res:
                try:
                    co = struct.unpack_from("<H", rec, off + 20)[0]
                    c = off + co
                    crtime = self._ntfs_ts(struct.unpack_from("<q", rec, c)[0])
                    mtime  = self._ntfs_ts(struct.unpack_from("<q", rec, c + 8)[0])
                    ctime  = self._ntfs_ts(struct.unpack_from("<q", rec, c + 16)[0])
                    atime  = self._ntfs_ts(struct.unpack_from("<q", rec, c + 24)[0])
                except Exception:
                    pass

            # $FILE_NAME = 0x30
            if attr_type == 0x30 and not non_res:
                try:
                    co = struct.unpack_from("<H", rec, off + 20)[0]
                    c = off + co
                    par_ref = struct.unpack_from("<q", rec, c)[0] & 0x0000FFFFFFFFFFFF
                    fname_crtime = self._ntfs_ts(struct.unpack_from("<q", rec, c + 8)[0])
                    fname_mtime  = self._ntfs_ts(struct.unpack_from("<q", rec, c + 16)[0])
                    fname_ctime  = self._ntfs_ts(struct.unpack_from("<q", rec, c + 24)[0])
                    fname_atime  = self._ntfs_ts(struct.unpack_from("<q", rec, c + 32)[0])
                    alloc_size   = struct.unpack_from("<q", rec, c + 40)[0]
                    real_size    = struct.unpack_from("<q", rec, c + 48)[0]
                    ns           = rec[c + 65] if c + 65 < len(rec) else 3
                    fname_len    = rec[c + 64] if c + 64 < len(rec) else 0
                    fname_bytes  = rec[c + 66: c + 66 + fname_len * 2]
                    fname        = fname_bytes.decode("utf-16-le", errors="ignore")

                    # Prefer Win32 (ns=1) or POSIX (ns=0), skip DOS-only (ns=2)
                    if ns < name_ns and fname and not fname.startswith("$"):
                        name      = fname
                        name_ns   = ns
                        parent_inode = par_ref
                        if real_size:
                            size = real_size
                        # Use $FILE_NAME timestamps only if $SI not found yet
                        if not crtime:
                            crtime = fname_crtime
                            mtime  = fname_mtime
                            ctime  = fname_ctime
                            atime  = fname_atime
                except Exception:
                    pass

            # $DATA = 0x80
            if attr_type == 0x80:
                try:
                    if non_res:
                        real_sz = struct.unpack_from("<q", rec, off + 48)[0]
                        if real_sz > 0:
                            size = real_sz
                    else:
                        co = struct.unpack_from("<H", rec, off + 20)[0]
                        cl = struct.unpack_from("<I", rec, off + 16)[0]
                        if cl > 0:
                            size = cl
                except Exception:
                    pass

            off += attr_len

        return name, parent_inode, size, mtime, ctime, atime, crtime

    def _ntfs_ts(self, win_ts: int) -> int:
        """Convert Windows FILETIME (100ns since 1601-01-01) to Unix timestamp."""
        try:
            return max(0, int((win_ts - 116444736000000000) / 10000000))
        except Exception:
            return 0

    # ── Ext2/3/4 parser ───────────────────────────────────────────
    def _parse_ext(self, f, part_offset: int, superblock: bytes, evidence_id: str) -> List[Dict]:
        """
        Parse Ext2/3/4 by reading directory entry blocks.
        Ext dir entries: inode(4) + rec_len(2) + name_len(1) + file_type(1) + name(name_len)
        This gives us real filenames instead of inode_N placeholders.
        """
        results: List[Dict] = []
        try:
            inodes_count     = struct.unpack_from("<I", superblock, 0)[0]
            block_size       = 1024 << struct.unpack_from("<I", superblock, 24)[0]
            blocks_per_group = struct.unpack_from("<I", superblock, 32)[0]
            inodes_per_group = struct.unpack_from("<I", superblock, 40)[0]
            inode_size_sb    = struct.unpack_from("<H", superblock, 88)[0] or 128
            first_data_block = struct.unpack_from("<I", superblock, 20)[0]
            first_ino        = struct.unpack_from("<I", superblock, 84)[0] or 11

            gdt_offset = part_offset + (first_data_block + 1) * block_size
            num_groups = max(1, (inodes_count + inodes_per_group - 1) // inodes_per_group)
            GDESC_SIZE = 32

            # ── Build inode table: inode_num → (offset_in_image, size, mode, timestamps) ──
            inode_info: Dict[int, Dict] = {}

            for g in range(min(num_groups, 1024)):
                try:
                    f.seek(gdt_offset + g * GDESC_SIZE)
                    gd = f.read(GDESC_SIZE)
                    if len(gd) < 32:
                        break
                    inode_table_block = struct.unpack_from("<I", gd, 8)[0]
                    dir_bitmap_block  = struct.unpack_from("<I", gd, 4)[0]
                    inode_table_off   = part_offset + inode_table_block * block_size

                    for i in range(inodes_per_group):
                        inum = g * inodes_per_group + i + 1
                        if inum > inodes_count or inum < first_ino:
                            continue
                        try:
                            f.seek(inode_table_off + i * inode_size_sb)
                            inode = f.read(inode_size_sb)
                            if len(inode) < 60:
                                continue
                            mode  = struct.unpack_from("<H", inode, 0)[0]
                            size  = struct.unpack_from("<I", inode, 4)[0]
                            atime = struct.unpack_from("<I", inode, 8)[0]
                            ctime = struct.unpack_from("<I", inode, 12)[0]
                            mtime = struct.unpack_from("<I", inode, 16)[0]
                            uid   = struct.unpack_from("<H", inode, 2)[0]
                            gid   = struct.unpack_from("<H", inode, 24)[0]
                            links = struct.unpack_from("<H", inode, 26)[0]
                            if mode == 0 or links == 0:
                                continue
                            # Direct block pointers at offset 40 (12 direct blocks)
                            blocks = [struct.unpack_from("<I", inode, 40 + j * 4)[0]
                                      for j in range(12)]
                            inode_info[inum] = {
                                "mode": mode, "size": size, "uid": uid, "gid": gid,
                                "atime": atime, "ctime": ctime, "mtime": mtime,
                                "blocks": blocks,
                            }
                        except Exception:
                            continue
                except Exception:
                    continue

            log.debug(f"Ext: loaded {len(inode_info)} inodes")

            # ── Walk directory entries ──────────────────────────────
            # Start from root inode (inode 2) and recurse
            visited_inodes: set = set()
            path_cache: Dict[int, str] = {2: "/"}

            def read_dir_block(block_num: int) -> bytes:
                if block_num == 0:
                    return b""
                try:
                    f.seek(part_offset + block_num * block_size)
                    return f.read(block_size)
                except Exception:
                    return b""

            def parse_dir_inode(inum: int, path: str, depth: int):
                if depth > 30 or inum in visited_inodes or len(results) >= 200000:
                    return
                if inum not in inode_info:
                    return
                visited_inodes.add(inum)
                info = inode_info[inum]

                for blk in info["blocks"]:
                    if blk == 0:
                        continue
                    data = read_dir_block(blk)
                    if not data:
                        continue
                    pos = 0
                    while pos + 8 <= len(data):
                        child_ino = struct.unpack_from("<I", data, pos)[0]
                        rec_len   = struct.unpack_from("<H", data, pos + 4)[0]
                        name_len  = data[pos + 6]
                        ftype     = data[pos + 7] if pos + 7 < len(data) else 0

                        if rec_len < 8 or rec_len > 4096:
                            break

                        if child_ino != 0 and name_len > 0:
                            raw_name = data[pos + 8: pos + 8 + name_len]
                            # Ext stores names as raw bytes — try UTF-8 first, then latin-1
                            try:
                                name = raw_name.decode("utf-8")
                            except UnicodeDecodeError:
                                name = raw_name.decode("latin-1")

                            if name not in (".", "..") and name.strip():
                                is_dir = (ftype == 2) or (
                                    child_ino in inode_info and
                                    bool(inode_info[child_ino]["mode"] & 0x4000)
                                )
                                full_path = path.rstrip("/") + "/" + name
                                child_info = inode_info.get(child_ino, {})
                                r = self._make_record(
                                    evidence_id=evidence_id,
                                    name=name,
                                    full_path=full_path,
                                    size=child_info.get("size", 0),
                                    inode=child_ino,
                                    mtime=child_info.get("mtime", 0),
                                    atime=child_info.get("atime", 0),
                                    ctime=child_info.get("ctime", 0),
                                    crtime=child_info.get("ctime", 0),
                                    uid=child_info.get("uid", 0),
                                    gid=child_info.get("gid", 0),
                                    mode=child_info.get("mode", 0),
                                    allocated=1,
                                    file_type="DIR" if is_dir else "FILE",
                                )
                                results.append(r)
                                self._save(r)
                                if is_dir and child_ino not in visited_inodes:
                                    parse_dir_inode(child_ino, full_path, depth + 1)

                        pos += rec_len

            # Parse from root inode 2
            parse_dir_inode(2, "/", 0)
            log.info(f"Ext parser: {len(results)} entries from directory traversal")

        except Exception as e:
            import traceback
            log.warning(f"Ext parse error: {e}\n{traceback.format_exc()}")
        return results

    # ── 4. raw carving fallback ───────────────────────────────────
    def _walk_carve(self, image_path: str, evidence_id: str) -> List[Dict]:
        """
        Last resort: scan the raw image for known file signatures and
        record them as pseudo-files so the triage is never empty.
        """
        results: List[Dict] = []
        SIGS = {
            b"\x4D\x5A":         ("exe",  "PE_EXE"),
            b"\x7FELF":          ("elf",  "ELF"),
            b"\xFF\xD8\xFF":     ("jpg",  "JPEG"),
            b"\x89PNG\r\n":      ("png",  "PNG"),
            b"%PDF":             ("pdf",  "PDF"),
            b"PK\x03\x04":       ("zip",  "ZIP"),
            b"\x1F\x8B":         ("gz",   "GZIP"),
            b"OggS":             ("ogg",  "OGG"),
            b"\xD0\xCF\x11\xE0": ("doc",  "OLE2"),
        }
        try:
            scan_size = min(os.path.getsize(image_path), 256 * 1024 * 1024)
            CHUNK = 4 * 1024 * 1024
            offset = 0
            with open(image_path, "rb") as f:
                while offset < scan_size:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    for sig, (ext, ftype) in SIGS.items():
                        pos = 0
                        while True:
                            p = chunk.find(sig, pos)
                            if p == -1:
                                break
                            abs_off = offset + p
                            name = f"carved_{ftype}_{abs_off:#010x}.{ext}"
                            r = self._make_record(
                                evidence_id=evidence_id, name=name,
                                full_path=f"/<carved>/{name}",
                                size=0, inode=abs_off,
                                mtime=0, atime=0, ctime=0, crtime=0,
                                uid=0, gid=0, mode=0o644,
                                allocated=1, file_type="FILE",
                            )
                            results.append(r)
                            self._save(r)
                            pos = p + 1
                    offset += CHUNK
        except Exception as e:
            log.error(f"Carving fallback error: {e}")
        return results

    # ── helpers ───────────────────────────────────────────────────
    @staticmethod
    def _clean_name(name: str) -> str:
        """
        Sanitize a filename for display.
        Keeps only printable ASCII (0x20–0x7E) plus safe Unicode letters/digits.
        Drops anything that renders as a box/? in monospace fonts:
          - \uFFFD, \uFFFF  — replacement/padding sentinels
          - C0/C1 control chars (0x00–0x1F, 0x7F–0x9F)
          - High-byte Latin-1 (0xA0–0xFF decoded as latin-1 = unrenderable in Consolas)
        """
        if not name:
            return "(unnamed)"
        result = []
        for c in name:
            cp = ord(c)
            # Keep standard printable ASCII only (space through tilde)
            if 0x20 <= cp <= 0x7E:
                result.append(c)
            # Keep safe Unicode ranges that render in common fonts:
            # Basic Latin, Latin Extended, CJK, Arabic etc — skip for forensic names
            # For forensic tools: ASCII-only is the standard (FTK/Autopsy both do this)
        cleaned = "".join(result).strip(". ")
        return cleaned or "(unnamed)"

    def _make_record(self, *, evidence_id, name, full_path, size,
                     inode, mtime, atime, ctime, crtime,
                     uid, gid, mode, allocated, file_type,
                     permissions="") -> Dict:
        def ts(v):
            try:
                if v and int(v) > 0:
                    return datetime.fromtimestamp(int(v), tz=timezone.utc).isoformat()
            except Exception:
                pass
            return None

        clean_name = self._clean_name(name)

        # Clean full_path segment by segment so LIKE searches work
        def clean_path(p: str) -> str:
            if not p:
                return ""
            segs = p.split("/")
            cleaned = "/".join(
                "".join(c for c in seg if 0x20 <= ord(c) <= 0x7E).strip()
                for seg in segs
            )
            return cleaned or p  # fallback to original if cleaning removes everything

        clean_fp = clean_path(full_path or "")

        return {
            "file_id":      str(uuid.uuid4()),
            "case_id":      self.case_id,
            "evidence_id":  evidence_id,
            "name":         clean_name,
            "full_path":    clean_fp,
            "size":         size or 0,
            "md5":          "",
            "sha256":       "",
            "inode":        inode or 0,
            "parent_inode": None,
            "created_ts":   ts(crtime),
            "modified_ts":  ts(mtime),
            "accessed_ts":  ts(atime),
            "changed_ts":   ts(ctime),
            "uid":          uid or 0,
            "gid":          gid or 0,
            "permissions":  permissions or oct(mode) if mode else "",
            "allocated":    allocated,
            "file_type":    file_type,
            "extracted_at": _now(),
        }

    def _save(self, r: Dict):
        try:
            self.db.execute(
                "INSERT OR REPLACE INTO extracted_files VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["file_id"], r["case_id"], r["evidence_id"], r["name"],
                 r["full_path"], r["size"], r["md5"], r["sha256"],
                 r["inode"], r["parent_inode"],
                 r["created_ts"], r["modified_ts"], r["accessed_ts"], r["changed_ts"],
                 r["uid"], r["gid"], r["permissions"], r["allocated"],
                 r["file_type"], r["extracted_at"])
            )
        except Exception as e:
            log.debug(f"DB save error: {e}")

    @staticmethod
    def _has_tool(name: str) -> bool:
        try:
            subprocess.run([name, "--version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

# ─── Engine 4: File Carving ───────────────────────────────────────────────────
class FileCarvingEngine:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db = CaseDatabase(case_id)
        self.output_dir = CASES_DIR / case_id / "carved"
        self.output_dir.mkdir(exist_ok=True)

    def carve(self, image_path: str, evidence_id: str, max_scan: int = MAX_CARVE_SIZE) -> List[Dict]:
        results = []
        try:
            file_size = os.path.getsize(image_path)
            scan_size = min(file_size, max_scan)
            with open(image_path, "rb") as f:
                data = f.read(scan_size)
            for sig_bytes, (file_type, max_size) in FILE_SIGNATURES.items():
                offset = 0
                while True:
                    pos = data.find(sig_bytes, offset)
                    if pos == -1:
                        break
                    end = min(pos + max_size * 1024, len(data))
                    carved_data = data[pos:end]
                    carved_id = str(uuid.uuid4())
                    out_path = self.output_dir / f"{carved_id}.{file_type.lower()}"
                    with open(out_path, "wb") as cf:
                        cf.write(carved_data)
                    hashes = _hash_file(out_path)
                    r = {
                        "carved_id": carved_id, "case_id": self.case_id,
                        "evidence_id": evidence_id, "file_type": file_type,
                        "start_offset": pos, "end_offset": end,
                        "size": len(carved_data), "md5": hashes["md5"],
                        "sha256": hashes["sha256"], "carved_at": _now(),
                    }
                    results.append(r)
                    self.db.execute(
                        "INSERT INTO carved_files VALUES (?,?,?,?,?,?,?,?,?,?)",
                        tuple(r.values())
                    )
                    offset = pos + 1
        except Exception as e:
            log.error(f"Carving error: {e}")
            self.db.log("ERROR", "Carving", str(e))
        return results

# ─── Engine 5: Memory Analysis ────────────────────────────────────────────────
class MemoryAnalysisEngine:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db = CaseDatabase(case_id)

    def run_plugins(self, memory_path: str, evidence_id: str, plugins: List[str] = None) -> Dict:
        if plugins is None:
            plugins = ["windows.pslist", "windows.netscan", "windows.malfind"]
        results = {}
        for plugin in plugins:
            try:
                output = self._run_volatility(memory_path, plugin)
                parsed = self._parse_output(plugin, output, evidence_id)
                results[plugin] = parsed
            except Exception as e:
                log.error(f"Plugin {plugin} failed: {e}")
                results[plugin] = []
        return results

    def _run_volatility(self, memory_path: str, plugin: str) -> str:
        cmd = ["python3", "-m", "volatility3", "-f", memory_path, "-r", "json", plugin]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                raise RuntimeError(result.stderr)
            return result.stdout
        except FileNotFoundError:
            log.warning("Volatility3 not installed. pip install volatility3")
            return json.dumps({"rows": []})
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Plugin {plugin} timed out")

    def _parse_output(self, plugin: str, raw: str, evidence_id: str) -> List[Dict]:
        try:
            data = json.loads(raw)
            rows = data.get("rows", [])
        except json.JSONDecodeError:
            return []
        artifacts = []
        for row in rows:
            artifact_id = str(uuid.uuid4())
            pid = row.get("PID") or row.get("pid") or 0
            name = row.get("ImageFileName") or row.get("name", "")
            a = {
                "artifact_id": artifact_id, "case_id": self.case_id,
                "evidence_id": evidence_id, "plugin": plugin,
                "pid": pid, "process_name": name,
                "ppid": row.get("PPID") or row.get("ppid") or 0,
                "offset": str(row.get("Offset", "")),
                "artifact_type": plugin.split(".")[-1].upper(),
                "raw_data": json.dumps(row),
                "risk_score": self._heuristic_score(plugin, row),
                "flags": self._flags(plugin, row),
                "extracted_at": _now(),
            }
            artifacts.append(a)
            self.db.execute(
                "INSERT OR REPLACE INTO memory_artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(a.values())
            )
        return artifacts

    def _heuristic_score(self, plugin: str, row: Dict) -> float:
        if plugin == "windows.malfind":
            return 80.0
        name = (row.get("ImageFileName") or "").lower()
        if any(s in name for s in ["mimikatz", "pwdump", "meterpreter", "procdump"]):
            return 95.0
        return 0.0

    def _flags(self, plugin: str, row: Dict) -> str:
        flags = []
        if plugin == "windows.malfind":
            flags.append("CODE_INJECTION")
            if "MZ" in str(row.get("Hexdump", "")):
                flags.append("PE_IN_RWX_REGION")
        return ",".join(flags)

# ─── Engine 6: YARA Engine ────────────────────────────────────────────────────
class YARAEngine:
    RULES_DIR = Path("./yara_rules")

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db = CaseDatabase(case_id)
        self.RULES_DIR.mkdir(exist_ok=True)

    def scan_file(self, filepath: str, evidence_id: str) -> List[Dict]:
        if not YARA_AVAILABLE:
            return []
        matches = []
        try:
            rules = self._compile_rules()
            for match in rules.match(filepath):
                confidence = 90.0 if match.meta.get("severity") == "CRITICAL" else 75.0
                r = {
                    "ioc_id": str(uuid.uuid4()), "case_id": self.case_id,
                    "ioc_type": "YARA", "indicator": match.rule,
                    "rule_name": match.rule, "confidence": confidence,
                    "tags": ",".join(match.tags),
                    "source_artifact": filepath, "matched_at": _now(),
                }
                matches.append(r)
                self.db.execute(
                    "INSERT INTO ioc_matches VALUES (?,?,?,?,?,?,?,?,?)",
                    tuple(r.values())
                )
        except Exception as e:
            log.error(f"YARA scan error: {e}")
        return matches

    def _compile_rules(self):
        rule_files = list(self.RULES_DIR.glob("*.yar"))
        if not rule_files:
            return yara.compile(source='rule dummy { condition: false }')
        return yara.compile(filepaths={f.stem: str(f) for f in rule_files})

    def import_rules(self, content: str, name: str) -> bool:
        try:
            if YARA_AVAILABLE:
                yara.compile(source=content)
            (self.RULES_DIR / f"{name}.yar").write_text(content)
            return True
        except Exception as e:
            log.error(f"YARA import failed: {e}")
            return False

# ─── Engine 7: PCAP Analysis ──────────────────────────────────────────────────
import struct as _struct
import math   as _math

# ── MITRE ATT&CK technique database ──────────────────────────────────────────
MITRE_TECHNIQUES = {
    "T1046":     {"name":"Network Service Discovery",          "tactic":"Discovery"},
    "T1110":     {"name":"Brute Force",                        "tactic":"Credential Access"},
    "T1071":     {"name":"Application Layer Protocol",         "tactic":"Command and Control"},
    "T1071.001": {"name":"Web Protocols (HTTP/S C2)",          "tactic":"Command and Control"},
    "T1071.004": {"name":"DNS C2",                             "tactic":"Command and Control"},
    "T1048":     {"name":"Exfiltration Over Alt Protocol",     "tactic":"Exfiltration"},
    "T1048.003": {"name":"DNS Tunneling",                      "tactic":"Exfiltration"},
    "T1190":     {"name":"Exploit Public-Facing Application",  "tactic":"Initial Access"},
    "T1059":     {"name":"Command and Scripting Interpreter",  "tactic":"Execution"},
    "T1021":     {"name":"Remote Services (Lateral Movement)", "tactic":"Lateral Movement"},
    "T1557.002": {"name":"ARP Cache Poisoning",                "tactic":"Credential Access"},
    "T1498":     {"name":"Network Denial of Service",          "tactic":"Impact"},
    "T1498.002": {"name":"Reflection Amplification",           "tactic":"Impact"},
    "T1571":     {"name":"Non-Standard Port",                  "tactic":"Command and Control"},
    "T1083":     {"name":"File and Directory Discovery",       "tactic":"Discovery"},
}

# ── IOC database (mirrors rules/ioc_lists.yaml) ───────────────────────────────
IOC_SUSPICIOUS_PORTS = {
    4444:  {"desc":"Metasploit default reverse shell", "severity":"HIGH"},
    5555:  {"desc":"Android ADB (potential compromise)","severity":"MEDIUM"},
    6666:  {"desc":"IRC (potential C2)",                "severity":"MEDIUM"},
    6667:  {"desc":"IRC (potential C2)",                "severity":"MEDIUM"},
    31337: {"desc":"Back Orifice trojan",               "severity":"CRITICAL"},
    12345: {"desc":"NetBus trojan",                     "severity":"CRITICAL"},
    1337:  {"desc":"Common hacker/backdoor port",       "severity":"MEDIUM"},
    9001:  {"desc":"Tor default OR port",               "severity":"LOW"},
    9050:  {"desc":"Tor SOCKS proxy",                   "severity":"LOW"},
    4899:  {"desc":"Radmin remote admin",               "severity":"MEDIUM"},
    1080:  {"desc":"SOCKS proxy / tunnelling",          "severity":"LOW"},
    3128:  {"desc":"Squid proxy",                       "severity":"LOW"},
    23:    {"desc":"Telnet – unencrypted",               "severity":"MEDIUM"},
}
IOC_SUSPICIOUS_UA_PATTERNS = [
    ("sqlmap",          "attack_tool",  "CRITICAL"),
    ("nikto",           "scanner",      "HIGH"),
    ("masscan",         "scanner",      "HIGH"),
    ("nmap",            "scanner",      "MEDIUM"),
    ("gobuster",        "scanner",      "MEDIUM"),
    ("powershell",      "suspicious",   "HIGH"),
    ("certutil",        "suspicious",   "HIGH"),
    ("python-requests", "automation",   "LOW"),
    ("python-urllib",   "automation",   "LOW"),
    ("curl/",           "automation",   "LOW"),
    ("wget/",           "automation",   "LOW"),
]
IOC_C2_UA_PATTERNS = [
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)",
]
IOC_C2_URIS = ["/submit.php","/pixel.gif","/__utm.gif","/updates.rss","/fwlink",
               "/admin/get.php","/news.php","/login/process.php"]
IOC_SUSPICIOUS_TLDS = {".xyz",".top",".win",".loan",".click",".gdn",".racing"}

# ── Pure-Python PCAP parser (Layer 1) ─────────────────────────────────────────
class PCAPParser:
    """Reads raw libpcap bytes, reconstructs sessions + rich packet objects."""
    PRIV_NETS = [
        (0xC0A80000,0xFFFF0000),(0xAC100000,0xFFF00000),
        (0x0A000000,0xFF000000),(0x7F000000,0xFF000000),
    ]

    def parse(self, pcap_path: str) -> Dict:
        sessions: Dict[str,Dict]  = {}
        packets:  List[Dict]      = []
        stats = {
            "packets":0,"bytes":0,"errors":0,
            "protocols":{},"top_talkers":{},"unique_ips":set(),
            "unique_ports":set(),"dns_queries":[],"http_requests":[],
            "first_ts":None,"last_ts":None,"arp_count":0,
            "pkt_per_minute":{},
        }
        with open(pcap_path,"rb") as f:
            gh = f.read(24)
            if len(gh) < 24: raise ValueError("File too small to be a PCAP")
            magic = _struct.unpack_from("<I",gh,0)[0]
            if   magic == 0xA1B2C3D4: endian = "<"
            elif magic == 0xD4C3B2A1: endian = ">"
            elif magic == 0xA1B23C4D: endian = "<"
            else: raise ValueError(f"Not a valid PCAP file (magic={magic:#010x})")
            link_type = _struct.unpack_from(f"{endian}I",gh,20)[0]
            while True:
                ph = f.read(16)
                if len(ph) < 16: break
                ts_sec,ts_usec,cap_len,orig_len = _struct.unpack_from(f"{endian}IIII",ph)
                raw = f.read(cap_len)
                if len(raw) < cap_len: break
                stats["packets"] += 1
                stats["bytes"]   += orig_len
                ts = ts_sec + ts_usec*1e-6
                if stats["first_ts"] is None: stats["first_ts"] = ts
                stats["last_ts"] = ts
                minute = int(ts/60)
                stats["pkt_per_minute"][minute] = stats["pkt_per_minute"].get(minute,0)+1
                try:
                    pkt = self._decode(raw,link_type,endian,ts,stats)
                    if pkt:
                        packets.append(pkt)
                        self._update_session(pkt,sessions)
                except Exception: stats["errors"]+=1
        dur = (stats["last_ts"] or 0)-(stats["first_ts"] or 0)
        return {
            "sessions":sessions,"packets":packets,
            "packet_count":stats["packets"],"byte_count":stats["bytes"],
            "duration":max(dur,0.001),"protocols":stats["protocols"],
            "top_talkers":stats["top_talkers"],"unique_ips":stats["unique_ips"],
            "unique_ports":stats["unique_ports"],"dns_queries":stats["dns_queries"],
            "http_requests":stats["http_requests"],"errors":stats["errors"],
            "first_ts":stats["first_ts"],"last_ts":stats["last_ts"],
            "arp_count":stats["arp_count"],"pkt_per_minute":stats["pkt_per_minute"],
        }

    def _decode(self,raw,link_type,endian,ts,stats) -> Optional[Dict]:
        if link_type==1:
            if len(raw)<14: return None
            eth_type = _struct.unpack_from(">H",raw,12)[0]
            ip_off = 14
            if eth_type==0x8100:
                eth_type = _struct.unpack_from(">H",raw,16)[0]; ip_off=18
        elif link_type in(101,228): eth_type,ip_off=0x0800,0
        else: return None
        if eth_type==0x0806:
            stats["arp_count"]+=1; return None
        if eth_type==0x0800:
            return self._decode_ipv4(raw[ip_off:],ts,stats)
        elif eth_type==0x86DD:
            if len(raw)<ip_off+40: return None
            src=":".join(f"{raw[ip_off+8+i]:02x}{raw[ip_off+9+i]:02x}" for i in range(0,16,2))
            dst=":".join(f"{raw[ip_off+24+i]:02x}{raw[ip_off+25+i]:02x}" for i in range(0,16,2))
            pn=raw[ip_off+6]; proto={6:"TCP",17:"UDP",58:"ICMPv6"}.get(pn,"IPv6")
            stats["protocols"][proto]=stats["protocols"].get(proto,0)+1
            stats["top_talkers"][src]=stats["top_talkers"].get(src,0)+1
            return {"src_ip":src,"dst_ip":dst,"proto":proto,"proto_num":pn,
                    "src_port":0,"dst_port":0,"size":0,"ts":ts,"payload":b"","flags":"","syn_count":0}
        return None

    def _decode_ipv4(self,ip,ts,stats)->Optional[Dict]:
        if len(ip)<20: return None
        ihl=(ip[0]&0x0F)*4; pn=ip[9]
        src=".".join(str(b) for b in ip[12:16])
        dst=".".join(str(b) for b in ip[16:20])
        size=_struct.unpack_from(">H",ip,2)[0]
        proto={1:"ICMP",6:"TCP",17:"UDP"}.get(pn,f"IP/{pn}")
        stats["protocols"][proto]=stats["protocols"].get(proto,0)+1
        stats["top_talkers"][src]=stats["top_talkers"].get(src,0)+1
        stats["unique_ips"].add(src); stats["unique_ips"].add(dst)
        transport=ip[ihl:]; sp=dp=0; payload=b""; flags=""; syn_count=0
        if pn==6 and len(transport)>=20:
            sp=_struct.unpack_from(">H",transport,0)[0]
            dp=_struct.unpack_from(">H",transport,2)[0]
            stats["unique_ports"].add(dp)
            doff=(transport[12]>>4)*4; tf=transport[13]
            flags="".join(c for c,b in[("S",0x02),("A",0x10),("F",0x01),("R",0x04),("P",0x08)] if tf&b)
            payload=transport[doff:doff+1024]
            if "S" in flags and "A" not in flags: syn_count=1
            if payload:
                text=payload.decode("utf-8",errors="replace")
                if text[:4] in("GET ","POST","PUT ","HEAD","DELE","HTTP"):
                    self._parse_http(text,src,dst,dp,ts,stats)
        elif pn==17 and len(transport)>=8:
            sp=_struct.unpack_from(">H",transport,0)[0]
            dp=_struct.unpack_from(">H",transport,2)[0]
            stats["unique_ports"].add(dp)
            payload=transport[8:520]
            if dp==53 or sp==53:
                proto="DNS"
                stats["protocols"]["DNS"]=stats["protocols"].get("DNS",0)+1
                q=self._parse_dns(payload)
                if q: stats["dns_queries"].append({"domain":q,"src":src,"ts":ts})
        return {"src_ip":src,"dst_ip":dst,"proto":proto,"proto_num":pn,
                "src_port":sp,"dst_port":dp,"size":size,
                "ts":ts,"payload":payload,"flags":flags,"syn_count":syn_count}

    def _parse_http(self,text,src,dst,dp,ts,stats):
        lines=text.split("\r\n")
        if not lines: return
        method=host=uri=ua=""
        parts0=lines[0].split()
        if parts0 and parts0[0] in("GET","POST","PUT","DELETE","HEAD","PATCH"):
            method=parts0[0]
            uri=parts0[1] if len(parts0)>1 else "/"
        for line in lines[1:]:
            ll=line.lower()
            if ll.startswith("host:"): host=line.split(":",1)[1].strip()
            elif ll.startswith("user-agent:"): ua=line.split(":",1)[1].strip()
        if method:
            stats["http_requests"].append({
                "src_ip":src,"dst_ip":dst,"port":dp,"ts":ts,
                "method":method,"host":host,"uri":uri,"user_agent":ua,
                "raw":text[:800],
            })

    def _parse_dns(self,data)->Optional[str]:
        try:
            if len(data)<12: return None
            if _struct.unpack_from(">H",data,4)[0]==0: return None
            off,labels=12,[]
            while off<len(data):
                l=data[off]
                if l==0: break
                if l&0xC0==0xC0: break
                off+=1
                if off+l>len(data): break
                labels.append(data[off:off+l].decode("ascii","replace"))
                off+=l
            return ".".join(labels) if labels else None
        except Exception: return None

    def _update_session(self,pkt,sessions):
        k=(f"{min(pkt['src_ip'],pkt['dst_ip'])}:{min(pkt['src_port'],pkt['dst_port'])}"
           f"-{max(pkt['src_ip'],pkt['dst_ip'])}:{max(pkt['src_port'],pkt['dst_port'])}"
           f"-{pkt['proto_num']}")
        if k not in sessions:
            sessions[k]={"src_ip":pkt["src_ip"],"dst_ip":pkt["dst_ip"],
                         "src_port":pkt["src_port"],"dst_port":pkt["dst_port"],
                         "protocol":pkt["proto"],"pkt_count":0,"byte_count":0,
                         "first_seen":pkt["ts"],"last_seen":pkt["ts"],
                         "flags":"","payload":b"","syn_count":0}
        s=sessions[k]
        s["pkt_count"]+=1; s["byte_count"]+=pkt["size"]; s["last_seen"]=pkt["ts"]
        if pkt["flags"]: s["flags"]=pkt["flags"]
        s["syn_count"]=s.get("syn_count",0)+pkt.get("syn_count",0)
        if pkt["payload"] and not s["payload"]: s["payload"]=pkt["payload"]

    def is_private(self,ip:str)->bool:
        try:
            p=ip.split(".")
            n=(int(p[0])<<24)|(int(p[1])<<16)|(int(p[2])<<8)|int(p[3])
            return any((n&m)==(net&m) for net,m in self.PRIV_NETS)
        except Exception: return True


# ── TrafficAnalyzer (Layer 2) ─────────────────────────────────────────────────
class TrafficAnalyzer:
    """Protocol stats, top talkers, bandwidth, suspicious protocol detection."""
    SUSPICIOUS_PROTOCOLS = {"IRC","TELNET","FTP","TFTP"}

    def analyze(self,parsed:Dict)->Dict:
        sessions=list(parsed["sessions"].values())
        total_pkts=parsed["packet_count"]; total_bytes=parsed["byte_count"]
        dur=parsed["duration"]; findings=[]
        # bytes per IP
        talker_bytes:Dict[str,int]={}
        talker_pkts:Dict[str,int]=parsed["top_talkers"]
        for s in sessions:
            for ip in(s["src_ip"],s["dst_ip"]):
                talker_bytes[ip]=talker_bytes.get(ip,0)+s["byte_count"]
        top_by_bytes=sorted(talker_bytes.items(),key=lambda x:x[1],reverse=True)[:10]
        # High-volume single host
        for ip,cnt in sorted(talker_pkts.items(),key=lambda x:x[1],reverse=True)[:5]:
            ratio=cnt/total_pkts if total_pkts>0 else 0
            if ratio>0.5:
                findings.append({"title":f"High Traffic Volume: {ip}",
                    "category":"Traffic Anomaly","severity":"MEDIUM",
                    "description":(f"{ip} generated {cnt} packets ({ratio*100:.1f}% of total). "
                                   f"Possible data exfiltration, DDoS participation or scanning."),
                    "evidence":[f"Packets: {cnt}",f"Traffic ratio: {ratio*100:.1f}%"],
                    "recommendations":["Investigate source for compromise","Review firewall logs"],
                    "mitre_technique":"T1048","mitre_tactic":"Exfiltration","ts":parsed["first_ts"]})
        # Suspicious protocols
        for proto in self.SUSPICIOUS_PROTOCOLS:
            cnt=parsed["protocols"].get(proto,0)
            if cnt>0:
                findings.append({"title":f"Suspicious Protocol: {proto}",
                    "category":"Protocol Anomaly","severity":"MEDIUM",
                    "description":(f"{cnt} packets using {proto}. Often associated with "
                                   f"legacy systems, malware C2, or unencrypted data transfer."),
                    "evidence":[f"Packet count: {cnt}"],
                    "recommendations":[f"Verify {proto} is authorised","Use encrypted alternatives"],
                    "mitre_technique":"T1071","mitre_tactic":"Command and Control","ts":parsed["first_ts"]})
        # Traffic spike
        ppm=parsed.get("pkt_per_minute",{})
        if len(ppm)>=2:
            avg_ppm=sum(ppm.values())/len(ppm); max_ppm=max(ppm.values())
            if max_ppm>avg_ppm*10 and max_ppm>1000:
                findings.append({"title":"Traffic Spike Detected",
                    "category":"Traffic Anomaly","severity":"MEDIUM",
                    "description":(f"Peak of {max_ppm} pkt/min vs average {avg_ppm:.0f} pkt/min "
                                   f"({max_ppm/avg_ppm:.1f}x). May indicate burst attack or scanning."),
                    "evidence":[f"Peak: {max_ppm} pkt/min",f"Avg: {avg_ppm:.0f} pkt/min"],
                    "recommendations":["Review traffic during spike","Check for DoS indicators"],
                    "ts":parsed["first_ts"]})
        # DNS amplification
        dns_cnt=parsed["protocols"].get("DNS",0)
        if total_pkts>0 and dns_cnt/total_pkts>0.8:
            findings.append({"title":"Potential DNS Amplification Attack",
                "category":"DDoS – Amplification","severity":"CRITICAL",
                "description":(f"DNS traffic is {dns_cnt/total_pkts*100:.1f}% of all traffic. "
                               f"Consistent with DNS amplification/reflection DDoS."),
                "evidence":[f"DNS packets: {dns_cnt}",f"Total: {total_pkts}"],
                "recommendations":["Block external DNS responses","Enable response rate limiting"],
                "mitre_technique":"T1498.002","mitre_tactic":"Impact","ts":parsed["first_ts"]})
        return {"name":"TrafficAnalyzer","findings":findings,
                "top_talkers_bytes":[{"ip":k,"bytes":v} for k,v in top_by_bytes],
                "packets_per_sec":round(total_pkts/dur,1),"bytes_per_sec":round(total_bytes/dur,1)}


# ── AnomalyDetector (Layer 3) ─────────────────────────────────────────────────
class AnomalyDetector:
    """Beaconing, exfiltration, lateral movement, ARP anomaly, timing anomalies."""
    def __init__(self,beacon_tolerance=0.1,min_beacon_count=10,exfil_threshold=10485760):
        self.beacon_tolerance=beacon_tolerance
        self.min_beacon_count=min_beacon_count
        self.exfil_threshold=exfil_threshold

    def analyze(self,parsed:Dict)->Dict:
        sessions=list(parsed["sessions"].values()); findings=[]
        findings.extend(self._detect_beaconing(parsed["packets"]))
        findings.extend(self._detect_exfiltration(sessions))
        findings.extend(self._detect_lateral_movement(sessions))
        findings.extend(self._detect_arp(parsed["arp_count"]))
        findings.extend(self._detect_dns_anomalies(parsed["dns_queries"]))
        return {"name":"AnomalyDetector","findings":findings,"finding_count":len(findings)}

    def _detect_beaconing(self,packets:List[Dict])->List[Dict]:
        findings=[]
        conn_times:Dict[str,List[float]]={}
        for p in packets:
            if p.get("src_ip") and p.get("dst_ip") and p.get("dst_port"):
                k=f"{p['src_ip']}->{p['dst_ip']}:{p['dst_port']}"
                if k not in conn_times: conn_times[k]=[]
                conn_times[k].append(p["ts"])
        for key,times in conn_times.items():
            if len(times)<self.min_beacon_count: continue
            times.sort()
            intervals=[times[i+1]-times[i] for i in range(len(times)-1)]
            avg_iv=sum(intervals)/len(intervals)
            if avg_iv<=0: continue
            var=sum((x-avg_iv)**2 for x in intervals)/len(intervals)
            cv=(var**0.5)/avg_iv
            if cv<self.beacon_tolerance:
                parts=key.split("->"); src=parts[0]; dp=parts[1]
                dst_ip=dp.rsplit(":",1)[0]; dst_port=dp.rsplit(":",1)[1]
                findings.append({"title":f"C2 Beaconing: {dst_ip}",
                    "category":"C2 Communication","severity":"CRITICAL",
                    "description":(f"Regular {avg_iv:.1f}s interval connections from {src} to "
                                   f"{dst_ip}:{dst_port}. CV={cv:.4f} — consistent with C2 beacon."),
                    "evidence":[f"Connections: {len(times)}",f"Avg interval: {avg_iv:.2f}s",
                                f"CV: {cv:.4f}",f"Duration: {times[-1]-times[0]:.1f}s"],
                    "recommendations":["Isolate affected host","Block destination IP",
                                       "Run full forensic analysis","Check for persistence"],
                    "mitre_technique":"T1071","mitre_tactic":"Command and Control","ts":times[0]})
        return findings

    def _detect_exfiltration(self,sessions:List[Dict])->List[Dict]:
        findings=[]
        outbound:Dict[str,int]={}
        for s in sessions:
            dst=s["dst_ip"]
            if s["byte_count"]>0:
                outbound[dst]=outbound.get(dst,0)+s["byte_count"]
        for dst,byt in outbound.items():
            if byt>self.exfil_threshold:
                findings.append({"title":f"Potential Data Exfiltration → {dst}",
                    "category":"Data Exfiltration","severity":"CRITICAL",
                    "description":(f"Large data transfer to {dst}: {byt/1048576:.2f}MB "
                                   f"(threshold {self.exfil_threshold/1048576:.0f}MB). "
                                   f"May indicate data exfiltration."),
                    "evidence":[f"Bytes: {byt:,}",f"MB: {byt/1048576:.2f}"],
                    "recommendations":["Investigate destination IP","Review DLP logs",
                                       "Check for authorised transfers","Block if unauthorised"],
                    "mitre_technique":"T1048","mitre_tactic":"Exfiltration",
                    "ts":next((s["first_seen"] for s in sessions if s["dst_ip"]==dst),None)})
        return findings

    def _detect_lateral_movement(self,sessions:List[Dict])->List[Dict]:
        findings=[]
        internal_prefixes=("10.","192.168.","172.16.","172.17.","172.18.","172.19.",
                          "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
                          "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.")
        src_dsts:Dict[str,set]={}
        for s in sessions:
            si=s["src_ip"]; di=s["dst_ip"]
            src_int=any(si.startswith(p) for p in internal_prefixes)
            dst_int=any(di.startswith(p) for p in internal_prefixes)
            if src_int and dst_int and si!=di:
                if si not in src_dsts: src_dsts[si]=set()
                src_dsts[si].add(di)
        for src,dsts in src_dsts.items():
            if len(dsts)>10:
                findings.append({"title":f"Lateral Movement from {src}",
                    "category":"Lateral Movement","severity":"HIGH",
                    "description":(f"{src} connected to {len(dsts)} unique internal hosts. "
                                   f"Consistent with network reconnaissance or lateral movement."),
                    "evidence":[f"Unique destinations: {len(dsts)}",
                                f"Sample: {', '.join(list(dsts)[:5])}"],
                    "recommendations":["Investigate source for compromise",
                                       "Review auth logs","Implement network segmentation"],
                    "mitre_technique":"T1021","mitre_tactic":"Lateral Movement",
                    "ts":next((s["first_seen"] for s in sessions if s["src_ip"]==src),None)})
        return findings

    def _detect_arp(self,arp_count:int)->List[Dict]:
        findings=[]
        if arp_count>1000:
            findings.append({"title":"Excessive ARP Traffic",
                "category":"ARP Anomaly","severity":"HIGH",
                "description":(f"{arp_count} ARP packets detected. High ARP traffic "
                               f"indicates ARP spoofing, flooding, or network scanning."),
                "evidence":[f"ARP count: {arp_count}"],
                "recommendations":["Enable Dynamic ARP Inspection","Implement static ARP entries",
                                   "Deploy ARP spoofing detection"],
                "mitre_technique":"T1557.002","mitre_tactic":"Credential Access"})
        return findings

    def _detect_dns_anomalies(self,dns:List[Dict])->List[Dict]:
        findings=[]
        # Excessive queries to one domain
        domain_counts:Dict[str,int]={}
        for q in dns: domain_counts[q["domain"]]=domain_counts.get(q["domain"],0)+1
        for domain,cnt in sorted(domain_counts.items(),key=lambda x:x[1],reverse=True)[:5]:
            if cnt>100:
                findings.append({"title":f"Excessive DNS Queries: {domain}",
                    "category":"DNS Anomaly","severity":"MEDIUM",
                    "description":(f"{cnt} DNS queries for {domain}. "
                                   f"May indicate DNS tunnelling, C2 communication or misconfiguration."),
                    "evidence":[f"Query count: {cnt}",f"Domain: {domain}"],
                    "recommendations":["Investigate querying host","Check domain reputation"],
                    "mitre_technique":"T1071.004","mitre_tactic":"Command and Control",
                    "ts":next((q["ts"] for q in dns if q["domain"]==domain),None)})
        # Suspicious TLDs
        for q in dns:
            tld="."+q["domain"].rsplit(".",1)[-1] if "." in q["domain"] else ""
            if tld in IOC_SUSPICIOUS_TLDS:
                findings.append({"title":f"Suspicious TLD Query: {q['domain']}",
                    "category":"DNS Anomaly","severity":"MEDIUM",
                    "description":(f"DNS query for domain with suspicious TLD '{tld}'. "
                                   f"Often used in malware campaigns."),
                    "evidence":[f"Domain: {q['domain']}",f"TLD: {tld}"],
                    "recommendations":["Block suspicious TLDs at DNS level","Investigate querying host"],
                    "mitre_technique":"T1071.004","mitre_tactic":"Command and Control","ts":q["ts"]})
            break  # one example per run is enough
        return findings


# ── AttackDetector (Layer 4) ──────────────────────────────────────────────────
class AttackDetector:
    """Port scans, brute force, SQLi, dir traversal, cmd injection, DoS, payload sigs."""
    AUTH_PORTS = {22:"SSH",21:"FTP",23:"Telnet",3389:"RDP",5900:"VNC",
                  3306:"MySQL",1433:"MSSQL",5432:"PostgreSQL",389:"LDAP",636:"LDAPS"}
    SQL_PATTERNS  = [b"' OR '1'='1",b"' OR 1=1",b"'; DROP",b"UNION SELECT",
                     b"1=1--",b"ADMIN'--",b"'; EXEC",b"XP_CMDSHELL",b"WAITFOR DELAY",b"BENCHMARK("]
    TRAV_PATTERNS = ["../","..\\","%2e%2e%2f","%2e%2e/","..%2f","%2e%2e%5c",
                     "..%5c","/etc/passwd","/etc/shadow","c:\\windows","boot.ini"]
    CMD_PATTERNS  = ["; cat ","; ls ","; id","; whoami","; nc ","; wget ","; curl ",
                     "| cat ","| ls ","| id ","| whoami ","| nc ","| wget ","| curl ",
                     "/bin/sh","/bin/bash","cmd.exe","powershell"]
    PAYLOAD_SIGS  = [
        (b"() {",        "Shellshock (CVE-2014-6271)",     "CRITICAL","T1190"),
        (b"${jndi:",     "Log4Shell (CVE-2021-44228)",      "CRITICAL","T1190"),
        (b"sekurlsa",    "Mimikatz credential dumping",     "CRITICAL","T1003"),
        (b"-EncodedCommand","Encoded PowerShell execution", "HIGH",    "T1059"),
        (b"/bin/sh",     "Reverse shell payload",           "CRITICAL","T1059"),
        (b"net user ",   "Net user command (recon/persist)","HIGH",    "T1136"),
    ]

    def analyze(self,parsed:Dict)->Dict:
        sessions=list(parsed["sessions"].values())
        http=parsed["http_requests"]; packets=parsed["packets"]
        dur=parsed["duration"]; findings=[]; matches=[]
        # Build port→sessions index
        port_sessions:Dict[int,List]={}
        for s in sessions:
            for p in(s["src_port"],s["dst_port"]):
                if p: port_sessions.setdefault(p,[]).append(s)
        # Port scan (per src within time window)
        ip_port_access:Dict[str,Dict[str,set]]={}
        ip_first:Dict[str,float]={}
        for pkt in packets:
            si=pkt.get("src_ip",""); dp=pkt.get("dst_port",0)
            if not si or not dp: continue
            k=f"{si}->{pkt.get('dst_ip','')}"
            if k not in ip_first: ip_first[k]=pkt["ts"]
            if pkt["ts"]-ip_first[k]<=60:
                ip_port_access.setdefault(si,{}).setdefault(pkt.get("dst_ip",""),set()).add(dp)
        for src,targets in ip_port_access.items():
            for dst,ports in targets.items():
                if len(ports)>=20:
                    scan_type=self._classify_scan(ports)
                    findings.append({"title":f"Port Scan: {scan_type} from {src}",
                        "category":"Port Scan","severity":"HIGH",
                        "description":(f"{src} scanned {len(ports)} ports on {dst} within 60s. "
                                       f"Network reconnaissance activity detected."),
                        "evidence":[f"Scan type: {scan_type}",f"Ports: {len(ports)}",
                                    f"Sample: {sorted(ports)[:10]}"],
                        "recommendations":["Block source IP","Review IDS logs",
                                           "Verify if authorised pen-test"],
                        "mitre_technique":"T1046","mitre_tactic":"Discovery",
                        "ts":ip_first.get(f"{src}->{dst}")})
                    matches.append({"src":src,"dst":dst})
        # Brute force
        attempts:Dict[str,Dict[int,int]]={}
        for s in sessions:
            if s["dst_port"] in self.AUTH_PORTS:
                attempts.setdefault(s["src_ip"],{})[s["dst_port"]] = \
                    attempts.get(s["src_ip"],{}).get(s["dst_port"],0)+s["pkt_count"]
        for src,port_map in attempts.items():
            for port,cnt in port_map.items():
                if cnt>=5:
                    svc=self.AUTH_PORTS[port]
                    findings.append({"title":f"Brute Force: {svc} from {src}",
                        "category":"Brute Force","severity":"HIGH",
                        "description":(f"{cnt} connection attempts from {src} to {svc} (port {port}). "
                                       f"Consistent with password brute forcing."),
                        "evidence":[f"Service: {svc}",f"Port: {port}",f"Attempts: {cnt}"],
                        "recommendations":[f"Block {src}","Implement account lockout",
                                           "Enable MFA","Review auth logs for success"],
                        "mitre_technique":"T1110","mitre_tactic":"Credential Access",
                        "ts":next((s["first_seen"] for s in sessions if s["src_ip"]==src),None)})
                    matches.append({"src":src,"port":port})
        # HTTP attack patterns (deduped per src/dst pair)
        seen_sqli:set=set(); seen_trav:set=set(); seen_cmd:set=set()
        for req in http:
            uri_low=req.get("uri","").lower(); raw_up=req.get("raw","").upper().encode()
            pair=(req.get("src_ip",""),req.get("dst_ip",""))
            if pair not in seen_sqli:
                for pat in self.SQL_PATTERNS:
                    if pat in raw_up:
                        findings.append({"title":"SQL Injection Attempt",
                            "category":"SQL Injection","severity":"CRITICAL",
                            "description":(f"SQLi pattern in HTTP from {req['src_ip']} → "
                                           f"{req['dst_ip']}:{req['port']} URI: {req.get('uri','')[:80]}"),
                            "evidence":[f"Pattern: {pat.decode()}",f"URI: {req.get('uri','')}",
                                        f"Method: {req.get('method','')}"],
                            "recommendations":["Block source IP","Review web app logs",
                                               "Implement WAF","Use parameterised queries"],
                            "mitre_technique":"T1190","mitre_tactic":"Initial Access",
                            "ts":req.get("ts")}); seen_sqli.add(pair); break
            if pair not in seen_trav:
                for pat in self.TRAV_PATTERNS:
                    if pat in uri_low:
                        findings.append({"title":"Directory Traversal Attempt",
                            "category":"Directory Traversal","severity":"HIGH",
                            "description":(f"Path traversal in HTTP from {req['src_ip']}. "
                                           f"Pattern: '{pat}' in URI: {req.get('uri','')[:80]}"),
                            "evidence":[f"Pattern: {pat}",f"URI: {req.get('uri','')}"],
                            "recommendations":["Block source IP","Validate file paths","Use WAF"],
                            "mitre_technique":"T1083","mitre_tactic":"Discovery",
                            "ts":req.get("ts")}); seen_trav.add(pair); break
            if pair not in seen_cmd:
                for pat in self.CMD_PATTERNS:
                    if pat in uri_low:
                        findings.append({"title":"Command Injection Attempt",
                            "category":"Command Injection","severity":"CRITICAL",
                            "description":(f"Command injection in HTTP from {req['src_ip']}. "
                                           f"Pattern: '{pat}'"),
                            "evidence":[f"Pattern: {pat}",f"URI: {req.get('uri','')}"],
                            "recommendations":["Block source IP immediately",
                                               "Sanitise all input","Review system logs"],
                            "mitre_technique":"T1059","mitre_tactic":"Execution",
                            "ts":req.get("ts")}); seen_cmd.add(pair); break
        # Payload signature matching
        for s in sessions:
            payload=s.get("payload",b"")
            if not isinstance(payload,bytes): continue
            for pat,name,sev,tech in self.PAYLOAD_SIGS:
                if pat in payload:
                    findings.append({"title":name,
                        "category":"Payload Signature","severity":sev,
                        "description":f"{name} detected in session {s['src_ip']}→{s['dst_ip']}",
                        "evidence":[f"Pattern: {pat.decode(errors='replace')}",
                                    f"Session: {s['src_ip']}:{s['src_port']}→{s['dst_ip']}:{s['dst_port']}"],
                        "recommendations":["Isolate affected hosts","Perform full forensic analysis"],
                        "mitre_technique":tech,"mitre_tactic":"Initial Access",
                        "ts":s["first_seen"]})
                    matches.append({"src":s["src_ip"],"dst":s["dst_ip"],"sig":name})
        # DoS detection
        pps=parsed["packet_count"]/parsed["duration"]
        if pps>10000:
            findings.append({"title":"Potential DoS Attack",
                "category":"Denial of Service","severity":"CRITICAL",
                "description":(f"Extremely high packet rate: {pps:.0f} pkt/s. Consistent with DoS."),
                "evidence":[f"PPS: {pps:.0f}",f"Packets: {parsed['packet_count']}",
                            f"Duration: {parsed['duration']:.1f}s"],
                "recommendations":["Enable rate limiting","Contact ISP for DDoS mitigation",
                                   "Block source IPs","Enable SYN cookies"],
                "mitre_technique":"T1498","mitre_tactic":"Impact","ts":parsed["first_ts"]})
        # User agent analysis
        ua_findings=self._check_user_agents(http)
        findings.extend(ua_findings)
        return {"name":"AttackDetector","findings":findings,"matches":matches,"finding_count":len(findings)}

    def _classify_scan(self,ports:set)->str:
        sp=sorted(ports)
        if len(sp)>10:
            seq=sum(1 for i in range(len(sp)-1) if sp[i+1]-sp[i]==1)
            if seq>len(sp)*0.8: return "Sequential Scan"
        common={21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080}
        if ports.issubset(common): return "Common Ports Scan"
        top={22,80,443,21,25,3389,110,445,139,143}
        if len(ports.intersection(top))>len(ports)*0.5: return "Top Ports Scan"
        return "Full Port Scan"

    def _check_user_agents(self,http:List[Dict])->List[Dict]:
        findings=[]; seen_uas:set=set()
        for req in http:
            ua=req.get("user_agent","")
            if not ua or ua in seen_uas: continue
            seen_uas.add(ua)
            ua_low=ua.lower()
            # Check C2 UA patterns
            for c2_ua in IOC_C2_UA_PATTERNS:
                if c2_ua.lower() in ua_low:
                    findings.append({"title":"Known C2 Framework User-Agent",
                        "category":"C2 Communication","severity":"CRITICAL",
                        "description":f"HTTP request with known C2 user-agent: {ua[:80]}",
                        "evidence":[f"User-Agent: {ua}"],
                        "recommendations":["Isolate source host","Check for Cobalt Strike/Empire"],
                        "mitre_technique":"T1071.001","mitre_tactic":"Command and Control",
                        "ts":req.get("ts")})
                    break
            # Check suspicious UA patterns
            for pattern,category,sev in IOC_SUSPICIOUS_UA_PATTERNS:
                if pattern in ua_low:
                    findings.append({"title":f"Suspicious User-Agent: {pattern}",
                        "category":"HTTP Anomaly","severity":sev,
                        "description":(f"HTTP request with suspicious UA ({category}): {ua[:80]}"),
                        "evidence":[f"User-Agent: {ua}",f"Category: {category}"],
                        "recommendations":["Investigate source host","Block if unauthorised"],
                        "mitre_technique":"T1071.001","mitre_tactic":"Command and Control",
                        "ts":req.get("ts")})
                    break
        # C2 URI patterns
        c2_uri_seen:set=set()
        for req in http:
            uri=req.get("uri","")
            for c2uri in IOC_C2_URIS:
                if c2uri in uri and uri not in c2_uri_seen:
                    findings.append({"title":f"Known C2 URI Pattern: {c2uri}",
                        "category":"C2 Communication","severity":"HIGH",
                        "description":(f"HTTP request to known C2 URI pattern '{c2uri}' "
                                       f"from {req.get('src_ip','')}"),
                        "evidence":[f"URI: {uri}",f"Host: {req.get('host','')}"],
                        "recommendations":["Block destination","Investigate source host"],
                        "mitre_technique":"T1071.001","mitre_tactic":"Command and Control",
                        "ts":req.get("ts")})
                    c2_uri_seen.add(uri); break
        return findings


# ── IOCChecker (Layer 5) ──────────────────────────────────────────────────────
class IOCChecker:
    """External IPs, DNS queries, HTTP hosts/URLs, suspicious ports, DGA detection."""
    def check(self,parsed:Dict,pcap_path:str)->List[Dict]:
        sessions=list(parsed["sessions"].values())
        dns=parsed["dns_queries"]; http=parsed["http_requests"]
        iocs:List[Dict]=[]; seen:set=set()
        def add(t,v,rule,conf,tags,ts=None):
            k=(t,v.lower()[:120])
            if k in seen: return
            seen.add(k); iocs.append({"type":t,"value":v,"rule":rule,"confidence":conf,"tags":tags,"ts":ts})
        # External IPs
        for s in sessions:
            for ip in(s["src_ip"],s["dst_ip"]):
                if not self._is_priv(ip) and ip not in("0.0.0.0","255.255.255.255","::"):
                    add("IP",ip,"External IP Contact",40,"network,external",s["first_seen"])
        # Suspicious ports
        for s in sessions:
            for port in(s["src_port"],s["dst_port"]):
                if port in IOC_SUSPICIOUS_PORTS:
                    meta=IOC_SUSPICIOUS_PORTS[port]
                    conf={"CRITICAL":90,"HIGH":75,"MEDIUM":55,"LOW":35}.get(meta["severity"],55)
                    add("IP",f"{s['dst_ip']}:{port}",
                        f"Suspicious Port — {meta['desc']}",conf,
                        f"network,suspicious_port,port_{port}",s["first_seen"])
        # DNS
        for q in dns:
            dom=q.get("domain","")
            if not dom: continue
            ent=self._entropy(dom.split(".")[0]) if "." in dom else 0
            if ent>3.8 and len(dom.split(".")[0])>8:
                add("DOMAIN",dom,"High-Entropy Domain (DGA)",72,"network,dns,dga",q["ts"])
            else:
                add("DOMAIN",dom,"DNS Query",50,"network,dns",q["ts"])
        # HTTP
        seen_hosts:set=set()
        for req in http:
            host=req.get("host","")
            if host and host not in seen_hosts:
                add("DOMAIN",host,"HTTP Host Header",55,"network,http",req.get("ts"))
                seen_hosts.add(host)
            uri=req.get("uri","")
            if uri and uri not in("/",""):
                add("URL",f"http://{req.get('dst_ip','')}{uri}","HTTP Request",45,"network,http,url",req.get("ts"))
        return iocs

    @staticmethod
    def _is_priv(ip:str)->bool:
        try:
            p=ip.split(".")
            n=(int(p[0])<<24)|(int(p[1])<<16)|(int(p[2])<<8)|int(p[3])
            priv=[(0xC0A80000,0xFFFF0000),(0xAC100000,0xFFF00000),(0x0A000000,0xFF000000),(0x7F000000,0xFF000000)]
            return any((n&m)==(net&m) for net,m in priv)
        except Exception: return True
    @staticmethod
    def _entropy(s:str)->float:
        if not s: return 0.0
        freq:Dict[str,int]={}
        for c in s: freq[c]=freq.get(c,0)+1
        n=len(s)
        return -sum((v/n)*_math.log2(v/n) for v in freq.values())


# ── PCAPEngine orchestrator ───────────────────────────────────────────────────
class PCAPEngine:
    """Runs all 5 analysis layers, persists results, returns rich summary."""
    def __init__(self,case_id:str):
        self.case_id=case_id; self.db=CaseDatabase(case_id)

    def analyse(self,pcap_path:str,evidence_id:str)->Dict:
        import time
        start_t=time.time()
        parser=PCAPParser()
        try: parsed=parser.parse(pcap_path)
        except Exception as e: return {"error":str(e)}
        sessions=parsed["sessions"]
        log.info(f"PCAP: {parsed['packet_count']} pkts, {len(sessions)} sessions")
        traffic  =TrafficAnalyzer().analyze(parsed)
        anomalies=AnomalyDetector().analyze(parsed)
        attacks  =AttackDetector().analyze(parsed)
        iocs     =IOCChecker().check(parsed,pcap_path)
        # Merge all findings
        all_f=(traffic.get("findings",[])+anomalies.get("findings",[])+attacks.get("findings",[]))
        # Deduplicate by title+src+dst
        seen_f:set=set(); deduped:List[Dict]=[]
        for f in all_f:
            k=(f["title"],f.get("src_ip",""),f.get("dst_ip",""))
            if k not in seen_f: seen_f.add(k); deduped.append(f)
        # Persist sessions
        self.db.execute("DELETE FROM pcap_sessions WHERE case_id=?",(self.case_id,))
        for sid,s in sessions.items():
            risk=self._session_risk(s,attacks.get("matches",[]))
            tags=self._session_tags(s)
            pp=""
            if s.get("payload"):
                raw_p=s["payload"]
                if isinstance(raw_p,(bytes,bytearray)):
                    pp="".join(chr(b) if 0x20<=b<=0x7E else "." for b in raw_p[:200])
                else: pp=str(raw_p)[:200]
            self.db.execute(
                "INSERT OR REPLACE INTO pcap_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid,self.case_id,evidence_id,
                 s["src_ip"],s["dst_ip"],s["src_port"],s["dst_port"],
                 s["protocol"],s["pkt_count"],s["byte_count"],
                 str(s["first_seen"]),str(s["last_seen"]),
                 s.get("flags",""),pp,risk,",".join(tags),_now()))
        # Persist IOCs
        self.db.execute("DELETE FROM ioc_matches WHERE case_id=? AND source_artifact=?",(self.case_id,pcap_path))
        for ioc in iocs:
            self.db.execute("INSERT OR IGNORE INTO ioc_matches VALUES (?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()),self.case_id,ioc["type"],ioc["value"],
                 ioc["rule"],ioc["confidence"],ioc["tags"],pcap_path,_now()))
        # Persist findings → timeline (clear old first, cap to 5 per title)
        self.db.execute("DELETE FROM timeline_events WHERE case_id=? AND source='PCAP'",(self.case_id,))
        title_counts:Dict[str,int]={}
        for f in deduped:
            title=f["title"]
            title_counts[title]=title_counts.get(title,0)+1
            if title_counts[title]>5: continue
            sev_score={"CRITICAL":95,"HIGH":75,"MEDIUM":50,"LOW":25}.get(f.get("severity","LOW"),25)
            # Real packet timestamp
            pkt_ts=f.get("ts")
            if pkt_ts:
                try:
                    import datetime
                    ts_str=datetime.datetime.utcfromtimestamp(float(pkt_ts)).strftime("%Y-%m-%dT%H:%M:%S")
                except Exception: ts_str=_now()
            else: ts_str=_now()
            mitre=f.get("mitre_technique","")
            mitre_name=MITRE_TECHNIQUES.get(mitre,{}).get("name","")
            desc=f["title"]+": "+f.get("description","")[:200]
            if mitre: desc+=f" [{mitre}]"
            self.db.execute(
                "INSERT INTO timeline_events "
                "(event_id,case_id,timestamp,event_type,source,description,risk_score,related_pid,related_file,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()),self.case_id,ts_str,
                 f.get("category","NETWORK"),"PCAP",desc,
                 sev_score,None,pcap_path,_now()))
        duration=time.time()-start_t
        sev_counts={"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in deduped:
            sev_counts[f.get("severity","LOW")]=sev_counts.get(f.get("severity","LOW"),0)+1
        top_talkers=sorted(parsed["top_talkers"].items(),key=lambda x:x[1],reverse=True)[:10]
        # MITRE coverage
        mitre_coverage:Dict[str,set]={}
        for f in deduped:
            tech=f.get("mitre_technique","")
            if tech and tech in MITRE_TECHNIQUES:
                tactic=MITRE_TECHNIQUES[tech]["tactic"]
                mitre_coverage.setdefault(tactic,set()).add(tech)
        return {
            "packets":parsed["packet_count"],"bytes":parsed["byte_count"],
            "duration_secs":round(duration,2),"sessions":len(sessions),
            "iocs":len(iocs),"findings":len(deduped),"severity":sev_counts,
            "protocols":parsed["protocols"],
            "top_talkers":[{"ip":k,"packets":v} for k,v in top_talkers],
            "dns_queries":len(parsed["dns_queries"]),
            "http_requests":len(parsed["http_requests"]),
            "unique_ips":len(parsed["unique_ips"]),"unique_ports":len(parsed["unique_ports"]),
            "errors":parsed["errors"],
            "analyzers":{"traffic":{"findings":len(traffic.get("findings",[]))},
                         "anomaly":{"findings":len(anomalies.get("findings",[]))},
                         "attack":{"findings":len(attacks.get("findings",[]))},
                         "ioc":{"findings":len(iocs)}},
            "mitre_coverage":{k:list(v) for k,v in mitre_coverage.items()},
            "all_findings":deduped[:100],
        }

    def _session_risk(self,s:Dict,matches:List)->float:
        score=0.0; port=s.get("dst_port",0)
        if port in IOC_SUSPICIOUS_PORTS:
            score+={"CRITICAL":60,"HIGH":50,"MEDIUM":35,"LOW":15}.get(IOC_SUSPICIOUS_PORTS[port]["severity"],30)
        try:
            p=s["dst_ip"].split(".")
            n=(int(p[0])<<24)|(int(p[1])<<16)|(int(p[2])<<8)|int(p[3])
            priv=[(0xC0A80000,0xFFFF0000),(0xAC100000,0xFFF00000),(0x0A000000,0xFF000000),(0x7F000000,0xFF000000)]
            if not any((n&m)==(net&m) for net,m in priv): score+=15
        except Exception: pass
        if s.get("byte_count",0)>1_000_000: score+=20
        if s.get("pkt_count",0)>1000: score+=10
        for m in matches:
            if m.get("src")==s["src_ip"] or m.get("dst")==s["dst_ip"]: score+=25; break
        return min(score,100.0)

    def _session_tags(self,s:Dict)->List[str]:
        tags=[]; port=s.get("dst_port",0)
        if port in IOC_SUSPICIOUS_PORTS: tags.append(IOC_SUSPICIOUS_PORTS[port]["desc"].split("(")[0].strip().lower().replace(" ","-"))
        try:
            p=s["dst_ip"].split(".")
            n=(int(p[0])<<24)|(int(p[1])<<16)|(int(p[2])<<8)|int(p[3])
            priv=[(0xC0A80000,0xFFFF0000),(0xAC100000,0xFFF00000),(0x0A000000,0xFF000000),(0x7F000000,0xFF000000)]
            if not any((n&m)==(net&m) for net,m in priv): tags.append("external")
        except Exception: pass
        if s.get("protocol")=="DNS": tags.append("dns")
        if port in(80,8080): tags.append("http")
        if port in(443,8443): tags.append("https")
        if s.get("byte_count",0)>1e6: tags.append("high-volume")
        return tags



# ─── Engine 8: AI Anomaly Detection ──────────────────────────────────────────
class AIAnomalyEngine:
    """
    Scores extracted files using a two-layer approach:
      1. Rule-based heuristics (always runs, no sklearn needed)
      2. IsolationForest anomaly detection on file feature vectors (sklearn optional)

    Heuristic features scored:
      - Suspicious filename patterns (mimikatz, nc, ncat, netcat, pwdump…)
      - Executable in unusual location (/tmp, /dev/shm, hidden dirs)
      - SUID/SGID bit on unexpected files
      - Recently modified system binaries
      - Files with no extension but ELF/PE magic
      - Double extensions (.pdf.exe, .jpg.sh)
      - World-writable executables
      - Deleted but still present (allocated=0 but size>0)
    """

    SUSP_NAMES = {
        "mimikatz","meterpreter","pwdump","procdump","wce","fgdump",
        "netcat","ncat","nc","socat","cryptolocker","wannacry","petya",
        "lazagne","secretsdump","bloodhound","sharphound","cobalt",
        "beacon","empire","psexec","wmiexec","smbexec","crackmapexec",
        "hydra","medusa","hashcat","john","sqlmap","nmap","masscan",
        "tcpdump","wireshark","volatility","autopsy",
    }

    SUSP_DIRS = {"/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/",
                 "/.hidden", "/.."}

    DOUBLE_EXT = {".exe",".sh",".py",".pl",".rb",".elf",".bat",".ps1",".vbs"}

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db = CaseDatabase(case_id)

    def run(self) -> List[Dict]:
        """Score all extracted files for this case. Returns list of scored records."""
        files = self.db.execute(
            """SELECT file_id, name, full_path, size, file_type,
                      allocated, permissions, modified_ts, inode
               FROM extracted_files WHERE case_id=? AND file_type='FILE'
               ORDER BY size DESC LIMIT 50000""",
            (self.case_id,)
        )
        if not files:
            return []

        # Clear old scores
        self.db.execute("DELETE FROM ai_risk_scores WHERE case_id=?", (self.case_id,))

        scored = []
        feature_matrix = []

        for f in files:
            h, reasons, features = self._heuristic(f)
            feature_matrix.append(features)
            scored.append({
                "file_id":        f["file_id"],
                "name":           f.get("name", ""),
                "full_path":      f.get("full_path", ""),
                "size":           f.get("size", 0),
                "heuristic_score": h,
                "reasons":        reasons,
                "features":       features,
                "final_score":    h,           # updated below if sklearn available
                "classification": self._classify(h),
            })

        # ── IsolationForest anomaly layer ──────────────────────────
        if SKLEARN_AVAILABLE and len(scored) >= 10:
            try:
                X = np.array(feature_matrix, dtype=float)
                # Normalize each column
                col_max = X.max(axis=0)
                col_max[col_max == 0] = 1
                X_norm = X / col_max

                model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
                model.fit(X_norm)
                # score_samples returns negative; invert and scale to 0-100
                raw = -model.score_samples(X_norm)
                # Normalise to 0-100
                r_min, r_max = raw.min(), raw.max()
                if r_max > r_min:
                    iso_scores = (raw - r_min) / (r_max - r_min) * 100
                else:
                    iso_scores = np.zeros(len(raw))

                for i, s in enumerate(scored):
                    iso = float(iso_scores[i])
                    # Blend: 70% heuristic + 30% isolation forest
                    blended = s["heuristic_score"] * 0.7 + iso * 0.3
                    s["iso_score"]    = round(iso, 1)
                    s["final_score"]  = round(min(blended, 100.0), 1)
                    s["classification"] = self._classify(s["final_score"])
                    if iso > 60:
                        s["reasons"].append(f"IsolationForest anomaly ({iso:.0f})")
            except Exception as e:
                log.warning(f"IsolationForest failed: {e}")

        # ── Persist top 500 scored files ──────────────────────────
        scored.sort(key=lambda x: x["final_score"], reverse=True)
        for s in scored[:500]:
            if s["final_score"] < 5:
                continue  # skip completely clean files to save space
            try:
                self.db.execute(
                    "INSERT OR REPLACE INTO ai_risk_scores VALUES (?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()), self.case_id,
                     s["full_path"] or s["name"],
                     "Heuristic+IsolationForest",
                     s["final_score"],
                     s["classification"],
                     json.dumps({
                         "reasons":    s["reasons"],
                         "heuristic":  s["heuristic_score"],
                         "iso":        s.get("iso_score", 0),
                         "features":   s["features"],
                         "name":       s["name"],
                         "full_path":  s["full_path"],
                         "size":       s["size"],
                     }),
                     _now())
                )
            except Exception as e:
                log.debug(f"AI score insert error: {e}")

        log.info(f"AI scored {len(scored)} files, {sum(1 for s in scored if s['final_score']>=40)} flagged")
        return scored

    def score_processes(self, processes: List[Dict]) -> List[Dict]:
        """Legacy: score memory processes."""
        if not SKLEARN_AVAILABLE or len(processes) < 2:
            return processes
        try:
            features = [[
                float(p.get("pid", 0)), float(p.get("ppid", 0)),
                float(len(p.get("raw_data", ""))), float(p.get("risk_score", 0)),
            ] for p in processes]
            X = np.array(features)
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(X)
            scores = -model.score_samples(X)
            for i, (proc, score) in enumerate(zip(processes, scores)):
                ai_score = min(float(score * 100), 100.0)
                clf = self._classify(ai_score)
                proc["ai_risk_score"] = ai_score
                proc["ai_classification"] = clf
                self.db.execute(
                    "INSERT INTO ai_risk_scores VALUES (?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()), self.case_id, str(proc.get("pid", "")),
                     "IsolationForest", ai_score, clf,
                     json.dumps({"features": features[i]}), _now())
                )
        except Exception as e:
            log.error(f"AI process scoring error: {e}")
        return processes

    def _heuristic(self, f: Dict):
        """
        Returns (score 0-100, [reasons], feature_vector).
        Feature vector: [size_kb, has_susp_name, susp_dir, double_ext,
                         is_exec, is_deleted, is_suid, name_entropy]
        """
        name     = (f.get("name") or "").lower()
        path     = (f.get("full_path") or "").lower()
        size     = f.get("size", 0) or 0
        alloc    = f.get("allocated", 1)
        perms    = f.get("permissions") or ""
        ext      = Path(name).suffix.lower()
        stem     = Path(name).stem.lower()

        score   = 0.0
        reasons = []

        # 1. Suspicious filename match
        for s in self.SUSP_NAMES:
            if s in name:
                score += 60
                reasons.append(f"Suspicious name match: '{s}'")
                break

        # 2. Double extension (.pdf.exe, .jpg.sh)
        stem_ext = Path(stem).suffix.lower()
        if stem_ext and ext in self.DOUBLE_EXT:
            score += 45
            reasons.append(f"Double extension: {stem_ext}{ext}")

        # 3. Executable in suspicious directory
        for d in self.SUSP_DIRS:
            if d in path and ext in {".sh",".py",".pl",".elf","",".bin"}:
                score += 40
                reasons.append(f"Executable in suspicious dir: {d}")
                break

        # 4. Deleted file with content
        if alloc == 0 and size > 0:
            score += 30
            reasons.append("Deleted file with recoverable content")

        # 5. SUID/SGID on non-standard binary
        if perms and ("s" in perms.lower()):
            std_suid = {"/bin/","/usr/bin/","/sbin/","/usr/sbin/"}
            if not any(s in path for s in std_suid):
                score += 35
                reasons.append("SUID/SGID bit on non-standard binary")

        # 6. Hidden file (starts with .)
        if name.startswith(".") and ext in {".sh",".py",".pl","",".elf",".bin",".exe"}:
            score += 25
            reasons.append("Hidden executable file")

        # 7. Script extension
        if ext in {".sh",".py",".pl",".rb",".ps1",".vbs",".bat",".cmd"}:
            score += 15
            reasons.append(f"Script file: {ext}")

        # 8. Name entropy (randomness — often malware)
        entropy = self._entropy(stem)
        if entropy > 4.0 and len(stem) > 6:
            score += 20
            reasons.append(f"High filename entropy ({entropy:.1f}) — possible random name")

        # 9. Very small executable (< 1 KB but marked as binary)
        if 0 < size < 1024 and ext in {".sh","",".bin",".elf"}:
            score += 10
            reasons.append("Suspiciously small executable")

        # Feature vector for IsolationForest
        features = [
            size / 1024,                           # size in KB
            1.0 if any(s in name for s in self.SUSP_NAMES) else 0.0,
            1.0 if any(d in path for d in self.SUSP_DIRS) else 0.0,
            1.0 if (stem_ext and ext in self.DOUBLE_EXT) else 0.0,
            1.0 if ext in {".sh",".py",".pl",".rb",".ps1",".exe",".elf",".bin"} else 0.0,
            1.0 if alloc == 0 else 0.0,
            1.0 if perms and "s" in perms.lower() else 0.0,
            entropy,
        ]

        return min(score, 100.0), reasons, features

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        from math import log2
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v/n) * log2(v/n) for v in freq.values())

    @staticmethod
    def _classify(score: float) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 35: return "MEDIUM"
        return "LOW"


# ─── Engine 9: Timeline Correlation ──────────────────────────────────────────
class TimelineCorrelationEngine:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db = CaseDatabase(case_id)

    def build_timeline(self, evidence_id: str) -> List[Dict]:
        events = []
        disk = self.db.execute(
            "SELECT 'FILE' as type,'Disk' as source,modified_ts as timestamp,'File: '||full_path as description,0 as risk_score,NULL as related_pid,full_path as related_file FROM extracted_files WHERE case_id=? AND modified_ts IS NOT NULL ORDER BY modified_ts DESC LIMIT 500",
            (self.case_id,)
        )
        events.extend(disk)
        mem = self.db.execute(
            "SELECT artifact_type as type,'Memory' as source,extracted_at as timestamp,plugin||': '||process_name||' (PID '||pid||')' as description,risk_score,pid as related_pid,NULL as related_file FROM memory_artifacts WHERE case_id=? ORDER BY extracted_at DESC LIMIT 500",
            (self.case_id,)
        )
        events.extend(mem)
        iocs = self.db.execute(
            "SELECT ioc_type as type,'IOC' as source,matched_at as timestamp,'IOC: '||rule_name as description,confidence as risk_score,NULL as related_pid,source_artifact as related_file FROM ioc_matches WHERE case_id=? ORDER BY matched_at DESC",
            (self.case_id,)
        )
        events.extend(iocs)
        events.sort(key=lambda x: x.get("timestamp") or "")
        for event in events:
            self.db.execute(
                "INSERT OR IGNORE INTO timeline_events (event_id,case_id,timestamp,event_type,source,description,risk_score,related_pid,related_file,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), self.case_id, event.get("timestamp"), event.get("type"),
                 event.get("source"), event.get("description"), event.get("risk_score", 0),
                 event.get("related_pid"), event.get("related_file"), _now())
            )
        return events

# ─── Engine 10: Report Generator ──────────────────────────────────────────────
class ReportEngine:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db = CaseDatabase(case_id)
        self.reports_dir = CASES_DIR / case_id / "reports"
        self.reports_dir.mkdir(exist_ok=True)

    def generate(self, report_type: str = "full", fmt: str = "json") -> Dict:
        case = self.db.execute("SELECT * FROM cases WHERE case_id=?", (self.case_id,))
        evidence = self.db.execute("SELECT * FROM evidence_items WHERE case_id=?", (self.case_id,))
        iocs = self.db.execute("SELECT * FROM ioc_matches WHERE case_id=?", (self.case_id,))
        timeline = self.db.execute("SELECT * FROM timeline_events WHERE case_id=? ORDER BY timestamp DESC LIMIT 100", (self.case_id,))
        coc = self.db.execute("SELECT * FROM chain_of_custody WHERE case_id=?", (self.case_id,))

        report = {
            "report_metadata": {
                "tool": "Forensic Cyber Triage Tool (FCTT)",
                "version": TOOL_VERSION,
                "case_id": self.case_id,
                "report_type": report_type,
                "generated_at": _now(),
                "integrity_note": "All evidence was mounted read-only. Hash values are cryptographically verified.",
            },
            "case_summary": case[0] if case else {},
            "evidence_items": evidence,
            "chain_of_custody": coc,
            "ioc_findings": {"total": len(iocs), "items": iocs},
            "timeline": timeline,
            "statistics": {
                "evidence_count": len(evidence),
                "ioc_count": len(iocs),
                "timeline_events": len(timeline),
            }
        }

        report_path = self.reports_dir / f"report_{_now()[:10]}_{report_type}.json"
        report_path.write_text(json.dumps(report, indent=2, default=str))
        report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
        report["report_metadata"]["report_sha256"] = report_hash
        self.db.append_coc("REPORT_GENERATED", "system", str(report_path), hash_after=report_hash)
        return report

# ─── Task Manager ─────────────────────────────────────────────────────────────
class TaskManager:
    def __init__(self):
        self._tasks: Dict[str, TaskStatus] = {}

    def create(self) -> str:
        tid = str(uuid.uuid4())
        self._tasks[tid] = TaskStatus(task_id=tid, status="queued", progress=0.0, message="Queued")
        return tid

    def update(self, tid: str, **kwargs):
        if tid in self._tasks:
            for k, v in kwargs.items():
                setattr(self._tasks[tid], k, v)

    def get(self, tid: str) -> Optional[TaskStatus]:
        return self._tasks.get(tid)

task_manager = TaskManager()
case_engine = CaseInitializationEngine()

# ─── FastAPI App ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Forensic Cyber Triage Tool API",
    description="FCTT Backend — SOC-Grade Digital Forensics Platform",
    version=TOOL_VERSION,
    docs_url="/api/docs",
)

app.add_middleware(CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"], allow_headers=["*"],
)

# ─── Case Routes ──────────────────────────────────────────────────────────────
@app.post("/api/cases", tags=["Cases"])
async def create_case(data: CaseCreate):
    return case_engine.create_case(data)

@app.get("/api/cases", tags=["Cases"])
async def list_cases():
    return case_engine.list_cases()

@app.delete("/api/cases/{case_id}", tags=["Cases"])
async def delete_case(case_id: str):
    """Permanently delete a case and all its data."""
    import shutil, gc, time, tempfile, os
    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        raise HTTPException(404, f"Case {case_id} not found")

    # ── Step 1: rename the directory first ───────────────────────
    # On Windows, renaming works even when files inside are open.
    # This instantly makes the case invisible to the rest of the app.
    tmp_dir = CASES_DIR / f"_deleting_{case_id}_{int(time.time())}"
    try:
        os.rename(case_dir, tmp_dir)
    except Exception as e:
        raise HTTPException(500, f"Could not rename case directory: {e}")

    # ── Step 2: delete the renamed directory in background ───────
    # We try immediately, then retry — by the time background tasks
    # finish their current DB call the handles will be released.
    def _do_delete(path):
        for attempt in range(10):
            try:
                shutil.rmtree(path, ignore_errors=False)
                log.info(f"Deleted case dir: {path}")
                return
            except Exception as e:
                log.debug(f"Delete attempt {attempt+1} failed: {e}")
                gc.collect()
                time.sleep(0.5)
        # Last resort: ignore errors and delete what we can
        shutil.rmtree(path, ignore_errors=True)
        log.warning(f"Force-deleted (some files may remain): {path}")

    import threading
    threading.Thread(target=_do_delete, args=(tmp_dir,), daemon=True).start()

    return {"deleted": True, "case_id": case_id}


async def get_case(case_id: str):
    db = CaseDatabase(case_id)
    rows = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,))
    if not rows:
        raise HTTPException(404, "Case not found")
    return rows[0]

# ─── Evidence Routes ──────────────────────────────────────────────────────────
@app.post("/api/cases/{case_id}/evidence", tags=["Evidence"])
async def ingest_evidence(case_id: str, file: UploadFile = File(...), investigator: str = "analyst"):
    engine = EvidenceIngestionEngine(case_id)
    return await engine.ingest(file, investigator)

@app.get("/api/cases/{case_id}/evidence", tags=["Evidence"])
async def list_evidence(case_id: str):
    return CaseDatabase(case_id).execute("SELECT * FROM evidence_items WHERE case_id=?", (case_id,))

# ─── Triage Routes ────────────────────────────────────────────────────────────
@app.post("/api/cases/{case_id}/triage", tags=["Triage"])
async def run_triage(case_id: str, req: TriageRequest, background_tasks: BackgroundTasks):
    tid = task_manager.create()
    background_tasks.add_task(_triage_worker, case_id, req, tid)
    return {"task_id": tid, "status": "queued"}

def _index_files_for_fts(case_id: str, image_path: str, files: List[Dict], db) -> int:
    """
    Index files for full-text keyword search, like Autopsy's keyword search module.

    For each file we index:
      1. The filename and full path (always)
      2. The text content of the file (for text/script/config files ≤ 512 KB)

    Text content is read directly from the disk image using the file's
    inode/cluster offset stored during filesystem parsing.

    Returns number of rows indexed.
    """
    # File extensions we try to extract text from
    TEXT_EXTS = {
        '.txt', '.log', '.csv', '.xml', '.json', '.html', '.htm', '.js', '.py',
        '.sh', '.bash', '.conf', '.cfg', '.ini', '.inf', '.bat', '.cmd', '.ps1',
        '.yaml', '.yml', '.toml', '.md', '.rst', '.sql', '.php', '.rb', '.pl',
        '.java', '.c', '.cpp', '.h', '.cs', '.vb', '.asm', '.nfo', '.readme',
        '.service', '.rules', '.list', '.sources', '.desktop', '.rc', '.env',
    }
    MAX_CONTENT_BYTES = 512 * 1024   # 512 KB max per file
    MAX_FILES         = 20000         # cap to avoid triage taking too long
    indexed = 0

    # Clear old FTS entries for this case to avoid duplicates on re-triage
    try:
        db.execute("DELETE FROM fts_index WHERE case_id=?", (case_id,))
    except Exception:
        pass

    try:
        img = open(image_path, "rb")
    except Exception as e:
        log.warning(f"FTS: cannot open image {image_path}: {e}")
        img = None

    for f in files[:MAX_FILES]:
        name      = f.get("name", "") or ""
        full_path = f.get("full_path", "") or ""
        file_id   = f.get("file_id", "") or ""
        size      = f.get("size", 0) or 0
        ftype     = f.get("file_type", "FILE")

        # Always index filename + path
        base_content = f"{name} {full_path}".strip()

        text_content = ""

        # Try to read text content for small text files
        ext = Path(name).suffix.lower() if name else ""
        if (
            img is not None
            and ftype == "FILE"
            and size > 0
            and size <= MAX_CONTENT_BYTES
            and ext in TEXT_EXTS
        ):
            try:
                # The file's data is at a cluster/block offset in the image.
                # We stored inode number but not the actual byte offset.
                # Best approach: use the /api/file-bytes endpoint logic —
                # read from the cases extracted files dir if it exists,
                # otherwise skip content extraction for this file.
                # For now: use strings(1)-style extraction — scan image near
                # where similar files live. Since we can't map inode→offset
                # without re-parsing, we extract printable strings from
                # whatever bytes the file would occupy if stored sequentially.
                # This is an approximation — pytsk3 would give exact offsets.
                #
                # REAL extraction via pytsk3 (if available):
                if PYTSK3_AVAILABLE:
                    import pytsk3
                    img_info = pytsk3.Img_Info(image_path)
                    try:
                        fs_info = pytsk3.FS_Info(img_info)
                        inode_num = f.get("inode", 0)
                        if inode_num and inode_num > 0:
                            file_entry = fs_info.open_meta(inode=inode_num)
                            raw = file_entry.read_random(0, min(size, MAX_CONTENT_BYTES))
                            text_content = _extract_text(raw)
                    except Exception:
                        pass
            except Exception as e:
                log.debug(f"FTS content read failed for {name}: {e}")

        # Build final indexed content:
        # "name full_path [text_content]"
        content = base_content
        if text_content:
            content = f"{base_content} {text_content}"

        try:
            db.execute(
                "INSERT INTO fts_index (case_id, file_id, name, full_path, source, content) "
                "VALUES (?,?,?,?,?,?)",
                (case_id, file_id, name, full_path, "disk", content)
            )
            indexed += 1
        except Exception as e:
            log.debug(f"FTS insert error for {name}: {e}")

    # Also index YARA hits, IOCs, memory artifacts
    try:
        yara_hits = db.execute(
            "SELECT ioc_id, rule_name, indicator, tags FROM ioc_matches WHERE case_id=?",
            (case_id,)
        )
        for h in yara_hits:
            content = f"{h.get('rule_name','')} {h.get('indicator','')} {h.get('tags','')}"
            db.execute(
                "INSERT INTO fts_index (case_id, file_id, name, full_path, source, content) "
                "VALUES (?,?,?,?,?,?)",
                (case_id, h.get('ioc_id',''), h.get('rule_name',''), '', "yara", content)
            )
    except Exception:
        pass

    try:
        mem_arts = db.execute(
            "SELECT artifact_id, plugin, details FROM memory_artifacts WHERE case_id=?",
            (case_id,)
        )
        for m in mem_arts:
            content = f"{m.get('plugin','')} {m.get('details','')}"
            db.execute(
                "INSERT INTO fts_index (case_id, file_id, name, full_path, source, content) "
                "VALUES (?,?,?,?,?,?)",
                (case_id, m.get('artifact_id',''), m.get('plugin',''), '', "memory", content)
            )
    except Exception:
        pass

    if img:
        img.close()

    log.info(f"FTS: indexed {indexed} files for case {case_id}")
    return indexed


def _extract_text(raw: bytes) -> str:
    """
    Extract printable text from raw bytes.
    Tries UTF-8, then latin-1, then falls back to ASCII printable extraction.
    Returns up to 4000 chars of text suitable for FTS indexing.
    """
    # Try UTF-8
    try:
        text = raw.decode("utf-8", errors="strict")
        return " ".join(text.split())[:4000]
    except UnicodeDecodeError:
        pass
    # Try latin-1
    try:
        text = raw.decode("latin-1")
        # Filter to printable ASCII for indexing
        printable = "".join(c for c in text if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t")
        return " ".join(printable.split())[:4000]
    except Exception:
        pass
    # Strings extraction — find runs of ≥4 printable ASCII chars
    strings = []
    current = []
    for b in raw:
        if 0x20 <= b <= 0x7E:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings.append("".join(current))
            current = []
    if len(current) >= 4:
        strings.append("".join(current))
    return " ".join(strings)[:4000]


async def _triage_worker(case_id: str, req: TriageRequest, tid: str):
    db = CaseDatabase(case_id)
    try:
        # ── 0. Locate evidence file ───────────────────────────────
        rows = db.execute(
            "SELECT filepath, evidence_type FROM evidence_items WHERE evidence_id=?",
            (req.evidence_id,)
        )
        if not rows:
            task_manager.update(tid, status="error", message="Evidence not found in DB")
            return
        image_path   = rows[0]["filepath"]
        evidence_type= rows[0].get("evidence_type", "")

        if not os.path.exists(image_path):
            task_manager.update(tid, status="error",
                message=f"Evidence file missing on disk: {image_path}")
            return

        file_size_mb = os.path.getsize(image_path) / (1024 * 1024)
        log.info(f"Triage started: {image_path} ({file_size_mb:.1f} MB) type={evidence_type}")

        # ── 1. File system walk ───────────────────────────────────
        task_manager.update(tid, status="running", progress=5,
            message=f"Parsing filesystem of {Path(image_path).name} ({file_size_mb:.1f} MB)…")
        walker = FileSystemWalker(case_id)
        files = walker.walk(image_path, req.evidence_id)
        log.info(f"FS walk complete: {len(files)} entries")
        task_manager.update(tid, progress=30,
            message=f"Filesystem parsed: {len(files)} files/dirs found")

        # ── 2. File signature carving ─────────────────────────────
        carved_count = 0
        if req.enable_carving and evidence_type in ("RAW_DISK", "MEMORY_DUMP", "UNKNOWN", ""):
            task_manager.update(tid, progress=35,
                message="Carving file signatures from raw image…")
            try:
                carver = FileCarvingEngine(case_id)
                carved = carver.carve(image_path, req.evidence_id)
                carved_count = len(carved)
                log.info(f"Carving complete: {carved_count} artifacts")
            except Exception as e:
                log.warning(f"Carving error (non-fatal): {e}")
        task_manager.update(tid, progress=45,
            message=f"Carving done: {carved_count} artifacts")

        # ── 3. YARA scan ──────────────────────────────────────────
        task_manager.update(tid, progress=50, message="Running YARA engine against image…")
        hits: List[Dict] = []
        try:
            yara_eng = YARAEngine(case_id)
            hits = yara_eng.scan_file(image_path, req.evidence_id)
            log.info(f"YARA: {len(hits)} hits")
        except Exception as e:
            log.warning(f"YARA error (non-fatal): {e}")
        task_manager.update(tid, progress=60,
            message=f"YARA complete: {len(hits)} hits")

        # ── 4. Memory analysis (only for .vmem / .raw memory dumps) ──
        mem_artifacts = 0
        if evidence_type in ("MEMORY_DUMP",) or Path(image_path).suffix.lower() in (".vmem",):
            task_manager.update(tid, progress=65,
                message="Running Volatility memory plugins…")
            try:
                mem = MemoryAnalysisEngine(case_id)
                mem_results = mem.run_plugins(image_path, req.evidence_id, req.plugins)
                mem_artifacts = sum(len(v) for v in mem_results.values())
                log.info(f"Memory analysis: {mem_artifacts} artifacts")
            except Exception as e:
                log.warning(f"Memory analysis error (non-fatal): {e}")
        task_manager.update(tid, progress=75,
            message=f"Memory analysis: {mem_artifacts} artifacts")

        # ── 5. AI anomaly scoring ─────────────────────────────────
        task_manager.update(tid, progress=80, message="Running AI risk scoring on extracted files…")
        try:
            ai = AIAnomalyEngine(case_id)
            ai_results = ai.run()
            flagged = sum(1 for r in ai_results if r["final_score"] >= 35)
            log.info(f"AI scoring: {len(ai_results)} files scored, {flagged} flagged")
            # Also score memory processes if available
            procs = db.execute(
                "SELECT * FROM memory_artifacts WHERE case_id=? AND plugin LIKE '%pslist%'",
                (case_id,)
            )
            if procs:
                ai.score_processes(procs)
        except Exception as e:
            log.warning(f"AI scoring error (non-fatal): {e}")

        # ── 6. Index files for full-text search ───────────────────
        task_manager.update(tid, progress=85, message="Extracting file content for keyword search…")
        try:
            _index_files_for_fts(case_id, image_path, files, db)
        except Exception as e:
            log.warning(f"FTS indexing error (non-fatal): {e}")

        # ── 7. Build unified timeline ─────────────────────────────
        task_manager.update(tid, progress=92, message="Building unified forensic timeline…")
        timeline: List[Dict] = []
        try:
            tl = TimelineCorrelationEngine(case_id)
            timeline = tl.build_timeline(req.evidence_id)
        except Exception as e:
            log.warning(f"Timeline error (non-fatal): {e}")

        # ── Done ──────────────────────────────────────────────────
        summary = (
            f"✓ Complete — {len(files)} files · {carved_count} carved · "
            f"{len(hits)} YARA hits · {mem_artifacts} mem artifacts · "
            f"{len(timeline)} timeline events"
        )
        task_manager.update(tid, status="done", progress=100, message=summary,
            result={
                "files":        len(files),
                "carved":       carved_count,
                "yara_hits":    len(hits),
                "mem_artifacts":mem_artifacts,
                "timeline":     len(timeline),
            })
        log.info(f"Triage complete for {case_id}: {summary}")

    except Exception as e:
        import traceback
        err = f"{type(e).__name__}: {e}"
        log.error(f"Triage fatal error: {err}\n{traceback.format_exc()}")
        task_manager.update(tid, status="error", message=err)

@app.get("/api/tasks/{task_id}", tags=["Tasks"])
async def get_task(task_id: str):
    t = task_manager.get(task_id)
    if not t:
        raise HTTPException(404, "Task not found")
    return t

# ─── Analysis Routes ──────────────────────────────────────────────────────────
@app.get("/api/cases/{case_id}/processes", tags=["Analysis"])
async def get_processes(case_id: str):
    return CaseDatabase(case_id).execute("SELECT * FROM memory_artifacts WHERE case_id=? AND plugin LIKE '%pslist%' ORDER BY risk_score DESC", (case_id,))

@app.get("/api/cases/{case_id}/network", tags=["Analysis"])
async def get_network(case_id: str):
    return CaseDatabase(case_id).execute("SELECT * FROM memory_artifacts WHERE case_id=? AND plugin LIKE '%netscan%' ORDER BY risk_score DESC", (case_id,))

@app.get("/api/cases/{case_id}/files", tags=["Analysis"])
async def get_files(case_id: str):
    rows = CaseDatabase(case_id).execute(
        "SELECT * FROM extracted_files WHERE case_id=? ORDER BY full_path ASC LIMIT 5000",
        (case_id,)
    )
    # Sanitize names at response time — cleans old DB data too
    def _ascii_only(s: str) -> str:
        if not s:
            return s
        return "".join(c for c in s if 0x20 <= ord(c) <= 0x7E).strip()

    for row in rows:
        if row.get("name"):
            row["name"] = _ascii_only(row["name"]) or "(unnamed)"
        if row.get("full_path"):
            # Clean each path segment individually
            parts = row["full_path"].split("/")
            row["full_path"] = "/".join(
                _ascii_only(p) if p else p for p in parts
            )
    return rows

# ─── PCAP Endpoints ───────────────────────────────────────────────────────────

@app.post("/api/cases/{case_id}/pcap/analyse", tags=["PCAP"])
async def analyse_pcap(case_id: str, evidence_id: str = ""):
    """Analyse a PCAP evidence file for this case."""
    db = CaseDatabase(case_id)
    if evidence_id:
        ev = db.execute(
            "SELECT filepath, evidence_id FROM evidence_items WHERE case_id=? AND evidence_id=?",
            (case_id, evidence_id)
        )
    else:
        # Match by evidence_type OR by file extension as fallback
        ev = db.execute(
            "SELECT filepath, evidence_id FROM evidence_items WHERE case_id=? "
            "AND (evidence_type='NETWORK_CAPTURE' "
            "  OR LOWER(filepath) LIKE '%.pcap' "
            "  OR LOWER(filepath) LIKE '%.pcapng' "
            "  OR LOWER(filepath) LIKE '%.cap') "
            "ORDER BY added_at DESC LIMIT 1",
            (case_id,)
        )
    if not ev:
        # Debug: return what evidence IS in the case
        all_ev = db.execute("SELECT filename, filepath, evidence_type FROM evidence_items WHERE case_id=?", (case_id,))
        detail = f"No PCAP evidence found. Evidence in case: {[dict(e) for e in all_ev]}"
        raise HTTPException(404, detail)
    path = ev[0]["filepath"]
    if not Path(path).exists():
        raise HTTPException(404, f"PCAP file not found on disk: {path}")
    eng = PCAPEngine(case_id)
    result = eng.analyse(path, ev[0]["evidence_id"])
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result

@app.get("/api/cases/{case_id}/pcap/sessions", tags=["PCAP"])
async def get_pcap_sessions(case_id: str, limit: int = 500, min_risk: float = 0):
    rows = CaseDatabase(case_id).execute(
        "SELECT * FROM pcap_sessions WHERE case_id=? AND risk_score >= ? "
        "ORDER BY risk_score DESC, byte_count DESC LIMIT ?",
        (case_id, min_risk, limit)
    )
    return rows

@app.get("/api/cases/{case_id}/pcap/stats", tags=["PCAP"])
async def get_pcap_stats(case_id: str):
    db = CaseDatabase(case_id)
    sessions = db.execute("SELECT * FROM pcap_sessions WHERE case_id=?", (case_id,))
    if not sessions:
        return {"sessions": 0, "total_bytes": 0, "total_packets": 0,
                "protocols": {}, "top_talkers": [], "risk_counts": {}}
    total_bytes   = sum(s.get("byte_count", 0) for s in sessions)
    total_packets = sum(s.get("packet_count", 0) for s in sessions)
    protocols: Dict[str, int] = {}
    talkers:   Dict[str, int] = {}
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in sessions:
        p = s.get("protocol", "UNKNOWN")
        protocols[p] = protocols.get(p, 0) + 1
        for ip in (s.get("src_ip", ""), s.get("dst_ip", "")):
            if ip: talkers[ip] = talkers.get(ip, 0) + s.get("packet_count", 0)
        r = s.get("risk_score", 0)
        clf = "CRITICAL" if r >= 80 else "HIGH" if r >= 60 else "MEDIUM" if r >= 35 else "LOW"
        risk_counts[clf] = risk_counts.get(clf, 0) + 1
    top_talkers = sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "sessions":      len(sessions),
        "total_bytes":   total_bytes,
        "total_packets": total_packets,
        "protocols":     protocols,
        "top_talkers":   [{"ip": k, "packets": v} for k, v in top_talkers],
        "risk_counts":   risk_counts,
    }

@app.get("/api/cases/{case_id}/iocs", tags=["IOC"])
async def get_iocs(case_id: str, ioc_type: str = "", limit: int = 500):
    db = CaseDatabase(case_id)
    if ioc_type:
        rows = db.execute(
            "SELECT * FROM ioc_matches WHERE case_id=? AND ioc_type=? ORDER BY confidence DESC LIMIT ?",
            (case_id, ioc_type, limit)
        )
    else:
        rows = db.execute(
            "SELECT * FROM ioc_matches WHERE case_id=? ORDER BY confidence DESC LIMIT ?",
            (case_id, limit)
        )
    return rows

@app.get("/api/yara/rules", tags=["YARA"])
async def list_yara_rules():
    """List all YARA rule files on disk."""
    rules_dir = Path("./yara_rules")
    rules_dir.mkdir(exist_ok=True)
    rules = []
    for f in sorted(rules_dir.glob("*.yar")):
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            # Count rule definitions in file
            rule_count = content.count("\nrule ") + content.count("rule ", 0, 5)
            rules.append({
                "name":       f.stem,
                "filename":   f.name,
                "size":       f.stat().st_size,
                "rule_count": rule_count,
                "content":    content,
                "valid":      True,
            })
        except Exception as e:
            rules.append({"name": f.stem, "filename": f.name, "size": 0,
                          "rule_count": 0, "content": "", "valid": False, "error": str(e)})
    return rules

@app.post("/api/yara/rules", tags=["YARA"])
async def save_yara_rule(rule_name: str, content: str):
    """Save (create or update) a YARA rule file. Validates syntax first."""
    rules_dir = Path("./yara_rules")
    rules_dir.mkdir(exist_ok=True)
    # Sanitise name
    safe_name = "".join(c for c in rule_name if c.isalnum() or c in "-_").strip("-_") or "rule"
    # Validate syntax
    if YARA_AVAILABLE:
        try:
            yara.compile(source=content)
        except Exception as e:
            raise HTTPException(400, f"YARA syntax error: {e}")
    path = rules_dir / f"{safe_name}.yar"
    path.write_text(content, encoding="utf-8")
    return {"saved": True, "name": safe_name, "filename": path.name}

@app.delete("/api/yara/rules/{rule_name}", tags=["YARA"])
async def delete_yara_rule(rule_name: str):
    """Delete a YARA rule file."""
    path = Path("./yara_rules") / f"{rule_name}.yar"
    if not path.exists():
        raise HTTPException(404, f"Rule '{rule_name}' not found")
    path.unlink()
    return {"deleted": True, "name": rule_name}

@app.post("/api/cases/{case_id}/yara/scan", tags=["YARA"])
async def run_yara_scan(case_id: str):
    """Re-run YARA scan against the case evidence image."""
    db = CaseDatabase(case_id)
    ev = db.execute("SELECT filepath FROM evidence_items WHERE case_id=? LIMIT 1", (case_id,))
    if not ev:
        raise HTTPException(404, "No evidence found for this case")
    image_path = ev[0]["filepath"]
    if not Path(image_path).exists():
        raise HTTPException(404, f"Evidence file not found: {image_path}")
    if not YARA_AVAILABLE:
        raise HTTPException(503, "YARA not installed. Run: pip install yara-python")
    # Clear old YARA hits for this case
    db.execute("DELETE FROM ioc_matches WHERE case_id=? AND ioc_type='YARA'", (case_id,))
    eng = YARAEngine(case_id)
    hits = eng.scan_file(image_path, "manual_scan")
    return {"scanned": True, "hits": len(hits),
            "matches": [{"rule": h["rule_name"], "tags": h["tags"], "confidence": h["confidence"]} for h in hits]}

@app.post("/api/cases/{case_id}/yara/import", tags=["YARA"])
async def import_yara(case_id: str, rule_name: str, content: str):
    eng = YARAEngine(case_id)
    return {"success": eng.import_rules(content, rule_name)}

@app.get("/api/cases/{case_id}/timeline", tags=["Timeline"])
async def get_timeline(case_id: str, limit: int = 2000, offset: int = 0):
    return CaseDatabase(case_id).execute(
        "SELECT * FROM timeline_events WHERE case_id=? ORDER BY timestamp ASC LIMIT ? OFFSET ?",
        (case_id, limit, offset)
    )

@app.get("/api/cases/{case_id}/search/debug", tags=["Search"])
async def search_debug(case_id: str):
    """Debug endpoint — shows DB counts and sample names to diagnose search issues."""
    db = CaseDatabase(case_id)
    file_count = db.execute("SELECT COUNT(*) as c FROM extracted_files WHERE case_id=?", (case_id,))
    fts_count  = db.execute("SELECT COUNT(*) as c FROM fts_index WHERE case_id=?", (case_id,))
    samples    = db.execute("SELECT name, full_path FROM extracted_files WHERE case_id=? LIMIT 10", (case_id,))
    cases      = db.execute("SELECT DISTINCT case_id FROM extracted_files LIMIT 5")
    return {
        "case_id":        case_id,
        "file_count":     file_count[0]["c"] if file_count else 0,
        "fts_count":      fts_count[0]["c"] if fts_count else 0,
        "sample_files":   samples,
        "all_case_ids":   [r["case_id"] for r in cases],
    }

@app.get("/api/cases/{case_id}/search", tags=["Search"])
async def search(case_id: str, q: str, limit: int = 100):
    if not q or not q.strip():
        return {"query": q, "count": 0, "results": []}

    db  = CaseDatabase(case_id)
    q   = q.strip()
    lim = min(limit, 2000)

    # ── sanitize helpers ──────────────────────────────────────────────
    def _c(s: str) -> str:
        """Strip to printable ASCII only."""
        if not s: return ""
        return "".join(ch for ch in s if 0x20 <= ord(ch) <= 0x7E).strip()

    def _cp(s: str) -> str:
        """Clean each segment of a path."""
        if not s: return ""
        return "/".join(_c(seg) for seg in s.split("/"))

    results: List[Dict] = []
    seen: set = set()   # deduplicate by (clean_name, clean_path)

    like = f"%{q}%"

    # ── 1. extracted_files LIKE search ───────────────────────────────
    try:
        for r in db.execute(
            """SELECT file_id, name, full_path, file_type, size, allocated
               FROM extracted_files
               WHERE case_id = ?
                 AND (name LIKE ? COLLATE NOCASE OR full_path LIKE ? COLLATE NOCASE)
               ORDER BY CASE WHEN name LIKE ? COLLATE NOCASE THEN 0 ELSE 1 END, name ASC
               LIMIT ?""",
            (case_id, like, like, like, lim * 4)
        ):
            name = _c(r.get("name", "") or "")
            fp   = _cp(r.get("full_path", "") or "")
            key  = (name.lower(), fp.lower())
            if not name or key in seen:
                continue
            seen.add(key)
            size = r.get("size", 0) or 0
            alloc = r.get("allocated", 1)
            size_str = (f"{size}B" if size < 1024
                        else f"{size//1024}KB" if size < 1048576
                        else f"{size//1048576}MB") if size else ""
            results.append({
                "file_id":   r.get("file_id", ""),
                "name":      name,
                "full_path": fp,
                "source":    "disk",
                "snippet":   f"{fp}  {size_str}{'  [DELETED]' if alloc==0 else ''}".strip(),
                "file_type": r.get("file_type", "FILE"),
                "size":      size,
                "allocated": alloc,
            })
            if len(results) >= lim:
                break
    except Exception as e:
        log.warning(f"extracted_files search error: {e}")

    # ── 2. FTS index (text content) ───────────────────────────────────
    if len(results) < lim:
        fts_ids = {r["file_id"] for r in results}
        tokens  = [t for t in q.split() if t]
        try:
            fts_rows = db.execute(
                "SELECT file_id, name, full_path, source, "
                "snippet(fts_index, 5, '<<', '>>', '...', 20) as snip "
                "FROM fts_index WHERE case_id=? AND content MATCH ? "
                "ORDER BY rank LIMIT ?",
                (case_id, " OR ".join(f'"{t}"' for t in tokens), lim - len(results))
            )
            for r in fts_rows:
                if r.get("file_id") in fts_ids:
                    continue
                name = _c(r.get("name", "") or "")
                fp   = _cp(r.get("full_path", "") or "")
                key  = (name.lower(), fp.lower())
                if key in seen:
                    continue
                seen.add(key)
                fts_ids.add(r.get("file_id", ""))
                results.append({
                    "file_id":   r.get("file_id", ""),
                    "name":      name,
                    "full_path": fp,
                    "source":    r.get("source", "disk"),
                    "snippet":   _c(r.get("snip", "")),
                    "file_type": "FILE",
                    "size":      0,
                    "allocated": 1,
                })
        except Exception:
            pass

    # ── 3. YARA / IOC ────────────────────────────────────────────────
    try:
        for r in db.execute(
            """SELECT ioc_id, rule_name, indicator, tags, source_artifact
               FROM ioc_matches WHERE case_id=?
               AND (rule_name LIKE ? COLLATE NOCASE
                    OR indicator LIKE ? COLLATE NOCASE
                    OR tags LIKE ? COLLATE NOCASE)
               LIMIT 50""",
            (case_id, like, like, like)
        ):
            results.append({
                "file_id":   r.get("ioc_id", ""),
                "name":      _c(r.get("rule_name", "")),
                "full_path": _c(r.get("source_artifact", "")),
                "source":    "yara",
                "snippet":   f"indicator: {_c(r.get('indicator',''))}  tags: {_c(r.get('tags',''))}",
                "file_type": "YARA", "size": 0, "allocated": 1,
            })
    except Exception:
        pass

    # ── 4. Memory artifacts ───────────────────────────────────────────
    try:
        for r in db.execute(
            "SELECT artifact_id, plugin, details FROM memory_artifacts "
            "WHERE case_id=? AND (plugin LIKE ? OR details LIKE ?) LIMIT 50",
            (case_id, like, like)
        ):
            results.append({
                "file_id":   r.get("artifact_id", ""),
                "name":      _c(r.get("plugin", "")),
                "full_path": "",
                "source":    "memory",
                "snippet":   _c((r.get("details") or "")[:200]),
                "file_type": "MEM", "size": 0, "allocated": 1,
            })
    except Exception:
        pass

    return {"query": q, "count": len(results), "results": results}

@app.post("/api/cases/{case_id}/report", tags=["Reports"])
async def generate_report(case_id: str, report_type: str = "full", fmt: str = "json"):
    return ReportEngine(case_id).generate(report_type, fmt)

@app.get("/api/cases/{case_id}/coc", tags=["Integrity"])
async def get_coc(case_id: str):
    return CaseDatabase(case_id).execute("SELECT * FROM chain_of_custody WHERE case_id=? ORDER BY ts ASC", (case_id,))

@app.get("/api/cases/{case_id}/ai-scores", tags=["AI"])
async def get_ai_scores(case_id: str, limit: int = 200):
    rows = CaseDatabase(case_id).execute(
        "SELECT * FROM ai_risk_scores WHERE case_id=? ORDER BY score DESC LIMIT ?",
        (case_id, limit)
    )
    for r in rows:
        try:
            r["features"] = json.loads(r["features"] or "{}")
        except Exception:
            r["features"] = {}
    return rows

@app.post("/api/cases/{case_id}/ai-scores/run", tags=["AI"])
async def run_ai_scoring(case_id: str):
    """Re-run AI scoring on demand without full triage."""
    try:
        ai = AIAnomalyEngine(case_id)
        results = ai.run()
        flagged = sum(1 for r in results if r["final_score"] >= 35)
        return {"scored": len(results), "flagged": flagged,
                "critical": sum(1 for r in results if r["classification"] == "CRITICAL"),
                "high":     sum(1 for r in results if r["classification"] == "HIGH")}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/file-bytes")
async def get_file_bytes(path: str, offset: int = 0, length: int = 256):
    """Read raw bytes from an extracted file for the hex viewer."""
    try:
        safe_path = Path(path).resolve()
        # Only allow reading files inside the cases directory
        cases_abs = CASES_DIR.resolve()
        if not str(safe_path).startswith(str(cases_abs)):
            raise HTTPException(403, "Access denied: path outside cases directory")
        if not safe_path.exists():
            raise HTTPException(404, f"File not found: {path}")
        length = min(length, 4096)  # cap at 4 KB per request
        with open(safe_path, "rb") as f:
            f.seek(offset)
            raw = f.read(length)
        return {"offset": offset, "length": len(raw), "bytes": list(raw)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/health")
async def health():
    return {"status": "healthy", "version": TOOL_VERSION,
            "engines": {"pytsk3": PYTSK3_AVAILABLE, "yara": YARA_AVAILABLE, "sklearn": SKLEARN_AVAILABLE},
            "timestamp": _now()}

# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print(f"""
╔══════════════════════════════════════════════╗
║  Forensic Cyber Triage Tool (FCTT) v{TOOL_VERSION}  ║
║  API Docs: http://127.0.0.1:8765/api/docs   ║
╚══════════════════════════════════════════════╝
""")
    uvicorn.run("main:app", host="127.0.0.1", port=8765, reload=True)
