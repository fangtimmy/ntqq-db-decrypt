"""Minimal ctypes binding for SQLCipher, tuned for NTQQ databases.

NTQQ wraps each SQLCipher database in a 1024-byte custom header and uses the
SQLCipher 3-era parameters (page size 4096, 4000 KDF iterations, HMAC-SHA1,
PBKDF2-HMAC-SHA512).  The key is passed to sqlite3_key as the raw-key string
``x'<64 hex key><32 hex salt>'``.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from pathlib import Path
from typing import Any, Iterable

SQLITE_OK = 0
SQLITE_ROW = 100
SQLITE_DONE = 101
SQLITE_OPEN_READONLY = 0x00000001
SQLITE_OPEN_READWRITE = 0x00000002
SQLITE_OPEN_CREATE = 0x00000004

SQLITE_INTEGER = 1
SQLITE_FLOAT = 2
SQLITE_TEXT = 3
SQLITE_BLOB = 4
SQLITE_NULL = 5

NTQQ_PRAGMAS = (
    "PRAGMA cipher_page_size=4096;",
    "PRAGMA kdf_iter=4000;",
    "PRAGMA cipher_hmac_algorithm=HMAC_SHA1;",
    "PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512;",
)


class SqlCipherError(RuntimeError):
    pass


def _library_candidates() -> Iterable[str]:
    env = os.environ.get("QQDB_LIBSQLCIPHER")
    if env:
        yield env
    found = ctypes.util.find_library("sqlcipher")
    if found:
        yield found
    for path in (
        "/usr/lib/x86_64-linux-gnu/libsqlcipher.so.3",
        "/usr/lib/x86_64-linux-gnu/libsqlcipher.so",
        "/usr/local/lib/libsqlcipher.so",
    ):
        if Path(path).exists():
            yield path
    # Local, unprivileged extraction used during this session.
    for path in sorted(Path("/tmp/sqltool/root/usr/lib").glob("*/libsqlcipher.so.*")):
        yield str(path)


def load_library(path: str | None = None) -> ctypes.CDLL:
    errors: list[str] = []
    for candidate in ([path] if path else list(_library_candidates())):
        if not candidate:
            continue
        try:
            lib = ctypes.CDLL(candidate)
            _configure(lib)
            return lib
        except OSError as exc:
            errors.append(f"{candidate}: {exc}")
    raise SqlCipherError(
        "cannot load libsqlcipher; install libsqlcipher2 or set "
        "QQDB_LIBSQLCIPHER=/path/to/libsqlcipher.so. " + "; ".join(errors)
    )


def _configure(lib: ctypes.CDLL) -> None:
    c_void_p = ctypes.c_void_p
    c_int = ctypes.c_int
    c_char_p = ctypes.c_char_p

    lib.sqlite3_open_v2.argtypes = [c_char_p, ctypes.POINTER(c_void_p), c_int, c_char_p]
    lib.sqlite3_open_v2.restype = c_int
    lib.sqlite3_close.argtypes = [c_void_p]
    lib.sqlite3_close.restype = c_int
    lib.sqlite3_errmsg.argtypes = [c_void_p]
    lib.sqlite3_errmsg.restype = c_char_p
    lib.sqlite3_key.argtypes = [c_void_p, c_char_p, c_int]
    lib.sqlite3_key.restype = c_int
    lib.sqlite3_exec.argtypes = [c_void_p, c_char_p, c_void_p, c_void_p, ctypes.POINTER(c_char_p)]
    lib.sqlite3_exec.restype = c_int
    lib.sqlite3_prepare_v2.argtypes = [
        c_void_p, c_char_p, c_int, ctypes.POINTER(c_void_p), ctypes.POINTER(c_char_p)
    ]
    lib.sqlite3_prepare_v2.restype = c_int
    lib.sqlite3_step.argtypes = [c_void_p]
    lib.sqlite3_step.restype = c_int
    lib.sqlite3_finalize.argtypes = [c_void_p]
    lib.sqlite3_finalize.restype = c_int
    lib.sqlite3_column_count.argtypes = [c_void_p]
    lib.sqlite3_column_count.restype = c_int
    lib.sqlite3_column_name.argtypes = [c_void_p, c_int]
    lib.sqlite3_column_name.restype = c_char_p
    lib.sqlite3_column_type.argtypes = [c_void_p, c_int]
    lib.sqlite3_column_type.restype = c_int
    lib.sqlite3_column_int64.argtypes = [c_void_p, c_int]
    lib.sqlite3_column_int64.restype = ctypes.c_longlong
    lib.sqlite3_column_double.argtypes = [c_void_p, c_int]
    lib.sqlite3_column_double.restype = ctypes.c_double
    lib.sqlite3_column_text.argtypes = [c_void_p, c_int]
    lib.sqlite3_column_text.restype = c_void_p
    lib.sqlite3_column_blob.argtypes = [c_void_p, c_int]
    lib.sqlite3_column_blob.restype = c_void_p
    lib.sqlite3_column_bytes.argtypes = [c_void_p, c_int]
    lib.sqlite3_column_bytes.restype = c_int


class Database:
    """Read-only view of a decrypted NTQQ database copy."""

    def __init__(self, path: str | Path, key: str, *, lib: ctypes.CDLL | None = None):
        self.lib = lib or load_library()
        self.path = Path(path)
        self._db: ctypes.c_void_p | None = None
        self._open(key)

    def _open(self, key: str) -> None:
        db = ctypes.c_void_p()
        rc = self.lib.sqlite3_open_v2(
            str(self.path).encode(),
            ctypes.byref(db),
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
            None,
        )
        if rc != SQLITE_OK:
            raise SqlCipherError(f"cannot open {self.path}: {self._errmsg(db)}")
        self._db = db
        self._exec(NTQQ_PRAGMAS[0])
        key_bytes = key.encode()
        rc = self.lib.sqlite3_key(self._db, key_bytes, len(key_bytes))
        if rc != SQLITE_OK:
            raise SqlCipherError(f"sqlite3_key failed: {self._errmsg()}")
        for pragma in NTQQ_PRAGMAS[1:]:
            self._exec(pragma)
        # Force the first page read so that a wrong key fails here.
        self.query("SELECT count(*) FROM sqlite_master;")

    def _errmsg(self, db: ctypes.c_void_p | None = None) -> str:
        handle = db if db is not None else self._db
        if not handle:
            return "out of memory"
        msg = self.lib.sqlite3_errmsg(handle)
        return msg.decode("utf-8", "replace") if msg else "unknown error"

    def _exec(self, sql: str) -> None:
        err = ctypes.c_char_p()
        rc = self.lib.sqlite3_exec(self._db, sql.encode(), None, None, ctypes.byref(err))
        if rc != SQLITE_OK:
            detail = err.value.decode("utf-8", "replace") if err.value else self._errmsg()
            raise SqlCipherError(f"{sql!r} failed: {detail}")

    def query(self, sql: str) -> tuple[list[str], list[tuple[Any, ...]]]:
        stmt = ctypes.c_void_p()
        err = ctypes.c_char_p()
        rc = self.lib.sqlite3_prepare_v2(
            self._db, sql.encode(), -1, ctypes.byref(stmt), ctypes.byref(err)
        )
        if rc != SQLITE_OK:
            detail = err.value.decode("utf-8", "replace") if err.value else self._errmsg()
            raise SqlCipherError(f"prepare failed for {sql!r}: {detail}")
        try:
            count = self.lib.sqlite3_column_count(stmt)
            columns = [
                self.lib.sqlite3_column_name(stmt, i).decode("utf-8", "replace")
                for i in range(count)
            ]
            rows: list[tuple[Any, ...]] = []
            while True:
                rc = self.lib.sqlite3_step(stmt)
                if rc == SQLITE_ROW:
                    rows.append(tuple(self._value(stmt, i) for i in range(count)))
                elif rc == SQLITE_DONE:
                    break
                else:
                    raise SqlCipherError(f"step failed: {self._errmsg()}")
            return columns, rows
        finally:
            self.lib.sqlite3_finalize(stmt)

    def _value(self, stmt: ctypes.c_void_p, index: int) -> Any:
        kind = self.lib.sqlite3_column_type(stmt, index)
        if kind == SQLITE_NULL:
            return None
        if kind == SQLITE_INTEGER:
            return self.lib.sqlite3_column_int64(stmt, index)
        if kind == SQLITE_FLOAT:
            return self.lib.sqlite3_column_double(stmt, index)
        size = self.lib.sqlite3_column_bytes(stmt, index)
        if kind == SQLITE_TEXT:
            ptr = self.lib.sqlite3_column_text(stmt, index)
            return ctypes.string_at(ptr, size).decode("utf-8", "replace") if ptr else ""
        if kind == SQLITE_BLOB:
            ptr = self.lib.sqlite3_column_blob(stmt, index)
            return ctypes.string_at(ptr, size) if ptr else b""
        return None

    def tables(self) -> list[str]:
        _, rows = self.query(
            "SELECT name FROM sqlite_master "
            "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name;"
        )
        return [row[0] for row in rows]

    def export_plaintext(self, destination: str | Path) -> None:
        destination = Path(destination)
        if destination.exists():
            raise SqlCipherError(f"refusing to overwrite {destination}")
        self._exec(f"ATTACH DATABASE '{destination}' AS plaintext KEY '';")
        try:
            self._exec("SELECT sqlcipher_export('plaintext');")
        finally:
            self._exec("DETACH DATABASE plaintext;")

    def close(self) -> None:
        if self._db:
            self.lib.sqlite3_close(self._db)
            self._db = None

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
