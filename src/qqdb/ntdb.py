"""Helpers for NTQQ's on-disk layout: account directories, salts and headers."""

from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .sqlcipher import Database

QQ_CONFIG = Path.home() / ".config" / "QQ"
HEADER_SIZE = 1024
SALT_SIZE = 16


@dataclass(frozen=True)
class Account:
    directory: Path
    name: str

    @property
    def db_dir(self) -> Path:
        return self.directory / "nt_db"

    def databases(self) -> list[Path]:
        if not self.db_dir.is_dir():
            return []
        return sorted(p for p in self.db_dir.glob("*.db") if p.is_file())


@dataclass(frozen=True)
class KeyEntry:
    key: str
    salt: str
    pid: int
    address: int


def accounts(base: Path = QQ_CONFIG) -> list[Account]:
    if not base.is_dir():
        return []
    return [Account(path, path.name) for path in sorted(base.glob("nt_qq_*")) if path.is_dir()]


def resolve_account(accounts_: list[Account], needle: str) -> Account:
    exact = [account for account in accounts_ if account.name == needle]
    if exact:
        return exact[0]
    partial = [account for account in accounts_ if needle in account.name]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise LookupError(f"no account directory matches {needle!r}")
    names = ", ".join(account.name for account in partial)
    raise LookupError(f"ambiguous account {needle!r}; matches: {names}")


def database_salt(path: Path) -> str | None:
    try:
        if path.stat().st_size < HEADER_SIZE + SALT_SIZE:
            return None
        with path.open("rb") as handle:
            handle.seek(HEADER_SIZE)
            salt = handle.read(SALT_SIZE)
    except OSError:
        return None
    return salt.hex() if len(salt) == SALT_SIZE else None


def key_entries(candidates) -> list[KeyEntry]:
    entries: list[KeyEntry] = []
    for candidate in candidates:
        body = candidate.key[2:-1]
        if len(body) < 32:
            continue
        entries.append(
            KeyEntry(
                key=candidate.key,
                salt=body[-32:].lower(),
                pid=candidate.pid,
                address=candidate.address,
            )
        )
    return entries


def key_for_salt(entries: list[KeyEntry], salt: str) -> KeyEntry | None:
    salt = salt.lower()
    for entry in entries:
        if entry.salt == salt:
            return entry
    return None


class DecryptedCopy:
    """A temporary, header-stripped copy of a database (plus its WAL)."""
    def __init__(self, source: Path, workdir: Path | None = None):
        self.source = source
        self._tempdir = Path(tempfile.mkdtemp(prefix="qqdb-", dir=workdir))
        self.path = self._tempdir / source.name
        with source.open("rb") as src:
            src.seek(HEADER_SIZE)
            with self.path.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1 << 20)
        for suffix in ("-wal",):
            sidecar = source.with_name(source.name + suffix)
            if sidecar.exists():
                shutil.copy2(sidecar, self.path.with_name(self.path.name + suffix))

    def cleanup(self) -> None:
        shutil.rmtree(self._tempdir, ignore_errors=True)

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *exc: object) -> None:
        self.cleanup()


@contextmanager
def open_database(account: Account, db_name: str, entries: list[KeyEntry]):
    """Yield a decrypted :class:`Database` for one account database."""
    db_path = account.db_dir / db_name
    if not db_path.is_file():
        raise FileNotFoundError(f"database not found: {db_path}")
    salt = database_salt(db_path)
    entry = key_for_salt(entries, salt) if salt else None
    if entry is None:
        raise LookupError(
            f"no key in process memory for {db_path.name} (salt={salt}); "
            "this account is probably logged out"
        )
    copy = DecryptedCopy(db_path)
    database: Database | None = None
    try:
        database = Database(copy.path, entry.key)
        yield database
    finally:
        if database is not None:
            database.close()
        copy.cleanup()

