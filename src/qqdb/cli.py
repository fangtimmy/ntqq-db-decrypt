"""Command line interface for the QQ database reader."""

from __future__ import annotations

import argparse
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import login, memscan, ntdb
from . import text as message_text
from .sqlcipher import Database, SqlCipherError


def _scan_entries() -> tuple[list[int], list[ntdb.KeyEntry]]:
    pids, candidates = memscan.scan()
    return pids, ntdb.key_entries(candidates)


def _matched_databases(account: ntdb.Account, entries: list[ntdb.KeyEntry]) -> list[tuple[Path, str | None]]:
    result = []
    for db_path in account.databases():
        salt = ntdb.database_salt(db_path)
        result.append((db_path, salt))
    return result


def _pick_account(
    accounts: Sequence[ntdb.Account], entries: list[ntdb.KeyEntry], needle: str | None
) -> ntdb.Account:
    if needle:
        return ntdb.resolve_account(list(accounts), needle)
    scored = []
    for account in accounts:
        score = 0
        for db_path, salt in _matched_databases(account, entries):
            if salt and ntdb.key_for_salt(entries, salt):
                score += 1
        scored.append((score, account))
    scored.sort(key=lambda item: item[0], reverse=True)
    if not scored or scored[0][0] == 0:
        raise SystemExit("no account has recoverable keys in memory; is QQ running and logged in?")
    return scored[0][1]


@contextmanager
def open_database(account: ntdb.Account, db_name: str, entries: list[ntdb.KeyEntry]):
    db_path = account.db_dir / db_name
    if not db_path.is_file():
        raise SystemExit(f"database not found: {db_path}")
    salt = ntdb.database_salt(db_path)
    entry = ntdb.key_for_salt(entries, salt) if salt else None
    if entry is None:
        raise SystemExit(
            f"no key in process memory for {db_path.name} (salt={salt}); "
            "this account is probably logged out"
        )
    copy = ntdb.DecryptedCopy(db_path)
    database: Database | None = None
    try:
        database = Database(copy.path, entry.key)
        yield database
    finally:
        if database is not None:
            database.close()
        copy.cleanup()


def _format_cell(value: Any, full: bool) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bytes):
        return f"<blob {len(value)} bytes>" if not full else value.hex()
    text = str(value)
    if not full and len(text) > 120:
        text = text[:117] + "..."
    return text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")


def _print_table(columns: Sequence[str], rows: Iterable[Sequence[Any]], full: bool) -> None:
    rows = [list(row) for row in rows]
    text_rows = [[_format_cell(value, full) for value in row] for row in rows]
    widths = [len(column) for column in columns]
    for row in text_rows:
        for index, cell in enumerate(row):
            widths[index] = min(max(widths[index], len(cell)), 60)
    print(" | ".join(column.ljust(widths[index]) for index, column in enumerate(columns)))
    print("-+-".join("-" * width for width in widths))
    for row in text_rows:
        print(" | ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))


def cmd_scan(args: argparse.Namespace) -> int:
    pids, entries = _scan_entries()
    print(f"QQ processes scanned: {', '.join(map(str, pids)) or 'none'}")
    print(f"raw key strings found: {len(entries)}")
    if args.show_keys:
        for entry in entries:
            print(f"  pid={entry.pid} addr={entry.address:#x} {entry.key}")

    identities = login.read_accounts()
    accounts = ntdb.accounts()
    if not accounts:
        print(f"no account directories under {ntdb.QQ_CONFIG}")
        return 1
    for account in accounts:
        matched = 0
        total = 0
        details = []
        for db_path, salt in _matched_databases(account, entries):
            if not salt:
                continue
            total += 1
            entry = ntdb.key_for_salt(entries, salt)
            if entry:
                matched += 1
            details.append((db_path.name, bool(entry)))
        marker = "  <-- current" if matched == total and total else ""
        identity = login.label(identities.get(account.name))
        suffix = f"  [{identity}]" if identity else ""
        print(f"\n{account.name}: {matched}/{total} databases have keys{marker}{suffix}")
        for name, ok in details:
            print(f"  {'OK ' if ok else '-- '}{name}")
    return 0


def cmd_accounts(_args: argparse.Namespace) -> int:
    pids, entries = _scan_entries()
    identities = login.read_accounts()
    accounts = ntdb.accounts()
    print(f"QQ pids: {', '.join(map(str, pids)) or 'none'}; keys: {len(entries)}")
    for account in accounts:
        identity = login.label(identities.get(account.name))
        print(f"\n{account.name}" + (f"  [{identity}]" if identity else ""))
        for db_path, salt in _matched_databases(account, entries):
            entry = ntdb.key_for_salt(entries, salt) if salt else None
            print(f"  {db_path.name:28} salt={salt or '-':32} key={'yes' if entry else 'no'}")
    return 0


def cmd_tables(args: argparse.Namespace) -> int:
    _, entries = _scan_entries()
    account = _pick_account(ntdb.accounts(), entries, args.account)
    with open_database(account, args.db, entries) as database:
        tables = database.tables()
        if args.counts:
            print(f"{'table':40} rows")
            for name in tables:
                _, rows = database.query(f'SELECT count(*) FROM "{name}";')
                print(f"{name:40} {rows[0][0]}")
        else:
            for name in tables:
                print(name)
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    _, entries = _scan_entries()
    account = _pick_account(ntdb.accounts(), entries, args.account)
    with open_database(account, args.db, entries) as database:
        columns, rows = database.query(args.sql)
        _print_table(columns, rows[: args.limit], args.full)
        if len(rows) > args.limit:
            print(f"... {len(rows) - args.limit} more rows (use --limit)")
    return 0


def _load_name_maps(account: ntdb.Account, entries: list[ntdb.KeyEntry]):
    nicknames: dict[str, str] = {}
    with open_database(account, "profile_info.db", entries) as database:
        _, rows = database.query('SELECT "1000","20002" FROM profile_info_v6;')
        for uid, nickname in rows:
            if uid and nickname:
                nicknames[str(uid)] = str(nickname)
    groups: dict[str, str] = {}
    with open_database(account, "group_info.db", entries) as database:
        _, rows = database.query('SELECT "60001","60007" FROM group_list;')
        for code, name in rows:
            if code and name:
                groups[str(code)] = str(name)
    return nicknames, groups


def cmd_messages(args: argparse.Namespace) -> int:
    _, entries = _scan_entries()
    account = _pick_account(ntdb.accounts(), entries, args.account)
    nicknames, groups = _load_name_maps(account, entries)
    tables = []
    if args.kind in ("c2c", "all"):
        tables.append(("c2c", "c2c_msg_table"))
    if args.kind in ("group", "all"):
        tables.append(("group", "group_msg_table"))

    collected: list[tuple[int, str, tuple[Any, ...]]] = []
    with open_database(account, "nt_msg.db", entries) as database:
        for kind, table in tables:
            _, rows = database.query(
                f'SELECT "40001","40050","40011","40020","40021","40800" '
                f'FROM "{table}" ORDER BY "40050" DESC LIMIT {args.limit};'
            )
            for row in rows:
                collected.append((int(row[1] or 0), kind, row))
    collected.sort(key=lambda item: item[0], reverse=True)

    rendered = []
    for timestamp, kind, row in collected[: args.limit]:
        when = (
            datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            if timestamp > 0
            else "-"
        )
        body = row[5] if isinstance(row[5], (bytes, bytearray)) else b""
        extracted = message_text.join_text(body, max_items=1000 if args.full else 6)
        sender = str(row[3] or "")
        chat = str(row[4] or "")
        sender = nicknames.get(sender, sender)
        chat = groups.get(chat, chat) if kind == "group" else nicknames.get(chat, chat)
        rendered.append((when, kind, sender, chat, row[2], extracted or "(no text)"))
    _print_table(("time", "kind", "sender_uid", "chat", "type", "text"), rendered, True)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    _, entries = _scan_entries()
    account = _pick_account(ntdb.accounts(), entries, args.account)
    destination = Path(args.out).expanduser().resolve()
    if destination.exists():
        raise SystemExit(f"refusing to overwrite {destination}")
    with open_database(account, args.db, entries) as database:
        database.export_plaintext(destination)
    print(f"exported plaintext SQLite database to {destination}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    pids, entries = _scan_entries()
    account = _pick_account(ntdb.accounts(), entries, args.account)
    identity = login.label(login.read_accounts().get(account.name))
    print(f"account directory: {account.directory}")
    if identity:
        print(f"account: {identity}")
    print(f"qq pids: {', '.join(map(str, pids))}")
    db_path = account.db_dir / args.db
    salt = ntdb.database_salt(db_path) if db_path.exists() else None
    entry = ntdb.key_for_salt(entries, salt) if salt else None
    print(f"database: {db_path}")
    print(f"salt: {salt}")
    print(f"key recovered: {'yes' if entry else 'no'}")
    if entry:
        with open_database(account, args.db, entries) as database:
            columns, rows = database.query("PRAGMA page_count;")
            print(f"pages: {rows[0][0] if rows else '?'}")
            print(f"tables: {len(database.tables())}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qqdb",
        description="Read NTQQ SQLCipher databases using a read-only memory scan "
        "(no injection, no hooks).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan QQ processes and report recoverable keys")
    scan.add_argument("--show-keys", action="store_true", help="print full key strings")
    scan.set_defaults(func=cmd_scan)

    accounts = sub.add_parser("accounts", help="show account databases and key status")
    accounts.set_defaults(func=cmd_accounts)

    info = sub.add_parser("info", help="show details for one database")
    info.add_argument("--account", help="account directory name or unique substring")
    info.add_argument("--db", default="nt_msg.db")
    info.set_defaults(func=cmd_info)

    tables = sub.add_parser("tables", help="list tables in a database")
    tables.add_argument("--account", help="account directory name or unique substring")
    tables.add_argument("--db", default="nt_msg.db")
    tables.add_argument("--counts", action="store_true", help="also count rows per table")
    tables.set_defaults(func=cmd_tables)

    query = sub.add_parser("query", help="run a read-only SQL query")
    query.add_argument("sql")
    query.add_argument("--account", help="account directory name or unique substring")
    query.add_argument("--db", default="nt_msg.db")
    query.add_argument("--limit", type=int, default=20)
    query.add_argument("--full", action="store_true", help="do not truncate cell values")
    query.set_defaults(func=cmd_query)

    messages = sub.add_parser("messages", help="show recent messages with extracted text")
    messages.add_argument("--account", help="account directory name or unique substring")
    messages.add_argument("--kind", choices=("c2c", "group", "all"), default="all")
    messages.add_argument("--limit", type=int, default=20)
    messages.add_argument("--full", action="store_true", help="do not truncate extracted strings")
    messages.set_defaults(func=cmd_messages)

    export = sub.add_parser("export", help="export a decrypted copy as plain SQLite")
    export.add_argument("--out", required=True)
    export.add_argument("--account", help="account directory name or unique substring")
    export.add_argument("--db", default="nt_msg.db")
    export.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (SqlCipherError, LookupError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
