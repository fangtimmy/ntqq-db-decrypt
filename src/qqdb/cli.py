"""Command line interface for the QQ database reader and exporter."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import export, login, memscan, model, ntdb
from .ntdb import open_database
from .sqlcipher import SqlCipherError


def _scan_entries() -> tuple[list[int], list[ntdb.KeyEntry]]:
    pids, candidates = memscan.scan()
    return pids, ntdb.key_entries(candidates)


def _matched_databases(account: ntdb.Account) -> list[tuple[Path, str | None]]:
    return [(db_path, ntdb.database_salt(db_path)) for db_path in account.databases()]


def _pick_account(
    accounts: Sequence[ntdb.Account], entries: list[ntdb.KeyEntry], needle: str | None
) -> ntdb.Account:
    if needle:
        return ntdb.resolve_account(list(accounts), needle)
    scored = []
    for account in accounts:
        score = 0
        for db_path, salt in _matched_databases(account):
            if salt and ntdb.key_for_salt(entries, salt):
                score += 1
        scored.append((score, account))
    scored.sort(key=lambda item: item[0], reverse=True)
    if not scored or scored[0][0] == 0:
        raise SystemExit("no account has recoverable keys in memory; is QQ running and logged in?")
    return scored[0][1]


def _parse_time(value: str | None) -> int | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return int(value)
    try:
        return int(datetime.fromisoformat(value).timestamp())
    except ValueError as exc:
        raise SystemExit(f"invalid time {value!r}; use unix seconds or YYYY-MM-DD[ HH:MM:SS]") from exc


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
        for db_path, salt in _matched_databases(account):
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
        for db_path, salt in _matched_databases(account):
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


def cmd_messages(args: argparse.Namespace) -> int:
    _, entries = _scan_entries()
    account = _pick_account(ntdb.accounts(), entries, args.account)
    directory = model.load_directory(account, entries)
    conversations = model.collect_conversations(
        account,
        entries,
        directory,
        kind=args.kind,
        since=_parse_time(args.since),
        until=_parse_time(args.until),
    )
    if args.chat:
        conversations = model.filter_conversations(conversations, args.chat)
        if not conversations:
            raise SystemExit(f"no conversation matches {args.chat!r}")
    messages = [message for conversation in conversations for message in conversation.messages]
    messages.sort(key=lambda message: (message.timestamp, message.seq), reverse=True)
    rows = [
        (message.time, message.chat_name, message.sender_name, message.msg_type, message.text)
        for message in messages[: args.limit]
    ]
    _print_table(("time", "chat", "sender", "type", "text"), rows, args.full)
    return 0


def cmd_chats(args: argparse.Namespace) -> int:
    _, entries = _scan_entries()
    account = _pick_account(ntdb.accounts(), entries, args.account)
    directory = model.load_directory(account, entries)
    conversations = model.collect_conversations(
        account,
        entries,
        directory,
        kind=args.kind,
        since=_parse_time(args.since),
        until=_parse_time(args.until),
        limit_per_chat=args.messages,
    )
    if args.search:
        conversations = model.filter_conversations(conversations, args.search)
    if args.limit:
        conversations = conversations[: args.limit]
    rows = [
        (
            conversation.chat_type,
            conversation.chat_id,
            conversation.name,
            conversation.count,
            conversation.first_iso,
            conversation.last_iso,
        )
        for conversation in conversations
    ]
    _print_table(("type", "chat_id", "name", "messages", "first", "last"), rows, True)
    print(
        f"\n{len(conversations)} conversations, "
        f"{sum(conversation.count for conversation in conversations)} messages"
    )
    return 0


def cmd_export_chats(args: argparse.Namespace) -> int:
    _, entries = _scan_entries()
    account = _pick_account(ntdb.accounts(), entries, args.account)
    directory = model.load_directory(account, entries)
    conversations = model.collect_conversations(
        account,
        entries,
        directory,
        kind=args.kind,
        since=_parse_time(args.since),
        until=_parse_time(args.until),
    )
    if args.chat:
        conversations = model.filter_conversations(conversations, args.chat)
        if not conversations:
            raise SystemExit(f"no conversation matches {args.chat!r}")
    result = export.export_conversations(
        conversations,
        args.out,
        formats=args.format,
        overwrite=args.force,
    )
    print(
        f"exported {result['messages']} messages from {result['conversations']} "
        f"conversations to {result['output']} ({', '.join(result['formats'])})"
    )
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
            _, rows = database.query("PRAGMA page_count;")
            print(f"pages: {rows[0][0] if rows else '?'}")
            print(f"tables: {len(database.tables())}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qqdb",
        description="Read and export NTQQ SQLCipher databases using a read-only "
        "memory scan (no injection, no hooks).",
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

    messages = sub.add_parser("messages", help="show recent messages with structured content")
    messages.add_argument("--account", help="account directory name or unique substring")
    messages.add_argument("--kind", choices=("c2c", "group", "all"), default="all")
    messages.add_argument("--chat", help="only this chat id, name or name substring")
    messages.add_argument("--limit", type=int, default=20)
    messages.add_argument("--since", help="unix seconds or ISO date/time")
    messages.add_argument("--until", help="unix seconds or ISO date/time")
    messages.add_argument("--full", action="store_true", help="do not truncate text")
    messages.set_defaults(func=cmd_messages)

    chats = sub.add_parser("chats", help="list conversations with message counts")
    chats.add_argument("--account", help="account directory name or unique substring")
    chats.add_argument("--kind", choices=("c2c", "group", "all"), default="all")
    chats.add_argument("--search", help="filter by chat name or id")
    chats.add_argument("--limit", type=int, default=50, help="maximum conversations to list")
    chats.add_argument("--messages", type=int, help="keep only the latest N messages per chat")
    chats.add_argument("--since", help="unix seconds or ISO date/time")
    chats.add_argument("--until", help="unix seconds or ISO date/time")
    chats.set_defaults(func=cmd_chats)

    export_chats = sub.add_parser(
        "export-chats", help="export conversations to TXT/CSV/JSON/JSONL"
    )
    export_chats.add_argument("--out", required=True, help="output directory")
    export_chats.add_argument("--account", help="account directory name or unique substring")
    export_chats.add_argument("--kind", choices=("c2c", "group", "all"), default="all")
    export_chats.add_argument("--chat", help="only this chat id, name or name substring")
    export_chats.add_argument("--format", default="txt,csv,json,jsonl")
    export_chats.add_argument("--since", help="unix seconds or ISO date/time")
    export_chats.add_argument("--until", help="unix seconds or ISO date/time")
    export_chats.add_argument("--force", action="store_true", help="allow a non-empty output directory")
    export_chats.set_defaults(func=cmd_export_chats)

    export_db = sub.add_parser("export", help="export a decrypted copy as plain SQLite")
    export_db.add_argument("--out", required=True)
    export_db.add_argument("--account", help="account directory name or unique substring")
    export_db.add_argument("--db", default="nt_msg.db")
    export_db.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (SqlCipherError, LookupError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
