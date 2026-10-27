"""Normalised message/conversation model and cross-database identity lookup."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from . import login, ntdb, schema
from .proto import Element, message_elements
from .sqlcipher import SqlCipherError


def _int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _iso(timestamp: int | None) -> str:
    if not timestamp:
        return ""
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class Directory:
    """Names resolved from login.db, profile_info.db and group_info.db."""

    self_uid: str | None = None
    self_uin: int | None = None
    self_name: str = ""
    nicknames: dict[str, str] = field(default_factory=dict)
    uins: dict[str, int] = field(default_factory=dict)
    groups: dict[str, str] = field(default_factory=dict)
    group_members: dict[tuple[str, str], str] = field(default_factory=dict)

    def chat_name(self, chat_type: str, chat_id: str) -> str:
        chat_id = str(chat_id)
        if chat_type == "group":
            return self.groups.get(chat_id) or f"群 {chat_id}"
        if self.self_uid and chat_id == self.self_uid:
            return f"{self.self_name}（自己）" if self.self_name else "自己"
        return self.nicknames.get(chat_id) or chat_id

    def sender_name(
        self,
        chat_type: str,
        chat_id: str,
        uid: str,
        fallback: str = "",
    ) -> str:
        if fallback:
            return fallback
        uid = str(uid or "")
        if uid and self.self_uid and uid == self.self_uid:
            return self.self_name or uid
        if chat_type == "group":
            name = self.group_members.get((str(chat_id), uid))
            if name:
                return name
        return self.nicknames.get(uid) or uid


def load_directory(account: ntdb.Account, entries: list[ntdb.KeyEntry]) -> Directory:
    identity = login.read_accounts().get(account.name, {})
    self_uid = str(identity.get("uid") or "") or None
    self_uin = _int(identity.get("uin"))
    self_name = str(identity.get("nickname") or "")
    directory = Directory(self_uid=self_uid, self_uin=self_uin, self_name=self_name)

    try:
        with ntdb.open_database(account, "profile_info.db", entries) as database:
            _, rows = database.query(
                'SELECT "1000","1002","20002","20009" FROM profile_info_v6;'
            )
            for uid, uin, nickname, remark in rows:
                if not uid:
                    continue
                uid = str(uid)
                name = str(remark or nickname or "").strip()
                if name:
                    directory.nicknames[uid] = name
                number = _int(uin)
                if number:
                    directory.uins[uid] = number
    except (LookupError, FileNotFoundError, SqlCipherError):
        pass

    try:
        with ntdb.open_database(account, "group_info.db", entries) as database:
            _, rows = database.query('SELECT "60001","60007" FROM group_list;')
            for code, name in rows:
                if code and name:
                    directory.groups[str(code)] = str(name)
            _, rows = database.query(
                'SELECT "60001","1000","64003","20002" FROM group_member3;'
            )
            for code, uid, card, nickname in rows:
                if not code or not uid:
                    continue
                name = str(card or nickname or "").strip()
                if name:
                    directory.group_members[(str(code), str(uid))] = name
    except (LookupError, FileNotFoundError, SqlCipherError):
        pass

    return directory


@dataclass
class Message:
    msg_id: int
    seq: int
    timestamp: int
    chat_type: str
    chat_id: str
    chat_name: str
    sender_uid: str
    sender_uin: int | None
    sender_name: str
    outgoing: bool
    msg_type: int
    sub_type: int
    elements: list[Element] = field(default_factory=list)

    @property
    def time(self) -> str:
        return _iso(self.timestamp)

    @property
    def text(self) -> str:
        rendered = " ".join(
            element.summary for element in self.elements if element.summary
        ).strip()
        if rendered:
            return rendered
        if self.msg_type == schema.MESSAGE_SYSTEM:
            return "[系统消息]"
        return ""

    @property
    def element_types(self) -> str:
        return ",".join(element.type for element in self.elements)

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "time": self.time,
            "chat_type": self.chat_type,
            "chat_id": self.chat_id,
            "chat_name": self.chat_name,
            "sender_uid": self.sender_uid,
            "sender_uin": self.sender_uin,
            "sender_name": self.sender_name,
            "outgoing": self.outgoing,
            "msg_type": self.msg_type,
            "sub_type": self.sub_type,
            "text": self.text,
            "elements": [element.to_dict() for element in self.elements],
        }


@dataclass
class Conversation:
    chat_type: str
    chat_id: str
    name: str
    messages: list[Message] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return (self.chat_type, self.chat_id)

    @property
    def count(self) -> int:
        return len(self.messages)

    @property
    def first_time(self) -> int:
        for message in self.messages:
            if message.timestamp > 0:
                return message.timestamp
        return 0

    @property
    def last_time(self) -> int:
        for message in reversed(self.messages):
            if message.timestamp > 0:
                return message.timestamp
        return 0

    @property
    def first_iso(self) -> str:
        return _iso(self.first_time)

    @property
    def last_iso(self) -> str:
        return _iso(self.last_time)


def parse_message_row(row: dict[str, Any], directory: Directory) -> Message | None:
    chat_type_number = _int(row.get(schema.CHAT_TYPE))
    if chat_type_number == schema.CHAT_TYPE_GROUP:
        chat_type = "group"
    elif chat_type_number == schema.CHAT_TYPE_C2C:
        chat_type = "c2c"
    else:
        chat_type = "other"

    chat_id = str(row.get(schema.CHAT_UID) or row.get(schema.CHAT_UIN) or "").strip()
    sender_uid = str(row.get(schema.SENDER_UID) or "").strip()
    if not chat_id:
        return None

    msg_id = _int(row.get(schema.MSG_ID)) or 0
    seq = _int(row.get(schema.MSG_SEQ)) or 0
    timestamp = _int(row.get(schema.MSG_TIME)) or 0
    msg_type = _int(row.get(schema.MSG_TYPE)) or 0
    sub_type = _int(row.get(schema.MSG_SUB_TYPE)) or 0

    outgoing = bool(directory.self_uid and sender_uid == directory.self_uid)
    if not outgoing and _int(row.get(schema.DIRECTION)) == 1:
        outgoing = True
    if not outgoing and _int(row.get(schema.SENDER_FLAG)) == 1:
        outgoing = True

    display_name = str(
        row.get(schema.SENDER_NAME) or row.get(schema.SENDER_REMARK) or ""
    ).strip()
    sender_name = directory.sender_name(
        chat_type, chat_id, sender_uid, fallback=display_name
    )
    if msg_type == schema.MESSAGE_SYSTEM and not display_name:
        sender_name = "系统"
    if not sender_name:
        sender_name = sender_uid or "系统"
    chat_name = directory.chat_name(chat_type, chat_id)

    content = row.get(schema.CONTENT)
    elements = message_elements(content if isinstance(content, bytes) else None)

    return Message(
        msg_id=msg_id,
        seq=seq,
        timestamp=timestamp,
        chat_type=chat_type,
        chat_id=chat_id,
        chat_name=chat_name,
        sender_uid=sender_uid,
        sender_uin=_int(row.get(schema.SENDER_UIN)),
        sender_name=sender_name or sender_uid,
        outgoing=outgoing,
        msg_type=msg_type,
        sub_type=sub_type,
        elements=elements,
    )


def collect_conversations(
    account: ntdb.Account,
    entries: list[ntdb.KeyEntry],
    directory: Directory | None = None,
    *,
    kind: str = "all",
    since: int | None = None,
    until: int | None = None,
    limit_per_chat: int | None = None,
) -> list[Conversation]:
    directory = directory or load_directory(account, entries)
    tables: list[tuple[str, str]] = []
    if kind in ("all", "c2c"):
        tables.append(("c2c", "c2c_msg_table"))
    if kind in ("all", "group"):
        tables.append(("group", "group_msg_table"))

    conditions: list[str] = []
    if since:
        conditions.append(f'"{schema.MSG_TIME}" >= {int(since)}')
    if until:
        conditions.append(f'"{schema.MSG_TIME}" <= {int(until)}')
    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

    buckets: dict[tuple[str, str], Conversation] = {}
    seen: set[tuple[str, int]] = set()

    with ntdb.open_database(account, "nt_msg.db", entries) as database:
        for _kind, table in tables:
            columns, rows = database.query(
                f'SELECT * FROM "{table}"{where} ORDER BY "{schema.MSG_TIME}" ASC;'
            )
            for values in rows:
                row = dict(zip(columns, values))
                message = parse_message_row(row, directory)
                if message is None:
                    continue
                key = (message.chat_type, message.chat_id)
                dedupe = (key, message.msg_id)
                if message.msg_id and dedupe in seen:
                    continue
                if message.msg_id:
                    seen.add(dedupe)
                conversation = buckets.get(key)
                if conversation is None:
                    conversation = Conversation(
                        chat_type=message.chat_type,
                        chat_id=message.chat_id,
                        name=message.chat_name,
                    )
                    buckets[key] = conversation
                conversation.messages.append(message)

    result: list[Conversation] = []
    for conversation in buckets.values():
        conversation.messages.sort(
            key=lambda message: (message.timestamp, message.seq, message.msg_id)
        )
        if limit_per_chat:
            conversation.messages = conversation.messages[-limit_per_chat:]
        if conversation.messages:
            conversation.name = conversation.messages[0].chat_name or conversation.name
            result.append(conversation)

    result.sort(key=lambda conversation: (-conversation.last_time, conversation.name))
    return result


def filter_conversations(
    conversations: Iterable[Conversation], query: str
) -> list[Conversation]:
    query = query.strip().lower()
    if not query:
        return list(conversations)
    matched: list[Conversation] = []
    for conversation in conversations:
        haystacks = (
            conversation.chat_id.lower(),
            conversation.name.lower(),
        )
        if any(query == value or query in value for value in haystacks):
            matched.append(conversation)
        elif conversation.chat_id.lower().endswith(query):
            matched.append(conversation)
    return matched
