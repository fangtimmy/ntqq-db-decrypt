"""Per-conversation export to TXT, CSV, JSON and JSONL."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .model import Conversation, Message

FORMATS = ("txt", "csv", "json", "jsonl")
_ILLEGAL = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def safe_name(value: str, fallback: str = "chat", max_length: int = 80) -> str:
    cleaned = _ILLEGAL.sub("_", value).strip().strip(".")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        cleaned = fallback
    return cleaned[:max_length].rstrip(" .") or fallback


def _directory_name(conversation: Conversation, used: set[str]) -> str:
    suffix = conversation.chat_id[-8:] if conversation.chat_id else "unknown"
    base = safe_name(f"{conversation.chat_type}-{conversation.name}-{suffix}")
    candidate = base
    index = 2
    while candidate in used:
        candidate = f"{base}-{index}"
        index += 1
    used.add(candidate)
    return candidate


def _first_element(message: Message, element_type: str) -> dict[str, Any]:
    for element in message.elements:
        if element.type == element_type:
            return element.data
    return {}


def _csv_row(message: Message) -> dict[str, Any]:
    image = _first_element(message, "image")
    file = _first_element(message, "file")
    ark = _first_element(message, "ark") or _first_element(message, "news")
    return {
        "time": message.time,
        "timestamp": message.timestamp,
        "msg_id": message.msg_id,
        "seq": message.seq,
        "chat_type": message.chat_type,
        "chat_id": message.chat_id,
        "chat_name": message.chat_name,
        "sender_uid": message.sender_uid,
        "sender_uin": message.sender_uin if message.sender_uin is not None else "",
        "sender_name": message.sender_name,
        "outgoing": 1 if message.outgoing else 0,
        "msg_type": message.msg_type,
        "sub_type": message.sub_type,
        "element_types": message.element_types,
        "text": message.text,
        "file_name": file.get("file_name") or image.get("file_name") or "",
        "file_size": file.get("size") or image.get("size") or "",
        "image_width": image.get("width") or "",
        "image_height": image.get("height") or "",
        "image_md5": image.get("md5") or "",
        "urls": ";".join(image.get("urls") or []),
        "local_path": file.get("local_path") or image.get("local_path") or "",
        "ark_title": ark.get("title") or "",
        "ark_url": ark.get("url") or "",
        "elements_json": json.dumps(
            [element.to_dict() for element in message.elements], ensure_ascii=False
        ),
    }


CSV_FIELDS = [
    "time",
    "timestamp",
    "msg_id",
    "seq",
    "chat_type",
    "chat_id",
    "chat_name",
    "sender_uid",
    "sender_uin",
    "sender_name",
    "outgoing",
    "msg_type",
    "sub_type",
    "element_types",
    "text",
    "file_name",
    "file_size",
    "image_width",
    "image_height",
    "image_md5",
    "urls",
    "local_path",
    "ark_title",
    "ark_url",
    "elements_json",
]


def _write_txt(path: Path, conversation: Conversation) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for message in conversation.messages:
            text = (message.text or "").replace("\r\n", "\n").replace("\n", "\\n")
            handle.write(f"[{message.time}] {message.sender_name}: {text}\n")


def _write_csv(path: Path, conversation: Conversation) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for message in conversation.messages:
            writer.writerow(_csv_row(message))


def _write_json(path: Path, conversation: Conversation) -> None:
    payload = [message.to_dict() for message in conversation.messages]
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _write_jsonl(path: Path, conversation: Conversation) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for message in conversation.messages:
            handle.write(json.dumps(message.to_dict(), ensure_ascii=False) + "\n")


def _normalise_formats(formats: str | Iterable[str]) -> set[str]:
    if isinstance(formats, str):
        requested = {item.strip().lower() for item in formats.split(",") if item.strip()}
    else:
        requested = {str(item).strip().lower() for item in formats if str(item).strip()}
    unknown = requested - set(FORMATS)
    if unknown:
        raise ValueError(f"unknown export formats: {', '.join(sorted(unknown))}")
    if not requested:
        raise ValueError("at least one export format is required")
    return requested


def export_conversations(
    conversations: Iterable[Conversation],
    output_dir: str | Path,
    *,
    formats: str | Iterable[str] = FORMATS,
    overwrite: bool = False,
) -> dict[str, Any]:
    chosen = _normalise_formats(formats)
    out = Path(output_dir).expanduser().resolve()
    if out.exists() and any(out.iterdir()) and not overwrite:
        raise FileExistsError(f"output directory is not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    chats_dir = out / "chats"
    chats_dir.mkdir(exist_ok=True)

    used: set[str] = set()
    index_rows: list[dict[str, Any]] = []
    message_total = 0
    conversation_list = [item for item in conversations if item.messages]

    for conversation in conversation_list:
        directory = _directory_name(conversation, used)
        target = chats_dir / directory
        target.mkdir(parents=True, exist_ok=True)
        if "txt" in chosen:
            _write_txt(target / "chat.txt", conversation)
        if "csv" in chosen:
            _write_csv(target / "chat.csv", conversation)
        if "json" in chosen:
            _write_json(target / "chat.json", conversation)
        if "jsonl" in chosen:
            _write_jsonl(target / "chat.jsonl", conversation)
        message_total += conversation.count
        index_rows.append(
            {
                "chat_type": conversation.chat_type,
                "chat_id": conversation.chat_id,
                "chat_name": conversation.name,
                "message_count": conversation.count,
                "first_time": conversation.first_iso,
                "last_time": conversation.last_iso,
                "directory": f"chats/{directory}",
            }
        )

    with (out / "index.csv").open("w", encoding="utf-8", newline="") as handle:
        fields = [
            "chat_type",
            "chat_id",
            "chat_name",
            "message_count",
            "first_time",
            "last_time",
            "directory",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(index_rows)

    return {
        "output": str(out),
        "conversations": len(conversation_list),
        "messages": message_total,
        "formats": sorted(chosen),
    }
