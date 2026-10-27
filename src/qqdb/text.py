"""Extract human-readable strings from NTQQ protobuf message blobs.

NTQQ stores message elements as protobuf messages in column ``40800``.  A full
schema is version-dependent, so this module walks the protobuf wire format and
collects length-delimited strings that look like text.  It is intentionally
heuristic: it is enough to read ordinary text messages, file names and card
titles, not a complete element parser.
"""

from __future__ import annotations

from typing import Iterable


def _varint(buffer: bytes, position: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while position < len(buffer):
        byte = buffer[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, position
        shift += 7
        if shift > 63:
            break
    raise ValueError("truncated varint")


def _is_text(text: str) -> bool:
    stripped = text.strip()
    if len(stripped) < 2:
        return False
    printable = sum(1 for char in stripped if char.isprintable())
    if printable / len(stripped) < 0.85:
        return False
    return any(char.isalnum() or "\u4e00" <= char <= "\u9fff" for char in stripped)


def _walk(buffer: bytes, depth: int, output: list[str]) -> None:
    position = 0
    while position < len(buffer):
        try:
            key, position = _varint(buffer, position)
        except ValueError:
            return
        wire_type = key & 0x07
        field = key >> 3
        if field == 0:
            return
        if wire_type == 0:
            try:
                _, position = _varint(buffer, position)
            except ValueError:
                return
        elif wire_type == 1:
            position += 8
        elif wire_type == 2:
            try:
                length, position = _varint(buffer, position)
            except ValueError:
                return
            if length < 0 or position + length > len(buffer):
                return
            chunk = buffer[position : position + length]
            position += length
            text = None
            try:
                text = chunk.decode("utf-8")
            except UnicodeDecodeError:
                pass
            if text is not None and _is_text(text):
                output.append(text)
            elif depth < 6 and len(chunk) > 1:
                _walk(chunk, depth + 1, output)
        elif wire_type == 5:
            position += 4
        else:
            return


def _is_noise(text: str) -> bool:
    if text.startswith(("/download?", "http://", "https://")):
        return True
    body = text.replace("-", "").replace("_", "")
    if len(body) >= 24 and body.isalnum() and not any(
        "\u4e00" <= char <= "\u9fff" for char in text
    ):
        return True
    return False


def extract(blob: bytes) -> list[str]:
    if not blob:
        return []
    output: list[str] = []
    _walk(blob, 0, output)
    seen: set[str] = set()
    result: list[str] = []
    for item in output:
        text = item.strip()
        if text not in seen and not _is_noise(text):
            seen.add(text)
            result.append(text)
    return result


def join_text(blob: bytes, max_items: int = 6) -> str:
    parts = extract(blob)
    if not parts:
        return ""
    if len(parts) > max_items:
        parts = parts[:max_items] + [f"... (+{len(parts) - max_items})"]
    return " | ".join(parts)
