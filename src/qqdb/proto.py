"""Structured parsing of NTQQ message protobuf elements.

A message row's ``40800`` blob is a protobuf message containing one or more
repeated ``40800`` element fields.  Each element has a numeric type and
type-specific fields; see :mod:`qqdb.schema` for the numbers used here.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterator

from . import schema
from . import text as fallback_text


@dataclass(frozen=True)
class Field:
    number: int
    wire: int
    value: int | bytes


def read_varint(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while position < len(data):
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, position
        shift += 7
        if shift > 63:
            break
    raise ValueError("truncated varint")


def iter_fields(data: bytes) -> Iterator[Field]:
    position = 0
    while position < len(data):
        try:
            key, position = read_varint(data, position)
        except ValueError:
            return
        number = key >> 3
        wire = key & 0x07
        if number == 0:
            return
        if wire == 0:
            try:
                value, position = read_varint(data, position)
            except ValueError:
                return
            yield Field(number, wire, value)
        elif wire == 1:
            if position + 8 > len(data):
                return
            yield Field(number, wire, data[position : position + 8])
            position += 8
        elif wire == 2:
            try:
                length, position = read_varint(data, position)
            except ValueError:
                return
            if length < 0 or position + length > len(data):
                return
            yield Field(number, wire, data[position : position + length])
            position += length
        elif wire == 5:
            if position + 4 > len(data):
                return
            yield Field(number, wire, data[position : position + 4])
            position += 4
        else:
            return


def _decode_text(raw: bytes | None) -> str | None:
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = text.strip("\x00")
    if not text:
        return None
    if all(char.isprintable() or char in "\r\n\t" for char in text):
        return text
    return None


def _texts(blobs: dict[int, list[bytes]], *numbers: int) -> list[str]:
    result: list[str] = []
    for number in numbers:
        for raw in blobs.get(number, []):
            text = _decode_text(raw)
            if text is not None and text not in result:
                result.append(text)
    return result


def _first_text(blobs: dict[int, list[bytes]], *numbers: int) -> str | None:
    values = _texts(blobs, *numbers)
    return values[0] if values else None


def _ints(fields: list[Field]) -> dict[int, int]:
    result: dict[int, int] = {}
    for item in fields:
        if item.wire == 0 and isinstance(item.value, int):
            result.setdefault(item.number, item.value)
    return result


def _blobs(fields: list[Field]) -> dict[int, list[bytes]]:
    result: dict[int, list[bytes]] = defaultdict(list)
    for item in fields:
        if item.wire == 2 and isinstance(item.value, bytes):
            result[item.number].append(item.value)
    return result


def _strip_ntos(path: str | None) -> str | None:
    if not path:
        return None
    prefix = "::NTOSFull::"
    return path[len(prefix) :] if path.startswith(prefix) else path


def _hex(raw: bytes | None) -> str | None:
    return raw.hex() if raw else None


def _human_size(value: int | None) -> str:
    if not value:
        return ""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{value}B"


def _clean(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        text = _decode_text(value)
        return text if text is not None else value.hex()
    return value


def _deep_text(data: bytes, limit: int = 2) -> str:
    parts = fallback_text.extract(data)
    return " | ".join(parts[:limit])


def _walk_key_values(obj: Any, keys: set[str], depth: int = 0) -> Iterator[str]:
    if depth > 6:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in keys and isinstance(value, str) and value.strip():
                yield value.strip()
            else:
                yield from _walk_key_values(value, keys, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_key_values(item, keys, depth + 1)


def _ark_info(obj: Any) -> dict[str, str]:
    title = next(
        _walk_key_values(
            obj, {"title", "desc", "summary", "brief", "name", "content", "txt", "text"}
        ),
        "",
    )
    description = next(
        _walk_key_values(
            obj, {"desc", "summary", "brief", "subtitle", "content", "txt", "text"}
        ),
        "",
    )
    url = next(
        _walk_key_values(obj, {"jumpUrl", "jump_url", "url", "qqdocurl", "preview"}),
        "",
    )
    info: dict[str, str] = {}
    if title:
        info["title"] = title
    if description and description != title:
        info["description"] = description
    if url:
        info["url"] = url
    return info


def _parse_file_nested(blobs: list[bytes]) -> dict[str, Any]:
    for raw in blobs:
        nested = list(iter_fields(raw))
        inner = next(
            (item.value for item in nested if item.number == 1 and item.wire == 2), None
        )
        if not isinstance(inner, bytes):
            continue
        fields = list(iter_fields(inner))
        ints = _ints(fields)
        blobs_inner = _blobs(fields)
        data = _clean(
            {
                "file_name": _first_text(blobs_inner, 5),
                "size": ints.get(6),
                "file_id": _first_text(blobs_inner, 3),
                "file_uuid": _first_text(blobs_inner, 57),
                "sha1": _hex(blobs_inner[56][0]) if blobs_inner.get(56) else None,
            }
        )
        if data:
            return data
    return {}


def _parse_file_payload(
    blobs: dict[int, list[bytes]], ints: dict[int, int]
) -> dict[str, Any]:
    return _clean(
        {
            "file_name": _first_text(blobs, schema.FILE_NAME),
            "local_path": _strip_ntos(_first_text(blobs, schema.FILE_PATH)),
            "size": ints.get(schema.FILE_SIZE),
            "width": ints.get(schema.WIDTH),
            "height": ints.get(schema.HEIGHT),
            "file_id": _first_text(blobs, schema.FILE_ID),
            "file_uuid": _first_text(blobs, schema.FILE_UUID),
            "sha1": _hex(blobs[schema.FILE_SHA1][0])
            if blobs.get(schema.FILE_SHA1)
            else None,
            "md5": _hex(blobs[schema.FILE_MD5][0])
            if blobs.get(schema.FILE_MD5)
            else _first_text(blobs, schema.IMAGE_MD5),
            "thumbnail": _strip_ntos(_first_text(blobs, schema.FILE_THUMBNAIL)),
            "nested": _parse_file_nested(blobs.get(schema.FILE_NESTED, [])),
        }
    )


def _looks_like_file(blobs: dict[int, list[bytes]]) -> bool:
    return bool(
        blobs.get(schema.FILE_NAME)
        and (
            blobs.get(schema.FILE_ID)
            or blobs.get(schema.FILE_UUID)
            or blobs.get(schema.FILE_PATH)
        )
    )


def _parse_video(fields: list[Field], blobs: dict[int, list[bytes]], ints: dict[int, int]) -> dict[str, Any]:
    cover_text = ""
    width = None
    height = None
    for raw in blobs.get(schema.VIDEO_COVER, []):
        cover_fields = list(iter_fields(raw))
        cover_blobs = _blobs(cover_fields)
        cover_ints = _ints(cover_fields)
        cover_text = cover_text or _first_text(cover_blobs, schema.TEXT) or ""
        width = width or cover_ints.get(schema.WIDTH)
        height = height or cover_ints.get(schema.HEIGHT)
    data = _clean(
        {
            "duration": ints.get(schema.VIDEO_DURATION),
            "cover_text": cover_text,
            "width": width,
            "height": height,
        }
    )
    return data


@dataclass
class Element:
    type: str
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        if self.type == "text":
            return str(self.data.get("text", ""))
        if self.type == "image":
            display = self.data.get("display")
            name = self.data.get("file_name")
            if display:
                return str(display)
            return f"[图片] {name}" if name else "[图片]"
        if self.type == "file":
            name = self.data.get("file_name") or "未命名文件"
            size = _human_size(self.data.get("size"))
            return f"[文件] {name}" + (f" ({size})" if size else "")
        if self.type == "face":
            name = self.data.get("name") or self.data.get("id")
            return f"[表情] {name}" if name else "[表情]"
        if self.type == "video":
            cover = self.data.get("cover_text")
            return f"[视频] {cover}" if cover else "[视频]"
        if self.type == "ark":
            title = (
                self.data.get("title")
                or self.data.get("description")
                or self.data.get("text")
            )
            return str(title) if title else "[卡片]"
        if self.type == "news":
            title = (
                self.data.get("title")
                or self.data.get("description")
                or self.data.get("text")
            )
            return str(title) if title else "[分享]"
        if self.type == "multi_msg":
            brief = self.data.get("brief") or self.data.get("count")
            return f"[聊天记录] {brief}" if brief else "[聊天记录]"
        if self.type == "interaction":
            names = self.data.get("names") or []
            return "[互动消息]" + (f" {' / '.join(names[:3])}" if names else "")
        if self.type == "system":
            return "[系统消息]"
        return f"[类型 {self.data.get('element_type', '?')}]"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, **self.data}


def parse_element(data: bytes, *, sub_type: int = 0) -> Element:
    fields = list(iter_fields(data))
    ints = _ints(fields)
    blobs = _blobs(fields)
    element_type = ints.get(schema.ELEMENT_TYPE, 0)

    if element_type == schema.ELEMENT_TEXT:
        text = _first_text(blobs, schema.TEXT)
        if text is None:
            text = _deep_text(data)
        return Element("text", {"text": text or ""})

    if element_type == schema.ELEMENT_IMAGE:
        paths = _texts(
            blobs, schema.IMAGE_URL, schema.IMAGE_URL_720, schema.IMAGE_URL_0
        )
        host = _first_text(blobs, schema.IMAGE_HOST)
        urls = [
            f"https://{host}{path}" if host and path.startswith("/") else path
            for path in paths
        ]
        payload = _clean(
            {
                "file_name": _first_text(blobs, schema.IMAGE_FILE_NAME),
                "size": ints.get(schema.FILE_SIZE),
                "width": ints.get(schema.WIDTH),
                "height": ints.get(schema.HEIGHT),
                "md5": _first_text(blobs, schema.IMAGE_MD5),
                "token": _first_text(blobs, schema.IMAGE_TOKEN),
                "paths": paths,
                "urls": urls,
                "local_path": _strip_ntos(_first_text(blobs, schema.IMAGE_LOCAL_PATH)),
                "display": _first_text(blobs, schema.IMAGE_DISPLAY),
                "host": host,
                "is_emoji": bool(sub_type == 4096),
            }
        )
        return Element("image", payload)

    if element_type == schema.ELEMENT_FILE:
        return Element("file", _parse_file_payload(blobs, ints))

    if element_type == schema.ELEMENT_FACE:
        payload = _clean(
            {
                "id": ints.get(schema.FACE_ID),
                "name": _first_text(blobs, schema.FACE_NAME),
            }
        )
        return Element("face", payload)

    if element_type == schema.ELEMENT_VIDEO:
        return Element("video", _parse_video(fields, blobs, ints))

    if element_type in (schema.ELEMENT_ARK, schema.ELEMENT_NEWS):
        if element_type == schema.ELEMENT_ARK and _looks_like_file(blobs):
            return Element("file", _parse_file_payload(blobs, ints))
        json_text = _first_text(blobs, schema.ARK_JSON, schema.ARK_JSON_SHARE)
        kind = "ark" if element_type == schema.ELEMENT_ARK else "news"
        obj: Any = None
        if json_text:
            try:
                obj = json.loads(json_text)
            except json.JSONDecodeError:
                obj = None
        if obj is not None:
            info = _ark_info(obj)
            payload = _clean(
                {
                    "kind": kind,
                    "title": info.get("title"),
                    "description": info.get("description"),
                    "url": info.get("url"),
                    "json": obj,
                }
            )
            return Element(kind, payload)
        names = _texts(
            blobs,
            schema.INTERACTION_NAME,
            schema.INTERACTION_NAME_2,
            schema.INTERACTION_SENDER_NAME,
            schema.INTERACTION_SENDER_CARD,
            schema.INTERACTION_RECEIVER_NAME,
            schema.INTERACTION_RECEIVER_CARD,
        )
        if names:
            return Element("interaction", _clean({"kind": "interaction", "names": names}))
        text = _deep_text(data)
        return Element(kind, _clean({"kind": kind, "text": text}))

    if element_type == schema.ELEMENT_MULTI_MSG:
        xml_text = _first_text(blobs, schema.MULTI_MSG_XML) or ""
        brief = ""
        count = ""
        file_name = ""
        if xml_text:
            try:
                root = ET.fromstring(xml_text)
                brief = root.get("brief") or ""
                count = root.get("tSum") or ""
                file_name = root.get("m_fileName") or ""
            except ET.ParseError:
                pass
        payload = _clean(
            {
                "brief": brief,
                "count": int(count) if count.isdigit() else count,
                "file_name": file_name,
                "id": _first_text(blobs, schema.MULTI_MSG_ID),
                "xml": xml_text,
            }
        )
        return Element("multi_msg", payload)

    raw = {str(item.number): _jsonable(item.value) for item in fields}
    return Element(
        "unknown",
        _clean(
            {
                "element_type": element_type,
                "text": _deep_text(data),
                "fields": raw,
            }
        ),
    )


def message_elements(blob: bytes | None) -> list[Element]:
    if not blob:
        return []
    try:
        outer = list(iter_fields(blob))
    except Exception:
        return []
    payloads = [
        item.value
        for item in outer
        if item.number == schema.CONTENT_FIELD
        and item.wire == 2
        and isinstance(item.value, bytes)
    ]
    if not payloads:
        payloads = [blob]
    return [parse_element(payload) for payload in payloads]
