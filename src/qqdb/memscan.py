"""Locate NTQQ raw-key strings in process memory without injection or hooks.

The scan only performs read-only ``pread`` calls on ``/proc/<pid>/mem`` for
private writable anonymous mappings.  It never attaches with ptrace, never
writes memory, and never loads code into the QQ process.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

QQ_EXECUTABLE = "/opt/QQ/qq"
KEY_PATTERN = re.compile(rb"x'([0-9a-fA-F]+)'")
MIN_KEY_HEX = 32
MAX_KEY_HEX = 128
MAX_REGION_SIZE = 512 << 20
CHUNK_SIZE = 4 << 20
OVERLAP = 4096


@dataclass(frozen=True)
class KeyCandidate:
    key: str
    pid: int
    address: int


def qq_pids(executable: str = QQ_EXECUTABLE) -> list[int]:
    wanted = {executable, os.path.realpath(executable)}
    pids: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            exe = os.path.realpath(os.readlink(entry / "exe"))
        except OSError:
            continue
        if exe in wanted:
            pids.append(int(entry.name))
    return sorted(pids)


def _writable_private_regions(pid: int):
    try:
        maps = Path(f"/proc/{pid}/maps").read_text().splitlines()
    except OSError:
        return
    for line in maps:
        fields = line.split()
        if len(fields) < 5:
            continue
        perms = fields[1]
        if "r" not in perms or "w" not in perms:
            continue
        if fields[4] != "0":  # private anonymous mappings only
            continue
        try:
            start, end = (int(part, 16) for part in fields[0].split("-"))
        except ValueError:
            continue
        if start >= end or end - start > MAX_REGION_SIZE:
            continue
        yield start, end


def _scan_region(handle, start: int, end: int, pid: int) -> list[KeyCandidate]:
    hits: list[KeyCandidate] = []
    position = start
    carry = b""
    while position < end:
        try:
            handle.seek(position)
            data = handle.read(min(CHUNK_SIZE, end - position))
        except OSError:
            break
        if not data:
            break
        buffer = carry + data
        base = position - len(carry)
        for match in KEY_PATTERN.finditer(buffer):
            body = match.group(1)
            if MIN_KEY_HEX <= len(body) <= MAX_KEY_HEX and len(body) % 2 == 0:
                hits.append(
                    KeyCandidate(
                        key=match.group(0).decode("ascii"),
                        pid=pid,
                        address=base + match.start(),
                    )
                )
        carry = data[-OVERLAP:]
        position += len(data)
    return hits


def scan_pid(pid: int) -> list[KeyCandidate]:
    try:
        handle = open(f"/proc/{pid}/mem", "rb", 0)
    except OSError:
        return []
    with handle:
        found: list[KeyCandidate] = []
        for start, end in _writable_private_regions(pid):
            found.extend(_scan_region(handle, start, end, pid))
        return found


def scan() -> tuple[list[int], list[KeyCandidate]]:
    """Return the QQ pids scanned and every unique raw-key string found."""
    pids = qq_pids()
    unique: dict[str, KeyCandidate] = {}
    for pid in pids:
        for hit in scan_pid(pid):
            unique.setdefault(hit.key, hit)
    return pids, list(unique.values())
