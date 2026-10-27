"""Read NTQQ's login.db (hard-coded key) to label account directories.

`login.db` uses a fixed 20-byte passphrase and is not tied to the account
currently logged in.  It stores each known account's QQ number, UID, nickname
and avatar path; the avatar path contains the `nt_qq_<hash>` directory name, so
we can map an account directory to a human-readable identity.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import ntdb
from .sqlcipher import Database

LOGIN_DB_KEY = "BD156D6710D54D8782F4"
_ACCOUNT_DIR = re.compile(r"(nt_qq_[0-9a-f]+)")


def read_accounts(base: Path = ntdb.QQ_CONFIG) -> dict[str, dict[str, object]]:
    source = base / "global" / "nt_db" / "login.db"
    if not source.is_file():
        return {}
    copy = ntdb.DecryptedCopy(source)
    try:
        with Database(copy.path, LOGIN_DB_KEY) as database:
            _, rows = database.query(
                'SELECT "1000","1001","1007","1011" FROM login_table;'
            )
    except Exception:
        return {}
    finally:
        copy.cleanup()

    accounts: dict[str, dict[str, object]] = {}
    for uin, uid, nickname, avatar in rows:
        entry = {"uin": uin, "uid": uid, "nickname": nickname}
        match = _ACCOUNT_DIR.search(str(avatar or ""))
        key = match.group(1) if match else f"uin:{uin}"
        accounts[key] = entry
    return accounts


def label(identity: dict[str, object] | None) -> str:
    if not identity:
        return ""
    uin = identity.get("uin")
    nickname = identity.get("nickname")
    if uin and nickname:
        return f"QQ {uin} ({nickname})"
    if uin:
        return f"QQ {uin}"
    return ""
