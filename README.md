# ntqq-db-decrypt

CLI: `qqdb`. Read the local QQNT (Linux QQ) SQLCipher databases on **your own machine**
without injecting code into QQ and without hooks.

## How it works

Linux QQNT stores its data under `~/.config/QQ/nt_qq_<hash>/nt_db/`.

* Each `.db` file begins with a **1024-byte custom NTQQ header**.
* After that header is a normal **SQLCipher** database (4 KB pages) using:
  * `cipher_page_size=4096`
  * `kdf_iter=4000`
  * `cipher_hmac_algorithm=HMAC_SHA1`
  * `cipher_kdf_algorithm=PBKDF2_HMAC_SHA512`
* The passphrase is the raw-key string `x'<64 hex key><32 hex salt>'`, which
  QQ hands to `sqlite3_key`.  The 32-hex suffix is the database's salt, i.e.
  bytes `[1024:1040]` of the file.
* The key strings live in the QQ process's private heap while the account is
  logged in.
* `~/.config/QQ/global/nt_db/login.db` uses a fixed hard-coded passphrase
  (`BD156D6710D54D8782F4`).  It contains the known accounts' QQ numbers, UIDs,
  nicknames and `nt_qq_<hash>` avatar paths, which lets the tool label each
  account directory.

This project scans `/proc/<pid>/mem` with **read-only reads** of private
writable anonymous mappings.  It does not use `ptrace`, does not write to the
process, does not load a library, and does not hook any function.

## Requirements

* Linux, with `libsqlcipher2` installed (or extracted locally).
* QQ running and the target account logged in.
* Python 3.10+; no third-party Python packages.

If SQLCipher is not in a standard path:

```bash
export QQDB_LIBSQLCIPHER=/path/to/libsqlcipher.so.3
```

On a Debian/Ubuntu machine without root you can fetch it locally:

```bash
mkdir -p /tmp/sqltool && cd /tmp/sqltool
apt-get download sqlcipher libsqlcipher2
for deb in *.deb; do dpkg-deb -x "$deb" root; done
export LD_LIBRARY_PATH=/tmp/sqltool/root/usr/lib/x86_64-linux-gnu
```

## Usage

```bash
uv run qqdb scan                # QQ pids, keys, readable DBs, account identity
uv run qqdb accounts            # per-account salt/key status
uv run qqdb info --account a7d6 # identity, page count, table count
uv run qqdb tables --account a7d6 --counts
uv run qqdb messages --account a7d6 --limit 10   # recent chat messages
uv run qqdb query --account a7d6 --limit 10 \
  'SELECT "1000","20002" FROM profile_info_v6 LIMIT 5'
uv run qqdb export --account a7d6 --out /tmp/nt_msg_plain.db
```

`--account` accepts the full `nt_qq_<hash>` name or any unique substring.
Without it, the account with the most recoverable keys (normally the logged-in
one) is used.

`export` writes a **plaintext** SQLite file; treat it as sensitive data.

## Notes

* Only private heap mappings are scanned, so the scan takes a few seconds and
  does not read QQ's huge shared library mappings.
* The current database is copied to a temporary directory (with its `-wal`
  file) and decrypted there; the live files are never modified.
* Accounts that have been logged out no longer have their key in memory and
  therefore cannot be decrypted with this method.  In that case the key may
  still be recoverable from a memory dump or crash dump taken while the
  account was active, but it is not stored next to the database.
* `messages` extracts readable strings from the `40800` protobuf blob.  It is a
  heuristic viewer, not a complete message-element renderer; images, files,
  cards and replies are shown by their embedded captions/paths.
* Use this only on a device and account you own, and follow local law and the
  software's terms of service.
