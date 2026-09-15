"""Encrypted provider state only. Console owns users and authorization."""

import json
import os
import re
import sqlite3
from pathlib import Path

from cryptography.fernet import Fernet


def validate_owner(owner: str) -> str:
    if not re.fullmatch(r"usr_[A-Za-z0-9]{1,64}", owner):
        raise ValueError("invalid owner")
    return owner


class SessionStore:
    def __init__(self, path: Path, key: str):
        self.cipher = Fernet(key.encode())
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS sessions (owner TEXT PRIMARY KEY, value BLOB NOT NULL)"
        )
        self.db.commit()

    def get(self, owner: str) -> str | None:
        row = self.db.execute(
            "SELECT value FROM sessions WHERE owner=?", (validate_owner(owner),)
        ).fetchone()
        if not row:
            return None
        value = json.loads(self.cipher.decrypt(row[0]))
        if value["owner"] != owner:
            raise ValueError("session owner mismatch")
        return value["session"]

    def put(self, owner: str, session: str) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO sessions VALUES (?,?) ON CONFLICT(owner) DO UPDATE SET value=excluded.value",
                (
                    validate_owner(owner),
                    self.cipher.encrypt(json.dumps({"owner": owner, "session": session}).encode()),
                ),
            )

    def delete(self, owner: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM sessions WHERE owner=?", (validate_owner(owner),))

    def close(self) -> None:
        self.db.close()
