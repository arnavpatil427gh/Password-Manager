import hmac
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from crypto import DEFAULT_KDF, VaultCorrupt, WrongPassword, derive_key, seal, unseal  # noqa: F401

DEFAULT_PATH = Path.home() / ".localvault" / "vault.dat"


def _now():
    return datetime.now().isoformat(timespec="seconds")


class Vault:
    def __init__(self, path=DEFAULT_PATH):
        self.path = Path(path)
        self.entries = []
        self._key = self._salt = self._kdf = None

    @property
    def unlocked(self):
        return self._key is not None

    def exists(self):
        return self.path.exists()

    def create(self, master):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._salt, self._kdf = os.urandom(16), dict(DEFAULT_KDF)
        self._key = derive_key(master, self._salt, self._kdf)
        self.entries = []
        self.save()

    def unlock(self, master):
        try:
            raw = self.path.read_bytes()
        except OSError:
            raise VaultCorrupt("Could not read the vault file.")
        data, self._key, self._salt, self._kdf = unseal(raw, master)
        self.entries = data.get("entries", [])

    def lock(self):
        self._key = self._salt = self._kdf = None
        self.entries = []

    def save(self):
        raw = seal(self._key, self._salt, self._kdf, {"entries": self.entries})
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(raw)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        if self.path.exists():
            shutil.copy2(self.path, self.path.with_suffix(".bak"))
        os.replace(tmp, self.path)  # atomic

    def add_entry(self, site, username, password, notes=""):
        e = {"id": uuid.uuid4().hex, "site": site, "username": username, "password": password,
             "notes": notes, "created": _now(), "modified": _now()}
        self.entries.append(e)
        self.save()
        return e

    def update_entry(self, entry, **fields):
        entry.update(fields, modified=_now())
        self.save()

    def delete_entry(self, entry):
        self.entries = [e for e in self.entries if e["id"] != entry["id"]]
        self.save()

    def change_master(self, old, new):
        if not hmac.compare_digest(derive_key(old, self._salt, self._kdf), self._key):
            raise WrongPassword()
        self._salt = os.urandom(16)
        self._key = derive_key(new, self._salt, self._kdf)
        self.save()
