"""Key derivation + authenticated encryption. Vault file = JSON header + AES-256-GCM ciphertext."""
import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = 1
AAD = b"localvault-v1"
DEFAULT_KDF = {"n": 2 ** 15, "r": 8, "p": 1}


class WrongPassword(Exception):
    pass


class VaultCorrupt(Exception):
    pass


def _b64(b):
    return base64.b64encode(b).decode()


def derive_key(password, salt, kdf):
    return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(password.encode())


def seal(key, salt, kdf, data):
    nonce = os.urandom(12)  # fresh nonce on every save
    ct = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), AAD)
    blob = {"version": VERSION, "kdf": {"name": "scrypt", **kdf},
            "salt": _b64(salt), "nonce": _b64(nonce), "ciphertext": _b64(ct)}
    return json.dumps(blob).encode()


def unseal(raw, password):
    """Returns (data, key, salt, kdf). Raises WrongPassword / VaultCorrupt."""
    try:
        blob = json.loads(raw)
        kdf = {k: int(blob["kdf"][k]) for k in ("n", "r", "p")}
        salt = base64.b64decode(blob["salt"])
        nonce = base64.b64decode(blob["nonce"])
        ct = base64.b64decode(blob["ciphertext"])
        if blob["version"] != VERSION or kdf["n"] > 2 ** 20 or kdf["r"] > 32 or kdf["p"] > 8:
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise VaultCorrupt("Vault file is damaged or unsupported.")
    key = derive_key(password, salt, kdf)
    try:
        data = json.loads(AESGCM(key).decrypt(nonce, ct, AAD))
    except InvalidTag:  # wrong password OR tampered file
        raise WrongPassword()
    return data, key, salt, kdf
