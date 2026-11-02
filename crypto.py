"""Primitivas criptográficas del chat.

Esquema (resumen):
  * Cada usuario tiene una identidad: X25519 (acuerdo de claves) + Ed25519 (firmas).
  * Las claves privadas viajan al servidor SOLO dentro de una "bóveda" cifrada con
    AES-256-GCM, con una clave derivada de la contraseña (scrypt). El servidor no puede
    abrirla. Así un dispositivo nuevo recupera la identidad con usuario + contraseña.
  * La autenticación ante el servidor es por desafío-firma con una clave Ed25519 derivada
    de la contraseña: la contraseña nunca se envía.
  * Cada mensaje se cifra por destinatario: ECDH efímero + ECDH estático -> HKDF ->
    AES-256-GCM, y se firma con Ed25519 (autenticidad del remitente).
"""
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

SCRYPT_N = int(os.environ.get("E2EE_SCRYPT_N", 2**15))  # bajar solo en tests
PROTOCOL = b"e2ee-chat/v1"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _raw_pub(k) -> bytes:
    return k.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _raw_priv(k) -> bytes:
    return k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _hkdf(key_material: bytes, info: bytes, salt: bytes | None = None, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        key_material
    )


# --------------------------------------------------------------- identidad
@dataclass
class Identity:
    dh_priv: X25519PrivateKey
    sign_priv: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "Identity":
        return cls(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())

    @property
    def dh_pub(self) -> bytes:
        return _raw_pub(self.dh_priv.public_key())

    @property
    def sign_pub(self) -> bytes:
        return _raw_pub(self.sign_priv.public_key())

    def to_bytes(self) -> bytes:
        return _raw_priv(self.dh_priv) + _raw_priv(self.sign_priv)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Identity":
        if len(data) != 64:
            raise ValueError("identidad inválida")
        return cls(
            X25519PrivateKey.from_private_bytes(data[:32]),
            Ed25519PrivateKey.from_private_bytes(data[32:]),
        )


def safety_number(a_name: str, a_dh: bytes, a_sign: bytes,
                  b_name: str, b_dh: bytes, b_sign: bytes) -> str:
    """Número de seguridad simétrico para verificar claves fuera de banda."""
    parts = sorted([(a_name, a_dh + a_sign), (b_name, b_dh + b_sign)])
    h = hashlib.sha256(
        PROTOCOL + b"/safety" + b"".join(n.encode() + b"\0" + k for n, k in parts)
    ).hexdigest()
    digits = str(int(h, 16)).zfill(60)[:30]
    return " ".join(digits[i:i + 5] for i in range(0, 30, 5))


# ------------------------------------------------- cuenta (contraseña/bóveda)
def new_salt() -> bytes:
    return os.urandom(32)


def derive_account_keys(passphrase: str, salt: bytes) -> tuple[Ed25519PrivateKey, bytes]:
    """De la contraseña salen dos claves independientes: autenticación y bóveda."""
    master = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(passphrase.encode())
    auth_key = Ed25519PrivateKey.from_private_bytes(_hkdf(master, PROTOCOL + b"/auth"))
    vault_key = _hkdf(master, PROTOCOL + b"/vault")
    return auth_key, vault_key


def seal_vault(vault_key: bytes, username: str, identity: Identity) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(vault_key).encrypt(nonce, identity.to_bytes(), username.encode())
    return b64(nonce + ct)


def open_vault(vault_key: bytes, username: str, vault: str) -> Identity:
    raw = unb64(vault)
    return Identity.from_bytes(
        AESGCM(vault_key).decrypt(raw[:12], raw[12:], username.encode())
    )


def login_message(nonce: str, username: str) -> bytes:
    return PROTOCOL + b"/login|" + nonce.encode() + b"|" + username.encode()


# ------------------------------------------------------------- mensajes
def _aad(sender: str, recipient: str, eph_pub: bytes) -> bytes:
    return PROTOCOL + b"|" + sender.encode() + b"|" + recipient.encode() + b"|" + eph_pub


def _msg_key(dh_eph: bytes, dh_static: bytes, eph_pub: bytes,
             sender_dh: bytes, recipient_dh: bytes) -> bytes:
    return _hkdf(
        dh_eph + dh_static,
        PROTOCOL + b"/msg",
        salt=eph_pub + sender_dh + recipient_dh,
    )


def encrypt_for(sender: Identity, sender_name: str, recipient_name: str,
                recipient_dh_pub: bytes, plaintext: bytes) -> dict:
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_pub(eph.public_key())
    r_pub = X25519PublicKey.from_public_bytes(recipient_dh_pub)
    key = _msg_key(eph.exchange(r_pub), sender.dh_priv.exchange(r_pub),
                   eph_pub, sender.dh_pub, recipient_dh_pub)
    nonce = os.urandom(12)
    aad = _aad(sender_name, recipient_name, eph_pub)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    sig = sender.sign_priv.sign(aad + nonce + ct)
    return {"v": 1, "E": b64(eph_pub), "n": b64(nonce), "ct": b64(ct), "sig": b64(sig)}


def decrypt_from(me: Identity, my_name: str, sender_name: str,
                 sender_dh_pub: bytes, sender_sign_pub: bytes, env: dict) -> bytes:
    """Verifica la firma y descifra. Lanza excepción ante cualquier manipulación."""
    if env.get("v") != 1:
        raise ValueError("versión de protocolo desconocida")
    eph_pub = unb64(env["E"])
    nonce = unb64(env["n"])
    ct = unb64(env["ct"])
    aad = _aad(sender_name, my_name, eph_pub)
    Ed25519PublicKey.from_public_bytes(sender_sign_pub).verify(
        unb64(env["sig"]), aad + nonce + ct
    )
    key = _msg_key(
        me.dh_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)),
        me.dh_priv.exchange(X25519PublicKey.from_public_bytes(sender_dh_pub)),
        eph_pub, sender_dh_pub, me.dh_pub,
    )
    return AESGCM(key).decrypt(nonce, ct, aad)


# --------------------------------------------------- almacenamiento local
def local_keys(identity: Identity) -> tuple[bytes, bytes]:
    """(clave de cifrado en reposo, clave para etiquetas de conversación)."""
    raw = identity.to_bytes()
    return _hkdf(raw, PROTOCOL + b"/local-store"), _hkdf(raw, PROTOCOL + b"/local-tag")


def seal_local(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, b"local")


def open_local(key: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], b"local")
