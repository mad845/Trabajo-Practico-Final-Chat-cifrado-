"""Cliente: cifra/descifra, guarda el historial local cifrado y lo sincroniza."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

import requests
from cryptography.exceptions import InvalidSignature, InvalidTag

from . import crypto as C


class ChatError(Exception):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


class KeyChangedError(ChatError):
    """La clave pública de un contacto cambió desde la primera vez que la vimos."""


class LocalStore:
    """SQLite local. Cuerpos, remitentes y nombres de conversación van cifrados."""

    def __init__(self, path: Path, identity: C.Identity):
        self.key, self.tag_key = C.local_keys(identity)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.RLock()
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS messages(
                msg_id TEXT PRIMARY KEY, tag TEXT, ts REAL, blob BLOB);
            CREATE INDEX IF NOT EXISTS idx_msgs_tag ON messages(tag, ts);
            CREATE TABLE IF NOT EXISTS convs(tag TEXT PRIMARY KEY, last_ts REAL, blob BLOB);
            CREATE TABLE IF NOT EXISTS peers(username TEXT PRIMARY KEY, dh TEXT, sign TEXT);
            CREATE TABLE IF NOT EXISTS outbox(msg_id TEXT PRIMARY KEY, blob BLOB);
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            """
        )

    def seal(self, obj) -> bytes:
        return C.seal_local(self.key, json.dumps(obj, separators=(",", ":")).encode())

    def open(self, blob: bytes):
        return json.loads(C.open_local(self.key, blob))

    def tag(self, conv: str) -> str:
        return hmac.new(self.tag_key, conv.encode(), hashlib.sha256).hexdigest()[:32]

    # cursor de sincronización
    def get_cursor(self) -> int:
        with self.lock:
            r = self.db.execute("SELECT v FROM meta WHERE k='cursor'").fetchone()
        return int(r[0]) if r else 0

    def set_cursor(self, seq: int) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES('cursor', ?)", (str(seq),))
            self.db.commit()


class ChatClient:
    def __init__(self, server: str, username: str, passphrase: str,
                 data_dir: str | None = None, timeout: float = 10.0):
        self.server = server.rstrip("/")
        self.username = username.lower()
        self._passphrase = passphrase
        self.data_dir = Path(
            data_dir or os.environ.get("E2EE_HOME", "~/.e2ee_chat")
        ).expanduser()
        self.timeout = timeout
        self.http = requests.Session()
        self.token: str | None = None
        self.identity: C.Identity | None = None
        self.store: LocalStore | None = None
        self._checked: set[str] = set()

    # ----------------------------------------------------------------- red
    def _req(self, method: str, path: str, auth: bool = True, **kw):
        headers = {"Authorization": f"Bearer {self.token}"} if auth and self.token else {}
        timeout = kw.pop("timeout", self.timeout)
        r = self.http.request(method, self.server + path, headers=headers,
                              timeout=timeout, **kw)
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", r.text[:200])
            except Exception:
                msg = r.text[:200]
            raise ChatError(msg, r.status_code)
        return r.json()

    # ------------------------------------------------------------- cuenta
    def register(self) -> None:
        salt = C.new_salt()
        auth_key, vault_key = C.derive_account_keys(self._passphrase, salt)
        identity = C.Identity.generate()
        self._req("POST", "/api/register", auth=False, json={
            "username": self.username,
            "salt": C.b64(salt),
            "auth_pub": C.b64(auth_key.public_key().public_bytes_raw()),
            "dh_pub": C.b64(identity.dh_pub),
            "sign_pub": C.b64(identity.sign_pub),
            "vault": C.seal_vault(vault_key, self.username, identity),
        })

    def login(self) -> None:
        salt = C.unb64(self._req("GET", f"/api/salt/{self.username}", auth=False)["salt"])
        auth_key, vault_key = C.derive_account_keys(self._passphrase, salt)
        nonce = self._req("POST", "/api/login/challenge", auth=False,
                          json={"username": self.username})["nonce"]
        sig = auth_key.sign(C.login_message(nonce, self.username))
        self.token = self._req("POST", "/api/login", auth=False, json={
            "username": self.username, "nonce": nonce, "sig": C.b64(sig)})["token"]
        try:
            self.identity = C.open_vault(
                vault_key, self.username, self._req("GET", "/api/vault")["vault"])
        except InvalidTag:
            raise ChatError("no se pudo abrir la bóveda de claves")
        # el servidor no puede cambiarnos las claves públicas sin que lo notemos
        mine = self._req("GET", f"/api/users/{self.username}")
        if (C.unb64(mine["dh_pub"]) != self.identity.dh_pub
                or C.unb64(mine["sign_pub"]) != self.identity.sign_pub):
            raise ChatError("las claves públicas del servidor no coinciden con tu identidad")
        self.store = LocalStore(self.data_dir / f"{self.username}.db", self.identity)
        self._checked = {self.username}

    # ------------------------------------------------------ claves de pares
    def _peer_keys(self, name: str) -> tuple[bytes, bytes]:
        if name == self.username:
            return self.identity.dh_pub, self.identity.sign_pub
        st = self.store
        with st.lock:
            pinned = st.db.execute(
                "SELECT dh, sign FROM peers WHERE username=?", (name,)).fetchone()
        if name not in self._checked:
            try:
                info = self._req("GET", f"/api/users/{name}")
            except (requests.ConnectionError, requests.Timeout):
                if pinned:  # sin red: usamos la clave ya fijada y reverificamos luego
                    return C.unb64(pinned[0]), C.unb64(pinned[1])
                raise ChatError(f"sin conexión y todavía no tenemos la clave de {name}")
            if pinned and (pinned[0] != info["dh_pub"] or pinned[1] != info["sign_pub"]):
                raise KeyChangedError(
                    f"¡La clave de {name} cambió! Verificá el número de seguridad "
                    f"con {name} y, si es legítimo, usá trust_new_key().")
            if not pinned:  # confianza en el primer uso (TOFU)
                with st.lock:
                    st.db.execute("INSERT INTO peers VALUES(?,?,?)",
                                  (name, info["dh_pub"], info["sign_pub"]))
                    st.db.commit()
                pinned = (info["dh_pub"], info["sign_pub"])
            self._checked.add(name)
        return C.unb64(pinned[0]), C.unb64(pinned[1])

    def trust_new_key(self, name: str) -> None:
        info = self._req("GET", f"/api/users/{name}")
        with self.store.lock:
            self.store.db.execute("INSERT OR REPLACE INTO peers VALUES(?,?,?)",
                                  (name, info["dh_pub"], info["sign_pub"]))
            self.store.db.commit()
        self._checked.add(name)

    def safety_number(self, peer: str) -> str:
        dh, sign = self._peer_keys(peer)
        return C.safety_number(self.username, self.identity.dh_pub, self.identity.sign_pub,
                               peer, dh, sign)

    # ------------------------------------------------------ conversaciones
    def _get_conv(self, conv: str) -> dict | None:
        st = self.store
        with st.lock:
            r = st.db.execute("SELECT blob FROM convs WHERE tag=?", (st.tag(conv),)).fetchone()
        return st.open(r[0]) if r else None

    def _save_conv(self, info: dict, ts: float | None = None) -> None:
        st = self.store
        with st.lock:
            old = st.db.execute("SELECT last_ts FROM convs WHERE tag=?",
                                (st.tag(info["conv"]),)).fetchone()
            last = max(ts or 0, old[0] if old else 0)
            st.db.execute("INSERT OR REPLACE INTO convs VALUES(?,?,?)",
                          (st.tag(info["conv"]), last, st.seal(info)))
            st.db.commit()

    def conversations(self) -> list[dict]:
        st = self.store
        with st.lock:
            rows = st.db.execute("SELECT blob, last_ts FROM convs ORDER BY last_ts DESC").fetchall()
        return [{**st.open(b), "last_ts": t} for b, t in rows]

    def create_group(self, name: str, members: list[str]) -> str:
        members = sorted({m.lower() for m in members} | {self.username})
        for m in members:
            self._peer_keys(m)  # valida que existan y fija sus claves
        gid = uuid.uuid4().hex[:12]
        conv = f"grp:{gid}"
        self._save_conv({"conv": conv, "title": name, "members": members, "group": gid},
                        time.time())
        self.send(conv, f"{self.username} creó el grupo «{name}»")
        return conv

    # --------------------------------------------------------------- envío
    def send(self, conv: str, text: str) -> dict:
        """Cifra y envía. Si no hay red, queda en la bandeja de salida."""
        if conv.startswith("dm:"):
            peer = conv[3:].lower()
            self._peer_keys(peer)
            rcpts, group = [peer], None
            if not self._get_conv(conv):
                self._save_conv({"conv": conv, "title": peer, "members": [self.username, peer]})
        else:
            info = self._get_conv(conv)
            if not info:
                raise ChatError("conversación desconocida")
            rcpts = [m for m in info["members"] if m != self.username]
            group = {"id": info["group"], "name": info["title"], "members": info["members"]}
        for r in rcpts:
            self._peer_keys(r)  # falla antes de guardar nada si una clave cambió
        payload = {"v": 1, "id": uuid.uuid4().hex, "ts": time.time(), "from": self.username,
                   "rcpts": rcpts, "group": group, "text": text}
        self._ingest(payload)  # aparece de inmediato en el historial local
        if not self._deliver(payload):
            with self.store.lock:
                self.store.db.execute("INSERT OR REPLACE INTO outbox VALUES(?,?)",
                                      (payload["id"], self.store.seal(payload)))
                self.store.db.commit()
        return {"id": payload["id"], "conv": conv, "pending": self._is_pending(payload["id"])}

    def _is_pending(self, msg_id: str) -> bool:
        with self.store.lock:
            return self.store.db.execute(
                "SELECT 1 FROM outbox WHERE msg_id=?", (msg_id,)).fetchone() is not None

    def _deliver(self, payload: dict) -> bool:
        plaintext = json.dumps(payload, separators=(",", ":")).encode()
        batch = []
        for target in dict.fromkeys(payload["rcpts"] + [self.username]):  # + copia propia
            dh, _ = self._peer_keys(target)
            env = C.encrypt_for(self.identity, self.username, target, dh, plaintext)
            batch.append({"to": target, "blob": json.dumps(env, separators=(",", ":"))})
        try:
            self._req("POST", "/api/send", json={"messages": batch})
            return True
        except (requests.ConnectionError, requests.Timeout):
            return False

    def flush_outbox(self) -> int:
        with self.store.lock:
            rows = self.store.db.execute("SELECT msg_id, blob FROM outbox").fetchall()
        sent = 0
        for msg_id, blob in rows:
            if self._deliver(self.store.open(blob)):
                with self.store.lock:
                    self.store.db.execute("DELETE FROM outbox WHERE msg_id=?", (msg_id,))
                    self.store.db.commit()
                sent += 1
            else:
                break
        return sent

    # ------------------------------------------------------------ recepción
    def _ingest(self, p: dict) -> dict | None:
        """Guarda un mensaje descifrado. Devuelve None si ya lo teníamos."""
        sender = p["from"]
        g = p.get("group")
        if g:
            members = sorted(set(g["members"]))
            if sender not in members or self.username not in members:
                raise ChatError("grupo inválido")
            conv = f"grp:{g['id']}"
            existing = self._get_conv(conv)
            if existing and sender not in existing["members"]:
                raise ChatError("remitente no pertenece al grupo")
            self._save_conv({"conv": conv, "title": g["name"], "members": members,
                             "group": g["id"]}, p["ts"])
        else:
            peer = p["rcpts"][0] if sender == self.username else sender
            conv = f"dm:{peer}"
            self._save_conv({"conv": conv, "title": peer,
                             "members": [self.username, peer]}, p["ts"])
        st = self.store
        entry = {"id": p["id"], "ts": p["ts"], "from": sender, "text": p["text"], "conv": conv}
        with st.lock:
            cur = st.db.execute("INSERT OR IGNORE INTO messages VALUES(?,?,?,?)",
                                (p["id"], st.tag(conv), p["ts"], st.seal(entry)))
            st.db.commit()
        return entry if cur.rowcount else None

    def sync(self, wait: float = 0) -> dict:
        """Trae mensajes nuevos (long-polling si wait>0).

        En un dispositivo nuevo el cursor es 0, así que esto reconstruye TODO el
        historial desde el servidor (que solo guarda sobres cifrados).
        """
        new, errors = [], []
        while True:
            cursor = self.store.get_cursor()
            data = self._req("GET", "/api/sync", timeout=wait + self.timeout,
                             params={"after": cursor, "wait": wait, "limit": 200})
            rows = data["messages"]
            if not rows:
                break
            for row in rows:
                try:
                    new_msg = self._handle_envelope(row)
                    if new_msg:
                        new.append(new_msg)
                except (InvalidTag, InvalidSignature, ValueError, KeyError,
                        json.JSONDecodeError, ChatError) as e:
                    if isinstance(e, KeyChangedError):
                        raise
                    errors.append({"seq": row["seq"], "from": row["from_user"],
                                   "error": type(e).__name__})
                self.store.set_cursor(row["seq"])
            wait = 0  # ya hay datos: seguir vaciando sin esperar
        return {"messages": new, "errors": errors}

    def _handle_envelope(self, row: dict) -> dict | None:
        sender = row["from_user"]
        dh, sign = self._peer_keys(sender)
        plaintext = C.decrypt_from(self.identity, self.username, sender, dh, sign,
                                   json.loads(row["blob"]))
        p = json.loads(plaintext)
        if p.get("from") != sender:
            raise ValueError("remitente no coincide")
        if sender != self.username and self.username not in p["rcpts"]:
            raise ValueError("no soy destinatario")
        return self._ingest(p)

    def listen(self, callback, stop: threading.Event, poll: float = 20.0) -> None:
        """Bucle de recepción en tiempo real (para correr en un hilo)."""
        while not stop.is_set():
            try:
                self.flush_outbox()
                for m in self.sync(wait=poll)["messages"]:
                    if m["from"] != self.username:
                        callback(m)
            except (requests.RequestException, ChatError):
                stop.wait(2.0)

    # ------------------------------------------------------------ historial
    def history(self, conv: str, limit: int = 50) -> list[dict]:
        st = self.store
        with st.lock:
            rows = st.db.execute(
                "SELECT blob FROM messages WHERE tag=? ORDER BY ts DESC LIMIT ?",
                (st.tag(conv), limit)).fetchall()
            pending = {r[0] for r in st.db.execute("SELECT msg_id FROM outbox")}
        msgs = [st.open(r[0]) for r in rows][::-1]
        for m in msgs:
            m["pending"] = m["id"] in pending
        return msgs
