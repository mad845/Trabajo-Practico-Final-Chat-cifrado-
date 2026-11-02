"""Servidor relay. Solo ve texto cifrado: guarda y reenvía sobres.

  uvicorn --factory e2ee_chat.server:create_app --port 8443
"""
from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import crypto as C

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
TOKEN_TTL = 24 * 3600
CHALLENGE_TTL = 60
MAX_BLOB = 64 * 1024
MAX_BATCH = 100
RATE_LIMIT = 300  # mensajes por usuario por minuto


def err(msg: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=status)


def create_app(db_path: str | None = None) -> Starlette:
    db_path = db_path or os.environ.get("E2EE_DB", "e2ee_server.db")
    db = sqlite3.connect(db_path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    lock = threading.Lock()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY, salt TEXT, auth_pub TEXT,
            dh_pub TEXT, sign_pub TEXT, vault TEXT, created REAL);
        CREATE TABLE IF NOT EXISTS mailbox(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            to_user TEXT NOT NULL, from_user TEXT NOT NULL,
            ts REAL NOT NULL, blob TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_mailbox_to ON mailbox(to_user, seq);
        """
    )
    row = db.execute("SELECT v FROM meta WHERE k='secret'").fetchone()
    if row:
        server_secret = bytes.fromhex(row["v"])
    else:
        server_secret = os.urandom(32)
        db.execute("INSERT INTO meta VALUES('secret', ?)", (server_secret.hex(),))
        db.commit()

    challenges: dict[str, tuple[str, float]] = {}
    tokens: dict[str, tuple[str, float]] = {}
    sent_log: dict[str, deque] = defaultdict(deque)
    cond = asyncio.Condition()

    def fake_salt(username: str) -> str:
        """Sal determinista para usuarios inexistentes (evita enumerar cuentas)."""
        return C.b64(hmac.new(server_secret, username.encode(), hashlib.sha256).digest())

    def user_of(request: Request) -> str | None:
        h = request.headers.get("authorization", "")
        if not h.startswith("Bearer "):
            return None
        entry = tokens.get(h[7:])
        if not entry or entry[1] < time.time():
            return None
        return entry[0]

    async def body(request: Request) -> dict:
        try:
            data = await request.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    # --------------------------------------------------------------- rutas
    async def register(request: Request):
        d = await body(request)
        u = str(d.get("username", ""))
        if not USERNAME_RE.match(u):
            return err("usuario inválido (3-32 caracteres: a-z, 0-9, _)")
        for f in ("salt", "auth_pub", "dh_pub", "sign_pub", "vault"):
            if not isinstance(d.get(f), str) or not d[f] or len(d[f]) > 4096:
                return err(f"campo inválido: {f}")
        with lock:
            if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
                return err("el usuario ya existe", 409)
            db.execute(
                "INSERT INTO users VALUES(?,?,?,?,?,?,?)",
                (u, d["salt"], d["auth_pub"], d["dh_pub"], d["sign_pub"], d["vault"], time.time()),
            )
            db.commit()
        return JSONResponse({"ok": True}, status_code=201)

    async def salt(request: Request):
        u = request.path_params["username"].lower()
        with lock:
            row = db.execute("SELECT salt FROM users WHERE username=?", (u,)).fetchone()
        return JSONResponse({"salt": row["salt"] if row else fake_salt(u)})

    async def challenge(request: Request):
        d = await body(request)
        nonce = secrets.token_urlsafe(32)
        now = time.time()
        for k in [k for k, (_, exp) in challenges.items() if exp < now]:
            challenges.pop(k, None)
        challenges[nonce] = (str(d.get("username", "")), now + CHALLENGE_TTL)
        return JSONResponse({"nonce": nonce})

    async def login(request: Request):
        d = await body(request)
        u, nonce, sig = str(d.get("username", "")), str(d.get("nonce", "")), str(d.get("sig", ""))
        entry = challenges.pop(nonce, None)  # un solo uso
        bad = err("usuario o contraseña incorrectos", 401)
        if not entry or entry[0] != u or entry[1] < time.time():
            return bad
        with lock:
            row = db.execute("SELECT auth_pub FROM users WHERE username=?", (u,)).fetchone()
        if not row:
            return bad
        try:
            Ed25519PublicKey.from_public_bytes(C.unb64(row["auth_pub"])).verify(
                C.unb64(sig), C.login_message(nonce, u)
            )
        except (InvalidSignature, ValueError):
            return bad
        token = secrets.token_urlsafe(32)
        tokens[token] = (u, time.time() + TOKEN_TTL)
        return JSONResponse({"token": token})

    async def vault(request: Request):
        u = user_of(request)
        if not u:
            return err("no autorizado", 401)
        with lock:
            row = db.execute("SELECT vault FROM users WHERE username=?", (u,)).fetchone()
        return JSONResponse({"vault": row["vault"]})

    async def user_keys(request: Request):
        if not user_of(request):
            return err("no autorizado", 401)
        u = request.path_params["username"].lower()
        with lock:
            row = db.execute(
                "SELECT username, dh_pub, sign_pub FROM users WHERE username=?", (u,)
            ).fetchone()
        if not row:
            return err("usuario no encontrado", 404)
        return JSONResponse(dict(row))

    async def send(request: Request):
        me = user_of(request)
        if not me:
            return err("no autorizado", 401)
        d = await body(request)
        msgs = d.get("messages")
        if not isinstance(msgs, list) or not 0 < len(msgs) <= MAX_BATCH:
            return err("lote inválido")
        now = time.time()
        log = sent_log[me]
        while log and log[0] < now - 60:
            log.popleft()
        if len(log) + len(msgs) > RATE_LIMIT:
            return err("demasiados mensajes, esperá un momento", 429)
        for m in msgs:
            if not isinstance(m, dict) or not isinstance(m.get("blob"), str):
                return err("mensaje inválido")
            if len(m["blob"]) > MAX_BLOB:
                return err("mensaje demasiado grande", 413)
        seqs = []
        with lock:
            for m in msgs:
                to = str(m.get("to", ""))
                if not db.execute("SELECT 1 FROM users WHERE username=?", (to,)).fetchone():
                    db.rollback()
                    return err(f"destinatario inexistente: {to}", 404)
            for m in msgs:
                # 'from' lo fija el servidor según el token; además va firmado en el sobre
                cur = db.execute(
                    "INSERT INTO mailbox(to_user,from_user,ts,blob) VALUES(?,?,?,?)",
                    (m["to"], me, now, m["blob"]),
                )
                seqs.append(cur.lastrowid)
            db.commit()
        log.extend([now] * len(msgs))
        async with cond:
            cond.notify_all()
        return JSONResponse({"seqs": seqs})

    def fetch(me: str, after: int, limit: int) -> list[dict]:
        with lock:
            rows = db.execute(
                "SELECT seq, from_user, to_user, ts, blob FROM mailbox "
                "WHERE to_user=? AND seq>? ORDER BY seq LIMIT ?",
                (me, after, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    async def sync(request: Request):
        me = user_of(request)
        if not me:
            return err("no autorizado", 401)
        try:
            after = int(request.query_params.get("after", 0))
            wait = min(float(request.query_params.get("wait", 0)), 30.0)
            limit = min(int(request.query_params.get("limit", 200)), 500)
        except ValueError:
            return err("parámetros inválidos")
        rows = fetch(me, after, limit)
        if not rows and wait > 0:  # long-polling: entrega casi en tiempo real
            deadline = time.monotonic() + wait
            async with cond:
                while True:
                    rows = fetch(me, after, limit)
                    remaining = deadline - time.monotonic()
                    if rows or remaining <= 0:
                        break
                    try:
                        await asyncio.wait_for(cond.wait(), remaining)
                    except asyncio.TimeoutError:
                        break
        return JSONResponse({"messages": rows})

    async def health(request: Request):
        return JSONResponse({"ok": True})

    return Starlette(
        routes=[
            Route("/api/health", health),
            Route("/api/register", register, methods=["POST"]),
            Route("/api/salt/{username}", salt),
            Route("/api/login/challenge", challenge, methods=["POST"]),
            Route("/api/login", login, methods=["POST"]),
            Route("/api/vault", vault),
            Route("/api/users/{username}", user_keys),
            Route("/api/send", send, methods=["POST"]),
            Route("/api/sync", sync),
        ]
    )
