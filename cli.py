"""Cliente de terminal.

  python -m e2ee_chat.cli --server http://localhost:8443 --user alice register
  python -m e2ee_chat.cli --server http://localhost:8443 --user alice
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import threading
import time

from .client import ChatClient, ChatError, KeyChangedError

HELP = """\
  /dm <usuario>              abrir chat directo
  /group <nombre> <u1> <u2>  crear grupo
  /open <n>                  abrir la conversación n de /list
  /list                      listar conversaciones
  /history [n]               últimos n mensajes (por defecto 30)
  /safety <usuario>          número de seguridad para verificar por otro canal
  /trust <usuario>           aceptar una clave nueva de un contacto
  /help  /quit
  (cualquier otro texto se envía a la conversación abierta)"""


def fmt(m: dict) -> str:
    t = time.strftime("%H:%M", time.localtime(m["ts"]))
    mark = " (pendiente)" if m.get("pending") else ""
    return f"[{t}] {m['from']}: {m['text']}{mark}"


def main() -> None:
    ap = argparse.ArgumentParser(prog="e2ee_chat")
    ap.add_argument("--server", default="http://localhost:8443")
    ap.add_argument("--user", required=True)
    ap.add_argument("--data-dir", default=None, help="carpeta local de este dispositivo")
    ap.add_argument("action", nargs="?", choices=["register", "chat"], default="chat")
    a = ap.parse_args()

    pw = os.environ.get("E2EE_PASSPHRASE") or getpass.getpass("Contraseña: ")
    c = ChatClient(a.server, a.user, pw, a.data_dir)
    try:
        if a.action == "register":
            if len(pw) < 10:
                sys.exit("Usá una contraseña larga (10+ caracteres): protege tus claves.")
            c.register()
            print("Cuenta creada. Ahora iniciá sesión sin 'register'.")
            return
        c.login()
        r = c.sync()
    except ChatError as e:
        sys.exit(f"Error: {e}")
    print(f"Sesión iniciada como {c.username}. {len(r['messages'])} mensajes sincronizados. /help")

    current: list[str | None] = [None]
    stop = threading.Event()

    def on_msg(m: dict) -> None:
        mark = "" if m["conv"] == current[0] else f" ({m['conv']})"
        print(f"\r{fmt(m)}{mark}\n> ", end="", flush=True)

    threading.Thread(target=c.listen, args=(on_msg, stop), daemon=True).start()

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        try:
            if line.startswith("/"):
                cmd, *args = line.split()
                if cmd == "/quit":
                    break
                elif cmd == "/help":
                    print(HELP)
                elif cmd == "/dm" and args:
                    current[0] = f"dm:{args[0].lower()}"
                    c._peer_keys(args[0].lower())
                    for m in c.history(current[0]):
                        print(fmt(m))
                elif cmd == "/group" and len(args) >= 2:
                    current[0] = c.create_group(args[0], args[1:])
                elif cmd == "/list":
                    for i, cv in enumerate(c.conversations()):
                        print(f"  {i}. {cv['conv']}  {cv['title']}")
                elif cmd == "/open" and args:
                    current[0] = c.conversations()[int(args[0])]["conv"]
                    for m in c.history(current[0]):
                        print(fmt(m))
                elif cmd == "/history":
                    n = int(args[0]) if args else 30
                    for m in c.history(current[0] or "", n):
                        print(fmt(m))
                elif cmd == "/safety" and args:
                    print(f"Número de seguridad con {args[0]}: {c.safety_number(args[0].lower())}")
                    print("Comparalo con el de tu contacto por otro canal (llamada, en persona).")
                elif cmd == "/trust" and args:
                    c.trust_new_key(args[0].lower())
                    print("Clave nueva aceptada.")
                else:
                    print("Comando no reconocido. /help")
            elif current[0] is None:
                print("Abrí una conversación primero: /dm <usuario>")
            else:
                c.send(current[0], line)
        except KeyChangedError as e:
            print(f"⚠ {e}")
        except ChatError as e:
            print(f"Error: {e}")
    stop.set()


if __name__ == "__main__":
    main()
