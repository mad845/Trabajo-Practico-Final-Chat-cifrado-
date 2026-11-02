"""Demo narrado del chat cifrado: servidor y clientes reales, todo en un proceso.

  PYTHONPATH=. python demo.py
"""
import os
import socket
import sqlite3
import tempfile
import threading
import time

import uvicorn

from e2ee_chat.client import ChatClient, KeyChangedError
from e2ee_chat.server import create_app

PW = "una-contraseña-bien-larga"
tmp = tempfile.mkdtemp()
DB = os.path.join(tmp, "servidor.db")


def titulo(n, s):
    print(f"\n\033[1;36m━━ {n}. {s}\033[0m")


def linea(who, s):
    print(f"   \033[1m{who:<14}\033[0m {s}")


def hist(c, conv, name):
    for m in c.history(conv):
        t = time.strftime("%H:%M:%S", time.localtime(m["ts"]))
        print(f"      [{t}] {m['from']}: {m['text']}")


s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
server = uvicorn.Server(uvicorn.Config(create_app(DB), host="127.0.0.1", port=port,
                                       log_level="error"))
threading.Thread(target=server.run, daemon=True).start()
while not server.started:
    time.sleep(0.05)
URL = f"http://127.0.0.1:{port}"


def cliente(user, device="notebook"):
    return ChatClient(URL, user, PW, os.path.join(tmp, device))


titulo(1, "Registro de tres usuarios (las claves se generan en cada dispositivo)")
ana, bruno, carla = cliente("ana"), cliente("bruno"), cliente("carla")
for c in (ana, bruno, carla):
    c.register(); c.login()
    linea(c.username, f"cuenta creada · clave pública X25519 {c.identity.dh_pub.hex()[:16]}…")

titulo(2, "Ana le escribe a Bruno")
ana.send("dm:bruno", "Hola Bruno, la clave del wifi es: TortugaVerde-2026")
r = bruno.sync()
for m in r["messages"]:
    linea("bruno recibe", f"{m['from']}: «{m['text']}»")

titulo(3, "Lo que ve el servidor (la base de datos del relay)")
con = sqlite3.connect(DB)
for to, frm, blob in con.execute("SELECT to_user, from_user, blob FROM mailbox ORDER BY seq"):
    linea(f"{frm} → {to}", blob[:70] + "…")
raw = open(DB, "rb").read()
linea("¿aparece 'Tortuga'?", "NO, está cifrado" if b"Tortuga" not in raw else "¡SÍ!")
linea("¿aparece la clave?", "NO" if PW.encode() not in raw else "¡SÍ!")
con.close()
print("      (2 filas: una para Bruno y otra copia cifrada para la propia Ana)")

titulo(4, "Bruno responde y Ana lo recibe")
bruno.send("dm:ana", "Gracias Ana, ya me conecté 👍")
ana.sync()
hist(ana, "dm:bruno", "ana")

titulo(5, "Ana abre su cuenta en un teléfono nuevo: el historial se reconstruye")
telefono = cliente("ana", "telefono")
telefono.login()
linea("teléfono", f"historial local antes de sincronizar: {len(telefono.history('dm:bruno'))} mensajes")
r = telefono.sync()
linea("teléfono", f"sincronizó {len(r['messages'])} mensajes desde el servidor")
hist(telefono, "dm:bruno", "teléfono")
telefono.send("dm:bruno", "Escribo desde el teléfono")
notebook = cliente("ana"); notebook.login(); notebook.sync()
linea("notebook de Ana", "ve lo enviado desde el teléfono:")
print(f"      {notebook.history('dm:bruno')[-1]['text']!r}")

titulo(6, "Grupo «Equipo» con Ana, Bruno y Carla")
conv = ana.create_group("Equipo", ["bruno", "carla"])
bruno.sync(); carla.sync()
carla.send(conv, "¿Reunión a las 10?")
bruno.send(conv, "Dale, ahí estoy")
for c in (ana, bruno, carla):
    c.sync()
linea("historial de ana", "")
hist(ana, conv, "ana")
print(f"      carla ve el grupo como: {carla.conversations()[0]['title']!r}")

titulo(7, "Alguien en el servidor altera un mensaje en tránsito")
ana.send("dm:bruno", "Transferí 100 a la cuenta 1234")
con = sqlite3.connect(DB)
blob, seq = con.execute("SELECT blob, seq FROM mailbox WHERE to_user='bruno' "
                        "ORDER BY seq DESC LIMIT 1").fetchone()
con.execute("UPDATE mailbox SET blob=? WHERE seq=?",
            (blob.replace('"ct":"', '"ct":"AAAA', 1), seq))
con.commit(); con.close()
r = bruno.sync()
linea("bruno", f"mensajes aceptados: {len(r['messages'])} · descartados por manipulación: {len(r['errors'])}")
print(f"      detalle: {r['errors'][0]['error']} (la firma/etiqueta no coincide)")

titulo(8, "Verificación de identidad: número de seguridad")
linea("ana ve", ana.safety_number("bruno"))
linea("bruno ve", bruno.safety_number("ana"))
print("      Si los dos números coinciden por otro canal, nadie se metió en el medio.")

titulo(9, "El servidor intenta cambiar la clave de Carla")
from e2ee_chat import crypto as C  # noqa: E402
falsa = C.Identity.generate()
con = sqlite3.connect(DB)
con.execute("UPDATE users SET dh_pub=?, sign_pub=? WHERE username='carla'",
            (C.b64(falsa.dh_pub), C.b64(falsa.sign_pub)))
con.commit(); con.close()
ana2 = cliente("ana"); ana2.login()
try:
    ana2.send("dm:carla", "mensaje privado")
except KeyChangedError as e:
    linea("ana", f"⚠ {str(e)[:78]}…")
    print("      El mensaje NO se envió.")

titulo(10, "Sin conexión: el mensaje espera y se manda al volver la red")
real = bruno.server
bruno.server = "http://127.0.0.1:1"
r = bruno.send("dm:ana", "Voy en el tren, sin señal")
linea("bruno", f"enviado={not r['pending']} · queda 'pendiente' en la bandeja de salida")
bruno.server = real
linea("bruno", f"vuelve la red → reenviados: {bruno.flush_outbox()}")
linea("ana recibe", ana.sync()["messages"][0]["text"])

print("\n\033[1;32m✔ Demo completo: todo funcionó sin que el servidor viera texto plano.\033[0m\n")
server.should_exit = True
