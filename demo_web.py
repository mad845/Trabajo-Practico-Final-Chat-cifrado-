"""Levanta todo para probar la interfaz web en tu navegador: relay + programa web.

  PYTHONPATH=. python demo_web.py

Abrí http://127.0.0.1:5000 en DOS pestañas (o una normal y una privada),
creá "ana" en una y "bruno" en la otra (marcá "Crear cuenta nueva") y chateá.
"""
import tempfile
import threading
import time

import uvicorn

from e2ee_chat.server import create_app as relay_app
from e2ee_chat.web import create_app as web_app

tmp = tempfile.mkdtemp()
RELAY, WEB = 8443, 5000
relay = uvicorn.Server(uvicorn.Config(relay_app(f"{tmp}/relay.db"), host="127.0.0.1",
                                      port=RELAY, log_level="warning"))
threading.Thread(target=relay.run, daemon=True).start()
while not relay.started:
    time.sleep(0.05)
print(f"Relay en http://127.0.0.1:{RELAY}")
print(f"Interfaz web: http://127.0.0.1:{WEB}   (Ctrl+C para salir)")
uvicorn.run(web_app(f"{tmp}/web", f"http://127.0.0.1:{RELAY}"), host="127.0.0.1",
            port=WEB, log_level="warning")
