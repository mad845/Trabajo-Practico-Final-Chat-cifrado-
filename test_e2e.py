"""Pruebas de extremo a extremo: servidor real (uvicorn) + clientes reales.

  python -m unittest discover -s tests -v
"""
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest

os.environ["E2EE_SCRYPT_N"] = str(2**10)  # rápido para tests

import uvicorn  # noqa: E402

from e2ee_chat import crypto as C  # noqa: E402
from e2ee_chat.client import ChatClient, ChatError, KeyChangedError  # noqa: E402
from e2ee_chat.server import create_app  # noqa: E402

PW = "una-contraseña-bien-larga"


class E2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = os.path.join(cls.tmp, "server.db")
        s = socket.socket(); s.bind(("127.0.0.1", 0)); cls.port = s.getsockname()[1]; s.close()
        cls.server = uvicorn.Server(uvicorn.Config(
            create_app(cls.db), host="127.0.0.1", port=cls.port, log_level="error"))
        threading.Thread(target=cls.server.run, daemon=True).start()
        while not cls.server.started:
            time.sleep(0.05)
        cls.url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True

    def client(self, user, device="d1", pw=PW):
        return ChatClient(self.url, user, pw, os.path.join(self.tmp, device))

    def make(self, user, device="d1"):
        c = self.client(user, device)
        c.register(); c.login()
        return c

    # ------------------------------------------------------------ pruebas
    def test_01_cuentas_y_login(self):
        self.make("alice"); self.make("bob"); self.make("carol")
        with self.assertRaises(ChatError) as cm:
            self.client("alice", pw="otra-contraseña-incorrecta").login()
        self.assertEqual(cm.exception.status, 401)
        with self.assertRaises(ChatError) as cm:  # usuario inexistente: mismo error
            self.client("nadie").login()
        self.assertEqual(cm.exception.status, 401)
        with self.assertRaises(ChatError) as cm:
            self.client("alice").register()
        self.assertEqual(cm.exception.status, 409)

    def test_02_mensajes_directos_e_historial(self):
        a, b = self.client("alice"), self.client("bob")
        a.login(); b.login()
        a.send("dm:bob", "hola bob, secreto-123")
        r = b.sync()
        self.assertEqual([m["text"] for m in r["messages"]], ["hola bob, secreto-123"])
        self.assertEqual(r["messages"][0]["from"], "alice")
        b.send("dm:alice", "hola alice")
        self.assertEqual(a.sync()["messages"][0]["text"], "hola alice")
        self.assertEqual([m["text"] for m in a.history("dm:bob")],
                         ["hola bob, secreto-123", "hola alice"])

    def test_03_el_servidor_solo_ve_texto_cifrado(self):
        raw = open(self.db, "rb").read()
        for needle in (b"secreto-123", b"hola alice", PW.encode()):
            self.assertNotIn(needle, raw)
        local = open(os.path.join(self.tmp, "d1", "alice.db"), "rb").read()
        self.assertNotIn(b"secreto-123", local)  # tampoco en el disco del cliente

    def test_04_dispositivo_nuevo_recupera_todo_el_historial(self):
        phone = self.client("alice", device="phone")
        phone.login()
        self.assertEqual(phone.history("dm:bob"), [])
        r = phone.sync()
        self.assertEqual(len(r["messages"]), 2)  # enviado y recibido
        self.assertEqual([m["text"] for m in phone.history("dm:bob")],
                         ["hola bob, secreto-123", "hola alice"])
        phone.send("dm:bob", "escrito desde el teléfono")
        laptop = self.client("alice"); laptop.login()
        laptop.sync()  # el otro dispositivo ve lo enviado desde el teléfono
        self.assertEqual(laptop.history("dm:bob")[-1]["text"], "escrito desde el teléfono")

    def test_05_grupos(self):
        a, b, c = (self.client(u) for u in ("alice", "bob", "carol"))
        for x in (a, b, c):
            x.login(); x.sync()
        conv = a.create_group("equipo", ["bob", "carol"])
        b.sync(); c.sync()
        a.send(conv, "reunión a las 10")
        c.send(conv, "ok, ahí estoy")
        for x in (a, b, c):
            x.sync()
            self.assertEqual([m["text"] for m in x.history(conv)][-2:],
                             ["reunión a las 10", "ok, ahí estoy"])
        self.assertEqual(c.conversations()[0]["title"], "equipo")

    def test_06_manipulacion_se_detecta(self):
        a, b = self.client("alice"), self.client("bob")
        a.login(); b.login(); b.sync()
        a.send("dm:bob", "mensaje legítimo")
        con = sqlite3.connect(self.db)
        (blob, seq) = con.execute(
            "SELECT blob, seq FROM mailbox WHERE to_user='bob' ORDER BY seq DESC LIMIT 1").fetchone()
        con.execute("UPDATE mailbox SET blob=? WHERE seq=?",
                    (blob.replace('"ct":"', '"ct":"AAAA', 1), seq))
        con.commit(); con.close()
        r = b.sync()
        self.assertEqual(r["messages"], [])
        self.assertEqual(len(r["errors"]), 1)  # descartado, sin romper la sincronización

    def test_07_no_se_puede_reenviar_un_sobre_a_otro_destinatario(self):
        a = self.client("alice"); a.login()
        bob_dh = a._peer_keys("bob")[0]
        env = C.encrypt_for(a.identity, "alice", "bob", bob_dh, b"x")
        c = self.client("carol"); c.login()
        with self.assertRaises(Exception):
            C.decrypt_from(c.identity, "carol", "alice", *a._peer_keys("alice"), env)

    def test_08_cambio_de_clave_de_contacto(self):
        a = self.client("alice"); a.login()
        a.send("dm:carol", "primer contacto")  # fija la clave de carol
        new = C.Identity.generate()
        con = sqlite3.connect(self.db)
        con.execute("UPDATE users SET dh_pub=?, sign_pub=? WHERE username='carol'",
                    (C.b64(new.dh_pub), C.b64(new.sign_pub)))
        con.commit(); con.close()
        a2 = self.client("alice"); a2.login()  # sesión nueva: vuelve a consultar al servidor
        with self.assertRaises(KeyChangedError):
            a2.send("dm:carol", "¿sigue siendo carol?")
        self.assertNotIn("¿sigue siendo carol?",
                         [m["text"] for m in a2.history("dm:carol")])
        a2.trust_new_key("carol")  # tras verificar el número de seguridad
        a2.send("dm:carol", "ahora sí")

    def test_09_tiempo_real_long_polling(self):
        a, b = self.client("alice"), self.client("bob")
        a.login(); b.login(); b.sync()
        got = {}
        t = threading.Thread(target=lambda: got.update(b.sync(wait=10)))
        t0 = time.time(); t.start(); time.sleep(0.5)
        a.send("dm:bob", "ping en vivo")
        t.join(8)
        self.assertEqual([m["text"] for m in got["messages"]], ["ping en vivo"])
        self.assertLess(time.time() - t0, 5)

    def test_10_bandeja_de_salida_sin_red(self):
        a, b = self.client("alice"), self.client("bob")
        a.login(); b.login(); b.sync()
        good = a.server
        a.server = "http://127.0.0.1:1"  # sin conexión
        r = a.send("dm:bob", "mensaje en el túnel")
        self.assertTrue(r["pending"])
        self.assertTrue(a.history("dm:bob")[-1]["pending"])
        a.server = good
        self.assertEqual(a.flush_outbox(), 1)
        self.assertEqual([m["text"] for m in b.sync()["messages"]], ["mensaje en el túnel"])
        self.assertFalse(a.history("dm:bob")[-1]["pending"])

    def test_11_numero_de_seguridad_coincide(self):
        a, b = self.client("alice"), self.client("bob")
        a.login(); b.login()
        self.assertEqual(a.safety_number("bob"), b.safety_number("alice"))

    def test_12_autenticacion_requerida(self):
        import requests
        for path in ("/api/sync", "/api/vault", "/api/users/bob"):
            self.assertEqual(requests.get(self.url + path).status_code, 401)
        self.assertEqual(requests.post(self.url + "/api/send", json={"messages": []}).status_code, 401)


if __name__ == "__main__":
    unittest.main()
