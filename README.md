# Chat cifrado de extremo a extremo con historial sincronizado

Servidor relay + cliente de terminal en Python. El servidor solo almacena y reenvía sobres
cifrados; las claves nunca salen de tus dispositivos en claro.

## Uso rápido
```bash
pip install -r requirements.txt
python -m e2ee_chat.serve --port 8443                      # servidor
python -m e2ee_chat.cli --user ana register                # crea la cuenta (pide contraseña)
python -m e2ee_chat.cli --user ana                         # chatear
```
Dentro del chat: `/dm bruno`, `/group equipo bruno carla`, `/list`, `/open 0`, `/history 50`,
`/safety bruno`, `/trust bruno`, `/help`, `/quit`.

**Otro dispositivo:** `python -m e2ee_chat.cli --user ana --data-dir ~/.e2ee_telefono` con el
mismo usuario y contraseña. Se descarga la bóveda de claves, se descifra localmente y se
reconstruye todo el historial desde el servidor.

## Cómo funciona
| Pieza | Detalle |
|---|---|
| Identidad | X25519 (acuerdo de claves) + Ed25519 (firmas), generadas en tu dispositivo |
| Contraseña | scrypt → dos claves independientes (HKDF): una de **acceso** (firma el login, la contraseña nunca viaja) y una de **bóveda** |
| Bóveda | Tus claves privadas, cifradas con AES-256-GCM; el servidor la guarda pero no puede abrirla |
| Mensaje | ECDH efímero + ECDH estático → HKDF → AES-256-GCM, más firma Ed25519; un sobre por destinatario |
| Historial | Cada mensaje también se cifra para vos mismo (copia propia). Un dispositivo nuevo recorre el buzón desde 0 y descifra todo |
| Disco local | SQLite con cuerpos, remitentes y nombres de conversación cifrados |
| Grupos | Reparto del mensaje a cada miembro (el servidor no sabe qué es un grupo) |
| Tiempo real | Long-polling; cola de salida si no hay red |
| Verificación | Número de seguridad por contacto; aviso si su clave cambia (TOFU) |

## Qué NO protege (leelo antes de usarlo en serio)
- **Metadatos**: el servidor ve quién le escribe a quién, cuándo y el tamaño aproximado.
- **Sin Double Ratchet**: hay claves efímeras por mensaje del lado del emisor, pero si alguien
  roba tu clave privada de identidad puede descifrar mensajes pasados. Signal/MLS resuelven esto
  con ratchets; es el siguiente paso natural.
- **Contraseña débil = bóveda débil**: quien controle el servidor puede intentar fuerza bruta
  offline contra la bóveda. Usá una contraseña larga.
- **TOFU**: la primera clave que ves de un contacto se acepta; verificá el número de seguridad.
- Desplegalo detrás de **HTTPS**. Los tokens de sesión viven en memoria del servidor
  (se pierden al reiniciar; el cliente vuelve a iniciar sesión).
- Sin adjuntos, sin borrado remoto, sin rotación de claves. Es un proyecto educativo/base, no
  un producto auditado.

## Pruebas
```bash
PYTHONPATH=. python -m unittest discover -s tests -v
```
12 pruebas de extremo a extremo con servidor y clientes reales: login, mensajes, historial en
dispositivo nuevo, grupos, manipulación de sobres, cambio de clave, long-polling, cola sin
conexión, y verificación de que ni el servidor ni el disco del cliente contienen texto plano.

## Video explicativo (2 min)
En `video/`:
- `video_mudo.mp4` — 1280×720, 120 s, sin subtítulos (ya renderizado).
- `guion.md` — narración por escena (voseo rioplatense).
- `make_voice.py` — genera la voz femenina argentina y la monta sobre el video:
  ```bash
  pip install piper-tts
  python -m piper.download_voices es_AR-daniela-high
  cd video && python make_voice.py        # → video_con_voz.mp4
  ```
- `make_video.py` — regenera las imágenes (`--preview` para ver fotogramas clave).
