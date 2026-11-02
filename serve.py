"""Arranque del servidor:  python -m e2ee_chat.serve --port 8443"""
import argparse

import uvicorn

from .server import create_app

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--db", default=None)
    a = ap.parse_args()
    uvicorn.run(create_app(a.db), host=a.host, port=a.port, log_level="warning")
