"""Zero-dependency server for the Pwnsat browser lab (Stage-2 slice).

stdlib only: ThreadingHTTPServer serves the static SPA and upgrades /ws to a
hand-rolled WebSocket (no pip install, runs offline on a LAN workstation).  One
SatelliteSim + Terminal per session id; no satellite state is shared between
sessions.  Chosen for reproducibility/zero-install per the analysis; swap for
FastAPI+uvicorn if async scaling is needed later.

Run:  python3 lab/server.py --host 0.0.0.0 --port 8080
Then open http://<instructor-ip>:8080/ in each student's browser.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import satellite_sim as sim
import v1_overread as v1
from terminal import Terminal

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_CTYPES = {".html": "text/html; charset=utf-8", ".js": "application/javascript",
           ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml",
           ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}

# Instructor access. Change via INSTRUCTOR_PASSWORD env var; do not commit a real one.
INSTRUCTOR_PASSWORD = os.environ.get("INSTRUCTOR_PASSWORD", "changeme")
_TOKENS: dict[str, float] = {}        # token -> expiry (monotonic)
_TOKENS_LOCK = threading.Lock()
_TOKEN_TTL = 3600.0
_START = time.monotonic()


def issue_token() -> str:
    tok = secrets.token_urlsafe(24)
    with _TOKENS_LOCK:
        _TOKENS[tok] = time.monotonic() + _TOKEN_TTL
    return tok


def valid_token(tok: str) -> bool:
    with _TOKENS_LOCK:
        exp = _TOKENS.get(tok)
        if exp is None:
            return False
        if time.monotonic() > exp:
            _TOKENS.pop(tok, None)
            return False
        return True


def server_rss_mb() -> float:
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(os.getpid())],
                             capture_output=True, text=True, timeout=2).stdout.strip()
        return round(float(out) / 1024.0, 1) if out else 0.0
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0.0


class Session:
    def __init__(self, sid: str):
        self.sid = sid
        self.sim = sim.SatelliteSim(sid)
        self.terminal = Terminal()
        self.lock = threading.Lock()
        self.created = time.time()
        self.last_activity = time.time()
        self.cmd_count = 0
        self.tm_count = 0
        self.sim_errors = 0
        self.connections = 0

    def info(self) -> dict:
        now = time.time()
        return {"sid": self.sid, "age_s": int(now - self.created),
                "idle_s": int(now - self.last_activity), "commands": self.cmd_count,
                "tm": self.tm_count, "errors": self.sim_errors,
                "connections": self.connections,
                "mode": sim.MISSION_MODES.get(self.sim.mission_mode, "?"),
                "secure": self.sim.secure_link_enabled, "debug": self.sim.usb_debug_enabled,
                "gs": self.sim.gs_mode_enabled, "relays": self.sim.payload_forward_count}


class SessionManager:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def get(self, sid: str | None) -> Session:
        sid = sid or uuid.uuid4().hex[:8]
        with self._lock:
            s = self._sessions.get(sid)
            if s is None:
                s = Session(sid)
                self._sessions[sid] = s
            return s

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def list_info(self) -> list[dict]:
        with self._lock:
            return [s.info() for s in sorted(self._sessions.values(),
                                             key=lambda x: x.created)]

    def reset(self, sid: str) -> bool:
        with self._lock:
            s = self._sessions.get(sid)
        if not s:
            return False
        with s.lock:
            s.sim.reset()
            s.terminal = Terminal()
        return True

    def delete(self, sid: str) -> bool:
        with self._lock:
            return self._sessions.pop(sid, None) is not None

    def reset_all(self) -> int:
        with self._lock:
            sessions = list(self._sessions.values())
        for s in sessions:
            with s.lock:
                s.sim.reset()
                s.terminal = Terminal()
        return len(sessions)


MANAGER = SessionManager()


# --- WebSocket framing (RFC 6455, minimal) --------------------------------
def ws_send(conn: socket.socket, payload: str) -> None:
    data = payload.encode("utf-8")
    header = bytearray([0x81])  # FIN + text
    n = len(data)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += struct.pack(">H", n)
    else:
        header.append(127)
        header += struct.pack(">Q", n)
    conn.sendall(bytes(header) + data)


def ws_recv(conn: socket.socket) -> str | None:
    """Return next text message, or None on close/error."""
    try:
        b = _recv_exact(conn, 2)
        if b is None:
            return None
        opcode = b[0] & 0x0F
        masked = b[1] & 0x80
        length = b[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", _recv_exact(conn, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", _recv_exact(conn, 8))[0]
        mask = _recv_exact(conn, 4) if masked else b"\x00\x00\x00\x00"
        payload = _recv_exact(conn, length) if length else b""
        if payload is None:
            return None
        data = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        if opcode == 0x8:  # close
            return None
        if opcode == 0x9:  # ping -> pong
            conn.sendall(bytes([0x8A, len(data)]) + data)
            return ws_recv(conn)
        if opcode == 0x1:  # text
            return data.decode("utf-8", "replace")
        return ""  # ignore other opcodes
    except socket.timeout:
        raise  # idle: let serve_ws run a telemetry tick
    except (OSError, struct.error):
        return None


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except socket.timeout:
            raise
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


# --- per-connection session loop ------------------------------------------
def _send(conn, obj):
    ws_send(conn, json.dumps(obj))


def _push_reaction(conn, direction_hint, reaction, session=None):
    """Stream logs + dissected TM packets to the client."""
    for level, text in reaction.logs:
        _send(conn, {"type": "log", "ts": time.time(), "level": level, "text": text})
    for p in reaction.tm:
        _send(conn, {"type": "packet", "ts": time.time(), "dir": "rx",
                     "note": p.note, **sim.dissect(p.spp, "rx")})
    if session is not None:
        session.tm_count += len(reaction.tm)


def serve_ws(handler: BaseHTTPRequestHandler, sid: str | None):
    conn = handler.connection
    key = handler.headers.get("Sec-WebSocket-Key", "")
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    handler.send_response(101)
    handler.send_header("Upgrade", "websocket")
    handler.send_header("Connection", "Upgrade")
    handler.send_header("Sec-WebSocket-Accept", accept)
    handler.end_headers()

    session = MANAGER.get(sid)
    session.connections += 1
    conn.settimeout(1.0)  # so we can interleave telemetry ticks with recv
    _send(conn, {"type": "hello", "session": session.sid, "sessions": MANAGER.count(),
                 "exercise": "V4 — flash-window flag"})
    _send(conn, {"type": "log", "ts": time.time(), "level": "INFO",
                 "text": f"Satellite online. Session {session.sid}. Secure link ON."})

    try:
        while True:
            try:
                msg = ws_recv(conn)
            except socket.timeout:
                with session.lock:
                    _push_reaction(conn, "rx", session.sim.tick(), session)
                continue
            if msg is None:
                break
            if not msg:
                continue
            session.last_activity = time.time()
            try:
                _handle_msg(conn, session, json.loads(msg))
            except (ValueError, KeyError) as exc:
                _send(conn, {"type": "log", "ts": time.time(), "level": "ERROR",
                             "text": f"bad message: {exc}"})
            except Exception as exc:  # noqa: BLE001 — a sim fault is a health signal
                session.sim_errors += 1
                _send(conn, {"type": "log", "ts": time.time(), "level": "ERROR",
                             "text": f"simulator fault: {exc}"})
    finally:
        session.connections = max(0, session.connections - 1)


def _run_brute_force(conn, session: Session):
    cipher = session.sim.last_tm_cipher
    if not cipher:
        _send(conn, {"type": "term", "text":
                     "no encrypted telemetry captured yet — keep the secure link ON and "
                     "wait for a STATUS packet, then retry."})
        return
    _send(conn, {"type": "term", "text":
                 f"dictionary attack on {len(cipher)}B of captured AES-128-ECB ciphertext..."})
    hit = None
    for row in sim.dictionary_attack(cipher):
        mark = "  <<< KEY FOUND" if row["result"] == "MATCH" else ""
        _send(conn, {"type": "term", "text": f"  try {row['key']!r:20} -> {row['result']}{mark}"})
        if row["result"] == "MATCH":
            hit = row
    if hit:
        _send(conn, {"type": "term", "text": f"recovered AES-128 key: {hit['key']!r}"})
        _send(conn, {"type": "log", "ts": time.time(), "level": "WARN",
                     "text": f"Link key recovered by dictionary attack: {hit['key']}"})
    else:
        _send(conn, {"type": "term", "text": "no candidate key matched."})


def _run_overread(conn, session: Session, hexpacket: str):
    import pwnsat_protocol as pp
    raw = bytes.fromhex(hexpacket)
    # Show the crafted packet in the analyzer (the hardened dissector flags it).
    _send(conn, {"type": "packet", "ts": time.time(), "dir": "tx",
                 "note": "crafted over-read", **sim.dissect(raw, "tx")})
    # Contrast 1: the hardened ground-tool parser validates length and rejects it.
    try:
        pp.parse_spp(raw)
        _send(conn, {"type": "term", "text": "ground-tool parser (spp_parser.py): accepted (unexpected!)"})
    except ValueError as exc:
        _send(conn, {"type": "term", "text": f"ground-tool parser (spp_parser.py): REJECTED — {exc}"})
    # Contrast 2: the REAL firmware parser trusts the declared length.
    ok, build_msg = v1.ensure_built()
    if not ok:
        _send(conn, {"type": "term", "text":
                     f"firmware parser unavailable ({build_msg}). V1 needs a C++ compiler; "
                     "the other exercises do not."})
        return
    res = v1.run_overread(hexpacket)
    if "crash" in res:
        _send(conn, {"type": "term", "text": f"firmware parser (real spp_unpack_packet): {res['crash']}"})
        _send(conn, {"type": "log", "ts": time.time(), "level": "ERROR",
                     "text": f"SPP parser fault on crafted packet: {res['crash']}"})
        return
    _send(conn, {"type": "term", "text":
                 f"firmware parser (real spp_unpack_packet): ret={res.get('ret')}  "
                 f"buffer had {res.get('buffer_len')} bytes but declared {res.get('declared_len')} "
                 f"-> copied {res.get('copied')} bytes"})
    leaked = bytes.fromhex(res.get("data", ""))
    ascii_leak = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in leaked)
    _send(conn, {"type": "term", "text": f"space_packet.data (leaked): {res.get('data')}"})
    _send(conn, {"type": "term", "text": f"                   as ASCII: |{ascii_leak}|"})
    if b"PWNSAT{" in leaked:
        flag = leaked[leaked.index(b"PWNSAT{"):].split(b"}")[0] + b"}"
        _send(conn, {"type": "term", "text":
                     f"over-read leaked adjacent memory: {flag.decode('latin1')}"})
        _send(conn, {"type": "log", "ts": time.time(), "level": "WARN",
                     "text": "SPP parser over-read leaked adjacent memory into the packet buffer"})


def _handle_msg(conn, session: Session, msg: dict):
    kind = msg.get("type")
    if kind == "cmd":
        session.cmd_count += 1
        result = session.terminal.execute(msg.get("line", ""))
        for ln in result["echo"]:
            _send(conn, {"type": "term", "text": ln})
        if result["action"] == "clear":
            _send(conn, {"type": "clear"})
        elif result["action"] == "brute_force":
            _run_brute_force(conn, session)
            return
        elif result["action"] == "v1_overread":
            _run_overread(conn, session, result.get("v1_hex", ""))
            return
        with session.lock:
            for frame in result["frames"]:
                # show the uplink packet too (strip the AA55 envelope for the SPP view)
                spp = frame[4:]
                _send(conn, {"type": "packet", "ts": time.time(), "dir": "tx",
                             "note": "uplink", **sim.dissect(spp, "tx")})
                _push_reaction(conn, "rx", session.sim.ingest_frame_bytes(frame), session)
    elif kind == "reset":
        with session.lock:
            session.sim.reset()
            session.terminal = Terminal()
        _send(conn, {"type": "clear"})
        _send(conn, {"type": "log", "ts": time.time(), "level": "WARN",
                     "text": "Satellite reset by operator. State restored to defaults."})
    elif kind == "raw":
        import pwnsat_protocol as pp
        try:
            spp = pp.parse_hex(msg.get("hex", ""))
        except ValueError as exc:
            _send(conn, {"type": "term", "text": f"error: {exc}"})
            return
        frame = pp.make_frame(spp)
        with session.lock:
            _send(conn, {"type": "packet", "ts": time.time(), "dir": "tx",
                         "note": "raw uplink", **sim.dissect(spp, "tx")})
            _push_reaction(conn, "rx", session.sim.ingest_frame_bytes(frame), session)


# --- HTTP + upgrade --------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        path = self.path.split("?", 1)
        route = path[0]
        if route == "/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            sid = None
            if len(path) > 1:
                for kv in path[1].split("&"):
                    if kv.startswith("session="):
                        sid = kv[len("session="):] or None
            serve_ws(self, sid)
            return
        if route == "/api/instructor/sessions":
            token = ""
            if len(path) > 1:
                for kv in path[1].split("&"):
                    if kv.startswith("token="):
                        token = kv[len("token="):]
            if not valid_token(token):
                return self._json(403, {"error": "unauthorized"})
            return self._json(200, {
                "server": {"rss_mb": server_rss_mb(), "sessions": MANAGER.count(),
                           "uptime_s": int(time.monotonic() - _START)},
                "sessions": MANAGER.list_info()})
        self._serve_static(route)

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        body = self._read_json()
        if route == "/api/instructor/login":
            if hmac.compare_digest(str(body.get("password", "")), INSTRUCTOR_PASSWORD):
                return self._json(200, {"token": issue_token()})
            time.sleep(0.5)  # token-guessing / brute-force speed bump
            return self._json(403, {"error": "wrong password"})
        if not valid_token(str(body.get("token", ""))):
            return self._json(403, {"error": "unauthorized"})
        if route == "/api/instructor/reset":
            ok = MANAGER.reset(str(body.get("sid", "")))
            return self._json(200 if ok else 404, {"ok": ok})
        if route == "/api/instructor/delete":
            ok = MANAGER.delete(str(body.get("sid", "")))
            return self._json(200 if ok else 404, {"ok": ok})
        if route == "/api/instructor/reset-all":
            return self._json(200, {"ok": True, "count": MANAGER.reset_all()})
        return self._json(404, {"error": "unknown route"})

    def _read_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, TypeError):
            return {}

    def _json(self, status: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, route: str):
        rel = "index.html" if route == "/" else route.lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            self.send_error(404)
            return
        with open(full, "rb") as fh:
            body = fh.read()
        ext = os.path.splitext(full)[1]
        self.send_response(200)
        self.send_header("Content-Type", _CTYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1", help="bind address (use 0.0.0.0 for LAN)")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Pwnsat lab on http://{args.host}:{args.port}/  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
        server.shutdown()


if __name__ == "__main__":
    main()
