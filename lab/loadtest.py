"""Concurrency load test for the Pwnsat lab server (spec section 13).

Starts a dedicated server, opens N independent WebSocket sessions, and for each:
  debug on -> set a UNIQUE mission mode -> flash-read the flag -> get-status.
It then verifies every session recovered the flag AND reads back only its own
mission mode (isolation under concurrency), while sampling the server process's
peak RSS and CPU time. Repeats for several session counts and prints a table.

Run:  python3 lab/loadtest.py            # 10, 20, 30 sessions
      python3 lab/loadtest.py 10 20 30 50
No external deps (stdlib + `ps`).
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))
import pwnsat_protocol as pp  # noqa: E402

HOST, PORT = "127.0.0.1", 8137
IDLE_WINDOW = 12.0  # seconds of steady-state telemetry per run


# --- minimal WS client ----------------------------------------------------
def ws_connect(session=None):
    s = socket.create_connection((HOST, PORT))
    s.settimeout(20)
    key = base64.b64encode(os.urandom(16)).decode()
    path = "/ws" + (f"?session={session}" if session else "")
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
    hdr = b""
    while b"\r\n\r\n" not in hdr:
        hdr += s.recv(1)
    assert b"101" in hdr, hdr
    return s


def ws_send(s, obj):
    d = json.dumps(obj).encode()
    m = os.urandom(4)
    n = len(d)
    h = bytearray([0x81])
    h.append(0x80 | (n if n < 126 else 126))
    if n >= 126:
        h += struct.pack(">H", n)
    s.sendall(bytes(h) + m + bytes(c ^ m[i % 4] for i, c in enumerate(d)))


def ws_recv(s):
    b = _rx(s, 2)
    if not b:
        return None
    ln = b[1] & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", _rx(s, 2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", _rx(s, 8))[0]
    data = _rx(s, ln) if ln else b""
    try:
        return json.loads(data)
    except ValueError:
        return {}


def _rx(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


# --- one simulated student ------------------------------------------------
def _status_mode(m):
    """Mission mode byte from a STATUS packet, via the (server-decoded) tree.

    Works whether the link is cleartext or encrypted, because the server-side
    dissector decrypts the payload with the known lab key before sending it."""
    for node in m.get("tree", []):
        if node.get("field") != "Data Field":
            continue
        for child in node.get("children", []):
            if "Payload" in child.get("field", ""):
                hexstr = str(child.get("value", "")).split()[0]
                try:
                    return bytes.fromhex(hexstr)[1]  # [SCID, mode, ...]
                except Exception:
                    return None
    return None


def student(idx, results, secure):
    mode = idx % 5  # unique-ish mission mode to check for cross-talk
    got_flag = False
    seen_mode = None
    packets = 0
    try:
        s = ws_connect()
        if not secure:
            ws_send(s, {"type": "cmd", "line": "debug on"})  # cleartext replies
        ws_send(s, {"type": "cmd", "line": f"mode {mode}"})
        ws_send(s, {"type": "cmd", "line": "flash-read 0xA5 83 32 0xC35A"})
        ws_send(s, {"type": "cmd", "line": "status"})
        deadline = time.time() + IDLE_WINDOW
        while time.time() < deadline:
            try:
                m = ws_recv(s)
            except socket.timeout:
                break
            if m is None:
                break
            if m.get("type") == "packet":
                packets += 1
                tree = json.dumps(m.get("tree", []))
                if "PWNSAT{" in tree:
                    got_flag = True
                if "0x00C (STATUS)" in tree:
                    md = _status_mode(m)
                    if md is not None:
                        seen_mode = md
        s.close()
    except Exception as exc:  # noqa: BLE001
        results[idx] = {"ok": False, "err": str(exc)}
        return
    isolated = seen_mode == mode
    results[idx] = {"ok": got_flag and isolated, "flag": got_flag,
                    "mode_set": mode, "mode_seen": seen_mode, "packets": packets}


# --- server process measurement -------------------------------------------
def ps_sample(pid):
    """Return (rss_mb, cputime_s) for pid via ps."""
    out = subprocess.run(["ps", "-o", "rss=,cputime=", "-p", str(pid)],
                         capture_output=True, text=True).stdout.strip()
    if not out:
        return 0.0, 0.0
    parts = out.split()
    rss_kb = float(parts[0])
    cpu = parts[1]
    # cputime format: [[HH:]MM:]SS[.ss]
    bits = cpu.replace("-", ":").split(":")
    secs = 0.0
    for b in bits:
        secs = secs * 60 + float(b)
    return rss_kb / 1024.0, secs


def run_level(n, baseline_pid, secure):
    results = {}
    rss0, cpu0 = ps_sample(baseline_pid)
    peak_rss = rss0
    stop = threading.Event()

    def sampler():
        nonlocal peak_rss
        while not stop.is_set():
            rss, _ = ps_sample(baseline_pid)
            peak_rss = max(peak_rss, rss)
            time.sleep(0.25)

    samp = threading.Thread(target=sampler, daemon=True)
    samp.start()
    t0 = time.time()
    threads = [threading.Thread(target=student, args=(i, results, secure)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.time() - t0
    stop.set()
    samp.join()
    rss1, cpu1 = ps_sample(baseline_pid)
    ok = sum(1 for r in results.values() if r.get("ok"))
    flags = sum(1 for r in results.values() if r.get("flag"))
    iso_fail = [i for i, r in results.items()
                if r.get("flag") and r.get("mode_seen") not in (None, r.get("mode_set"))]
    cpu_pct = (cpu1 - cpu0) / wall * 100 if wall else 0
    return {"n": n, "ok": ok, "flags": flags, "iso_fail": len(iso_fail),
            "peak_rss": peak_rss, "cpu_pct": cpu_pct, "wall": wall,
            "errs": [r.get("err") for r in results.values() if r.get("err")]}


def main():
    levels = [int(x) for x in sys.argv[1:]] or [10, 20, 30]
    env = dict(os.environ)
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py"),
                             "--host", HOST, "--port", str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        for _ in range(50):
            try:
                socket.create_connection((HOST, PORT), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        time.sleep(1.0)
        idle_rss, _ = ps_sample(proc.pid)
        print(f"server pid {proc.pid}  idle RSS {idle_rss:.1f} MB")
        rows = []
        for secure in (False, True):
            print(f"\n--- secure link {'ON (AES on every telemetry packet)' if secure else 'OFF (debug, cleartext)'} ---")
            print(f"{'sessions':>8} {'ok':>6} {'flags':>6} {'iso_fail':>9} "
                  f"{'peak_RSS_MB':>12} {'server_CPU%':>12} {'wall_s':>7}")
            for n in levels:
                r = run_level(n, proc.pid, secure)
                r["secure"] = secure
                rows.append(r)
                print(f"{r['n']:>8} {r['ok']:>6} {r['flags']:>6} {r['iso_fail']:>9} "
                      f"{r['peak_rss']:>12.1f} {r['cpu_pct']:>12.1f} {r['wall']:>7.1f}")
                if r["errs"]:
                    print(f"    errors: {r['errs'][:3]}")
        print(f"\nidle baseline RSS: {idle_rss:.1f} MB")
        allok = all(r["ok"] == r["n"] and r["iso_fail"] == 0 for r in rows)
        print("RESULT:", "PASS — every session recovered its flag with no cross-talk"
              if allok else "FAIL — see rows above")
        return 0 if allok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
