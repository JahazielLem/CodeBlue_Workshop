"""V1 — run the REAL firmware SPP parser in an isolated subprocess.

The actual firmware code (firmware/spp.cpp) is compiled host-side and executed
as a short-lived child process with a timeout, so the deliberate out-of-bounds
read / off-by-one can only affect that child — never the server or another
student's session.  This is the one exercise that runs unmodified firmware code
(per the README) rather than a behavioural port.
"""
from __future__ import annotations

import os
import shutil
import subprocess

_LAB = os.path.dirname(os.path.abspath(__file__))
_V1 = os.path.join(_LAB, "v1")
_FIRMWARE = os.path.join(os.path.dirname(_LAB), "firmware")
_HARNESS_SRC = os.path.join(_V1, "spp_harness.cpp")
_SPP_SRC = os.path.join(_FIRMWARE, "spp.cpp")
_BIN = os.path.join(_V1, "spp_harness")

_built: tuple[bool, str] | None = None


def ensure_built() -> tuple[bool, str]:
    """Compile the harness if needed. Cached. (ok, message)."""
    global _built
    if _built is not None:
        return _built
    try:
        sources = [_HARNESS_SRC, _SPP_SRC]
        if os.path.isfile(_BIN) and all(
                os.path.getmtime(_BIN) >= os.path.getmtime(s) for s in sources):
            _built = (True, "already built")
            return _built
        cxx = shutil.which("clang++") or shutil.which("g++")
        if not cxx:
            _built = (False, "no C++ compiler (clang++ or g++) on PATH")
            return _built
        cmd = [cxx, "-O0", "-g", "-o", _BIN, _SPP_SRC, _HARNESS_SRC, "-I", _V1, "-I", _FIRMWARE]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        _built = (True, "built") if r.returncode == 0 else (False, f"build failed: {r.stderr[:300]}")
    except (OSError, subprocess.SubprocessError) as exc:
        _built = (False, f"build error: {exc}")
    return _built


def run_overread(hexpacket: str) -> dict:
    """Run the real parser on a packet. Returns parsed fields or {'crash': ...}."""
    try:
        r = subprocess.run([_BIN, hexpacket], capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        return {"crash": "timed out (possible hang)"}
    except OSError as exc:
        return {"crash": f"could not run harness: {exc}"}
    if r.returncode < 0:
        return {"crash": f"terminated by signal {-r.returncode} (memory fault)"}
    if r.returncode != 0:
        return {"crash": f"exit {r.returncode}: {r.stderr[:200]}"}
    out: dict = {}
    for line in r.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out
