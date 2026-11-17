"""Per-student Pwnsat satellite simulator (behavioral port of the firmware).

This reuses ``tools/pwnsat_protocol.py`` as the ground-truth SPP + AES core, so
the simulator and the student tools encode/decode bytes identically.  The
command dispatch mirrors ``firmware/worker.cpp`` ``commandHandlerInternal`` /
``commandApidHandler``; file:line references in comments point at the C source
each handler reproduces.

Fidelity note: this is a *behavioral* port of worker.cpp (Arduino/hardware deps
make direct execution impractical).  The SPP/AES bytes are produced by the same
Python module the students use, so wire-format fidelity is exact; mission logic
is reproduced, not the original machine code.  The V1 SPP parser over-read is
NOT reproduced here yet (deferred to the compiled-spp.c path in the analysis).
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field

# Reuse the exact protocol module the workshop tools import.
_TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

import pwnsat_protocol as pp  # noqa: E402

# --- APIDs (mission.h) ----------------------------------------------------
TC_PING = 0x01
TC_RESETC = 0x02
TC_SEND_FW = 0x03
TC_BROADCAST_MSG = 0x06
TC_FLASH = 0x07
TC_GET_PAYLOAD_STATUS = 0x0F
TM_BROADCAST = 0x06
TM_PAYLOAD_STATUS = 0x0F
TC_AES_CONFIG = 0x0A
TC_FLASH_READ = 0x0B
TC_GET_STATUS = 0x0C
TC_SET_MISSION_MODE = 0x0D
TC_GET_NAV = 0x0E
TC_DEBUG_CONFIG = 0x10
TC_GS_MODE = 0x11
TC_GS_ACCESS = 0x12
TC_GS_STATUS = 0x13

TM_PING = 0x01
TM_SEND_FW = 0x03
TM_ERROR = 0x09
TM_AES_CONFIG = 0x0A
TM_FLASH_READ = 0x0B
TM_STATUS = 0x0C
TM_MISSION_MODE = 0x0D
TM_IDLE = 0x3FF  # SPP_APID_IDLE = 0b1111111111 (spp.h) -> 10 ones = 0x3FF

SPACECRAFT_ID = pp.SPACECRAFT_ID

# flash window secret (worker.cpp:116-120) + gate constants (worker.cpp:113-115)
FLASH_WINDOW_ID = 0xA5
FLASH_UNLOCK_TAG = 0xC35A
FLASH_READ_MAX_BYTES = 32
FLASH_WINDOW_BLOB = (
    b"OPS:STORE_FORWARD=ENABLED\n"
    b"OPS:PAYLOAD_WINDOW=0420Z\n"
    b"MAINT:FLASH_WINDOW=A5:C35A\n"
    b"FLAG=PWNSAT{flash_window_store_and_forward}\n"
)

MISSION_MODES = {0: "SAFE", 1: "NOMINAL", 2: "PAYLOAD", 3: "SCIENCE", 4: "CONTINGENCY"}

# Ground-station auth (worker.cpp:127,234) — the V3 vulnerability constant.
GS_SHARED_AUTH_KEY = 0xC0DEFACE
GS_SESSION_WINDOW_S = 300.0
GS_HANDSHAKE_WINDOW_S = 60.0


def gs_expected_response(challenge: int) -> int:
    """worker.cpp:234 — expected = challenge XOR shared key (forgeable)."""
    return (challenge ^ GS_SHARED_AUTH_KEY) & 0xFFFFFFFF


# V6: AES-128 key dictionary attack (mirrors tools/brute_spp.py).
def _load_candidate_keys() -> list[bytes]:
    """Read the lab wordlist (keys.txt at the repo root)."""
    path = os.path.join(os.path.dirname(_TOOLS), "keys.txt")
    keys = []
    try:
        with open(path, "rb") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith(b"#"):
                    keys.append(line)
    except OSError:
        pass
    return keys


CANDIDATE_KEYS = _load_candidate_keys()


def dictionary_attack(ciphertext: bytes) -> list[dict]:
    """Try each candidate key against captured ciphertext (AES-128-ECB).

    A key is a hit when its plaintext has a valid length marker AND the decoded
    payload begins with the spacecraft id — the same structure secure_decode
    expects. Returns one row per key with its result (and plaintext on a hit)."""
    import struct
    rows = []
    if not ciphertext or len(ciphertext) % 16:
        return rows
    for key in CANDIDATE_KEYS:
        if len(key) != 16:
            rows.append({"key": key.decode("latin1"), "result": "skipped (not 16 bytes)"})
            continue
        try:
            plain = b"".join(pp._decrypt_block(ciphertext[i:i + 16], key)
                             for i in range(0, len(ciphertext), 16))
            plen = struct.unpack(">H", plain[:2])[0]
            payload = plain[2:2 + plen]
            hit = plen <= len(ciphertext) - 2 and payload and payload[0] == SPACECRAFT_ID
        except Exception:
            hit, payload = False, b""
        rows.append({"key": key.decode("latin1"), "result": "MATCH" if hit else "no",
                     "plaintext": payload.hex() if hit else None})
    return rows


def crc8(data: bytes) -> int:
    """CRC-8 poly 0x07, init 0x00 (worker.cpp:145 crc8_compute)."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if (crc & 0x80) else (crc << 1) & 0xFF
    return crc


@dataclass
class OutPacket:
    """A simulated downlink (TM) packet, as a raw SPP byte string."""

    spp: bytes
    note: str = ""


@dataclass
class Reaction:
    """Result of ingesting one uplink: downlink packets + console log lines."""

    tm: list[OutPacket] = field(default_factory=list)
    logs: list[tuple[str, str]] = field(default_factory=list)  # (level, text)


class SatelliteSim:
    """One isolated satellite.  No state is shared between instances."""

    def __init__(self, session_id: str, now: float | None = None):
        self.session_id = session_id
        self._parser = pp.FrameParser()
        self._tm_seq = 0
        self.reset(now)

    def reset(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self.boot_time = now
        self.secure_link_enabled = True     # firmware default (secure_link.cpp:16)
        self.usb_debug_enabled = False
        self.mission_mode = 1               # NOMINAL (worker.cpp:99)
        self.payload_armed = False
        self._tm_seq = 0
        self._parser = pp.FrameParser()
        self._last_status_tm = now
        self._last_idle_tm = now
        # Ground-station mode (worker.cpp:98-111). GPS is abstracted to "usable
        # and in range" for this slice so V3 focuses on the auth forge; the full
        # geofence / GPS-spoofing surface is a later exercise.
        self.gps_usable = True
        self.gps_in_range = True
        self.gs_mode_enabled = False
        self.gs_challenge = 0
        self._gs_session_expires = 0.0
        self._gs_challenge_expires = 0.0
        # Payload relay / store-and-forward counters (worker.cpp:35-37).
        self.last_payload_frequency = 0
        self.payload_forward_count = 0
        self.last_payload_length = 0
        self.last_tm_cipher: bytes | None = None  # most recent encrypted TM (V6 target)

    # --- helpers ----------------------------------------------------------
    def _next_seq(self) -> int:
        self._tm_seq = (self._tm_seq + 1) & 0x3FFF
        return self._tm_seq

    def _encrypt_tm(self) -> bool:
        # telemetrySPPBuildPacketEx: encrypt unless usb-debug bypasses (worker.cpp:603)
        return self.secure_link_enabled and not self.usb_debug_enabled

    def _build_tm(self, apid: int, app_payload: bytes, force_cleartext: bool = False) -> bytes:
        encrypted = self._encrypt_tm() and not force_cleartext
        payload = pp.encode_tm_payload(app_payload, encrypted)
        if encrypted:
            self.last_tm_cipher = payload[1:]  # ciphertext after the 0x01 flag (for V6)
        return pp.build_spp(apid, payload, packet_type=pp.SPP_TYPE_TM,
                            sequence_count=self._next_seq())

    def _error_tm(self, message: str) -> OutPacket:
        app = bytes([SPACECRAFT_ID]) + message.encode()[: pp.SPP_MAX_PAYLOAD_CHUNK - 2] + b"\x00"
        return OutPacket(self._build_tm(TM_ERROR, app), f"ERROR: {message}")

    # --- ingress (mirrors commandHandlerInternal, worker.cpp:1546) --------
    def ingest_frame_bytes(self, chunk: bytes) -> Reaction:
        """Feed raw AA55 transport bytes; dispatch each complete SPP packet."""
        out = Reaction()
        for spp in self._parser.feed(chunk):
            r = self.ingest_spp(spp)
            out.tm.extend(r.tm)
            out.logs.extend(r.logs)
        return out

    def ingest_spp(self, raw: bytes) -> Reaction:
        out = Reaction()
        try:
            pkt = pp.parse_spp(raw)
        except ValueError as exc:
            out.logs.append(("ERROR", f"Unpacking SPP: {exc}"))
            out.tm.append(self._error_tm("SPP PARSE ERROR"))
            return out

        apid = pkt.apid
        name = pp.TM_APID_NAMES.get(apid, "UNKNOWN")
        out.logs.append(("TC", f"[TC - SPP] APID=0x{apid:03X} ({name}) "
                               f"SEQ={pkt.sequence_count} LEN={len(pkt.data)} "
                               f"SEC_HDR={'YES' if pkt.secondary_header else 'NO'}"))

        data = pkt.data
        # AES/DEBUG toggles handled before decrypt (worker.cpp:1560)
        if apid in (TC_AES_CONFIG, TC_DEBUG_CONFIG):
            state = self._extract_toggle(data)
            if apid == TC_DEBUG_CONFIG:
                self._handle_debug(state, out)
            else:
                self._handle_aes(state, out)
            return out

        # secureLinkDecodeInPlace (worker.cpp:641): decrypt if secure & not debug
        if self.secure_link_enabled and not self.usb_debug_enabled:
            try:
                data = pp.secure_decode(data)
            except ValueError:
                out.logs.append(("ERROR", "Secure link payload decrypt failed"))
                out.tm.append(self._error_tm("AES DECRYPT FAIL"))
                return out

        allowed, reason = self._gs_allowed(apid, data)
        if not allowed:
            out.logs.append(("WARN", f"Ground station gate rejected APID 0x{apid:03X}: {reason}"))
            out.tm.append(self._error_tm(reason))
            out.tm.append(OutPacket(self._build_tm(TC_GS_STATUS, self._gs_status_payload()),
                                    "GS STATUS"))
            return out

        self._dispatch(apid, data, out)
        return out

    # --- ground station gate (worker.cpp:343 groundStationCommandAllowed) --
    def _gs_session_active(self) -> bool:
        return self.gs_mode_enabled and time.monotonic() < self._gs_session_expires

    def _gs_handshake_pending(self) -> bool:
        return self.gs_challenge != 0 and time.monotonic() < self._gs_challenge_expires

    def _gs_allowed(self, apid: int, data: bytes) -> tuple[bool, str | None]:
        if not self.gs_mode_enabled:
            return True, None
        if apid in (TC_DEBUG_CONFIG, TC_GS_ACCESS, TC_GS_STATUS):
            return True, None
        if apid == TC_GS_MODE:  # enabling is always allowed; disabling needs auth/debug
            if data and data[0] != 0:
                return True, None
            if self.usb_debug_enabled:
                return True, None
        if not self.gps_usable:
            return False, "GS GPS INVALID"
        if not self.gps_in_range:
            return False, "GS RANGE LOCK"
        if not self._gs_session_active():
            return False, "GS AUTH REQUIRED"
        return True, None

    def _gs_status_byte(self) -> int:
        flags = 0
        if self.gs_mode_enabled:
            flags |= 0x01  # MODE_ENABLED
        if self.gps_usable:
            flags |= 0x02  # GPS_VALID
        if self.gps_in_range:
            flags |= 0x04  # WITHIN_RANGE
        if self._gs_session_active():
            flags |= 0x08  # AUTH_ACTIVE
        if self._gs_handshake_pending():
            flags |= 0x10  # HANDSHAKE_PENDING
        return flags

    def _gs_status_payload(self) -> bytes:
        # SCID, gs_status, challenge U32LE (the cleartext leak), session flag
        import struct
        return (bytes([SPACECRAFT_ID, self._gs_status_byte()])
                + struct.pack("<I", self.gs_challenge)
                + bytes([1 if self._gs_session_active() else 0]))

    def _extract_toggle(self, data: bytes) -> bool:
        # extractToggleConfigMode (worker.cpp:667): decrypt if block-aligned
        if data and len(data) % 16 == 0:
            try:
                plain = pp.secure_decode(data)
                if plain:
                    return plain[0] != 0
            except ValueError:
                pass
        return bool(data and data[0] != 0)

    # --- command handlers (commandApidHandler, worker.cpp:1425) -----------
    def _dispatch(self, apid: int, data: bytes, out: Reaction) -> None:
        if apid == TC_PING:
            app = bytes([SPACECRAFT_ID]) + b"ACK\x00"
            out.tm.append(OutPacket(self._build_tm(TM_PING, app), "PING ACK"))
        elif apid == TC_RESETC:
            out.logs.append(("WARN", "RESETC received -> software reset"))
            self.reset()
            out.logs.append(("INFO", "Firmware reinitialised (NOMINAL, secure link ON)"))
        elif apid == TC_SEND_FW:
            app = bytes([SPACECRAFT_ID, 0, 0, 1, 0])  # patch.minor.major = 0.0.1
            out.tm.append(OutPacket(self._build_tm(TM_SEND_FW, app), "VERSION 1.0.0"))
        elif apid == TC_GET_STATUS:
            out.tm.append(OutPacket(self._build_tm(TM_STATUS, self._status_payload()), "STATUS"))
        elif apid == TC_SET_MISSION_MODE:
            self._handle_mission_mode(data, out)
        elif apid == TC_FLASH_READ:
            self._handle_flash_read(data, out)
        elif apid == TC_BROADCAST_MSG:
            self._handle_broadcast(data, out)
        elif apid == TC_GET_PAYLOAD_STATUS:
            out.tm.append(OutPacket(self._build_tm(TM_PAYLOAD_STATUS, self._payload_status()),
                                    "PAYLOAD STATUS"))
        elif apid == TC_GS_MODE:
            self._handle_gs_mode(data, out)
        elif apid == TC_GS_ACCESS:
            self._handle_gs_access(data, out)
        elif apid == TC_GS_STATUS:
            out.tm.append(OutPacket(self._build_tm(TC_GS_STATUS, self._gs_status_payload()),
                                    "GS STATUS"))
        else:
            out.logs.append(("ERROR", f"Unknown/unsupported APID 0x{apid:03X}"))
            out.tm.append(self._error_tm("Error Unknown APID"))

    def _handle_aes(self, state: bool, out: Reaction) -> None:
        self.secure_link_enabled = state
        out.logs.append(("INFO", f"Secure link {'enabled' if state else 'disabled'}"))
        app = bytes([SPACECRAFT_ID, 1 if state else 0, 0])
        out.tm.append(OutPacket(self._build_tm(TM_AES_CONFIG, app), "AES STATUS"))

    def _handle_debug(self, state: bool, out: Reaction) -> None:
        self.usb_debug_enabled = state
        out.logs.append(("INFO", f"USB debug mode {'enabled' if state else 'disabled'}"
                                 f"{' (link cleartext + GS gate bypassed)' if state else ''}"))
        app = bytes([SPACECRAFT_ID, 1 if state else 0,
                     1 if self.secure_link_enabled else 0, 1])
        # debug status is always cleartext (worker.cpp:1034 force_cleartext)
        out.tm.append(OutPacket(self._build_tm(0x10, app, force_cleartext=True), "DEBUG STATUS"))

    def _handle_mission_mode(self, data: bytes, out: Reaction) -> None:
        if not data or data[0] > 4:
            out.tm.append(self._error_tm("MISSION MODE INVALID"))
            return
        self.mission_mode = data[0]
        self.payload_armed = data[0] in (2, 3)  # PAYLOAD/SCIENCE (worker.cpp:706)
        out.logs.append(("INFO", f"Mission mode -> {MISSION_MODES[data[0]]}"))
        app = bytes([SPACECRAFT_ID, self.mission_mode,
                     1 if self.payload_armed else 0, self._status_flags()])
        out.tm.append(OutPacket(self._build_tm(TM_MISSION_MODE, app), "MISSION MODE"))

    def _handle_flash_read(self, data: bytes, out: Reaction) -> None:
        # worker.cpp:1491 — parse window_id, offset LE16, len, unlock BE16
        if len(data) < 6:
            out.tm.append(self._error_tm("FLASH WINDOW LOCKED"))
            return
        window_id = data[0]
        offset = data[1] | (data[2] << 8)
        read_len = data[3]
        unlock = (data[4] << 8) | data[5]
        if window_id != FLASH_WINDOW_ID or unlock != FLASH_UNLOCK_TAG:
            out.logs.append(("WARN", f"FLASH_READ rejected (window=0x{window_id:02X} "
                                     f"unlock=0x{unlock:04X})"))
            out.tm.append(self._error_tm("FLASH WINDOW LOCKED"))
            return
        # telemetrySPPTransmitFlashRead (worker.cpp:1275)
        if read_len == 0:
            out.tm.append(self._error_tm("FLASH READ SIZE ZERO"))
            return
        if offset >= len(FLASH_WINDOW_BLOB):
            out.tm.append(self._error_tm("FLASH READ OOB"))
            return
        bounded = min(read_len, FLASH_READ_MAX_BYTES)
        available = len(FLASH_WINDOW_BLOB) - offset
        copy_len = min(bounded, available)
        chunk = FLASH_WINDOW_BLOB[offset:offset + copy_len]
        app = (bytes([SPACECRAFT_ID, offset & 0xFF, (offset >> 8) & 0xFF, copy_len])
               + chunk + bytes([crc8(chunk)]))
        out.logs.append(("INFO", f"FLASH window unlocked -> {copy_len} bytes @ offset {offset}"))
        out.tm.append(OutPacket(self._build_tm(TM_FLASH_READ, app),
                                f"FLASH_READ {copy_len}B @ {offset}"))

    # --- payload relay (worker.cpp:1457 BROADCAST_MSG) --------------------
    def _handle_broadcast(self, data: bytes, out: Reaction) -> None:
        if len(data) < 3:  # 2-byte frequency + at least one message byte
            out.tm.append(self._error_tm("BROADCAST FORMAT"))
            return
        frequency = (data[0] << 8) | data[1]     # BE16
        message = data[2:]
        # The vulnerability: relay works even outside payload mode — only a warning.
        if not self.payload_armed:
            out.logs.append(("WARN", "Payload relay used outside payload mode"))
        self.last_payload_frequency = frequency
        self.payload_forward_count += 1
        self.last_payload_length = len(message)
        out.logs.append(("INFO", f"Relayed {len(message)} bytes on freq 0x{frequency:04X} "
                                 f"(forward #{self.payload_forward_count})"))
        # Re-broadcast the attacker's bytes verbatim as TM (bent-pipe).
        out.tm.append(OutPacket(self._build_tm(TM_BROADCAST, message), "RELAY"))

    def _payload_status(self) -> bytes:
        import struct
        return (bytes([SPACECRAFT_ID, self.mission_mode,
                       1 if self.payload_armed else 0,
                       1 if self.secure_link_enabled else 0])
                + struct.pack("<H", self.last_payload_frequency)
                + struct.pack("<H", self.payload_forward_count)
                + bytes([self.last_payload_length & 0xFF, 0x00]))

    # --- ground station handlers (worker.cpp:734, 778) --------------------
    def _handle_gs_mode(self, data: bytes, out: Reaction) -> None:
        if not data:
            out.tm.append(self._error_tm("GS MODE FORMAT"))
            return
        enable = data[0] != 0
        if not enable:
            self.gs_mode_enabled = False
            self._gs_session_expires = 0.0
            self.gs_challenge = 0
            out.logs.append(("INFO", "Ground station communication mode disabled"))
        else:
            if not self.gps_usable:
                out.tm.append(self._error_tm("GS MODE GPS REQUIRED"))
                return
            if not self.gps_in_range:
                out.tm.append(self._error_tm("GS RANGE LOCK"))
                return
            self.gs_mode_enabled = True
            out.logs.append(("INFO", "Ground station communication mode enabled "
                                     "(commands now require an authenticated session)"))
        out.tm.append(OutPacket(self._build_tm(TC_GS_MODE, self._gs_status_payload()), "GS MODE"))

    def _handle_gs_access(self, data: bytes, out: Reaction) -> None:
        import os
        import struct
        if not data:
            out.tm.append(self._error_tm("GS ACCESS FORMAT"))
            return
        phase = data[0]
        if phase == 0x00:  # issue challenge
            self.gs_challenge = struct.unpack("<I", os.urandom(4))[0] or 0x13579BDF
            self._gs_challenge_expires = time.monotonic() + GS_HANDSHAKE_WINDOW_S
            out.logs.append(("INFO", f"Ground station challenge issued: 0x{self.gs_challenge:08X}"))
            out.tm.append(OutPacket(self._build_tm(TC_GS_ACCESS, self._gs_access_payload(0, 0)),
                                    "GS CHALLENGE"))
            return
        if phase != 0x01 or len(data) < 5:
            out.tm.append(self._error_tm("GS ACCESS FORMAT"))
            return
        if not self._gs_handshake_pending():
            out.tm.append(self._error_tm("GS CHALLENGE NONE"))
            return
        response = struct.unpack(">I", data[1:5])[0]
        expected = gs_expected_response(self.gs_challenge)
        if response != expected:
            out.logs.append(("WARN", f"GS handshake failed: resp=0x{response:08X} "
                                     f"expected=0x{expected:08X}"))
            self.gs_challenge = 0
            self._gs_session_expires = 0.0
            out.tm.append(self._error_tm("GS AUTH FAIL"))
            out.tm.append(OutPacket(self._build_tm(TC_GS_ACCESS, self._gs_access_payload(1, 2)),
                                    "GS AUTH FAIL"))
            return
        self._gs_session_expires = time.monotonic() + GS_SESSION_WINDOW_S
        out.logs.append(("INFO", "Ground station handshake accepted — session active"))
        out.tm.append(OutPacket(self._build_tm(TC_GS_ACCESS, self._gs_access_payload(1, 1)),
                                "GS AUTH OK"))

    def _gs_access_payload(self, phase: int, auth_state: int) -> bytes:
        import struct
        return (bytes([SPACECRAFT_ID, phase, auth_state, self._gs_status_byte()])
                + struct.pack("<I", self.gs_challenge))

    # --- status / periodic telemetry --------------------------------------
    def _status_flags(self) -> int:
        flags = 0
        if self.secure_link_enabled:
            flags |= 0x10
        if self.payload_armed:
            flags |= 0x20
        if self.usb_debug_enabled:
            flags |= 0x40
        return flags

    def _status_payload(self) -> bytes:
        uptime = int(time.monotonic() - self.boot_time)
        return bytes([SPACECRAFT_ID, self.mission_mode, self._status_flags(),
                      (uptime >> 8) & 0xFF, uptime & 0xFF, 0, 0, 1])

    def tick(self, now: float | None = None) -> Reaction:
        """Autonomous downlink on firmware-like cadence (worker.cpp:1381)."""
        now = time.monotonic() if now is None else now
        out = Reaction()
        if now - self._last_status_tm >= 5.0:
            self._last_status_tm = now
            out.tm.append(OutPacket(self._build_tm(TM_STATUS, self._status_payload()),
                                    "periodic STATUS"))
        if now - self._last_idle_tm >= 12.0:
            self._last_idle_tm = now
            app = bytes([SPACECRAFT_ID]) + b"HackTheWorld!\x00"
            out.tm.append(OutPacket(self._build_tm(TM_IDLE, app, force_cleartext=True),
                                    "idle"))
        return out


# --- dissector (reuses SppPacket; decodes actual bytes) -------------------
def dissect(raw: bytes, direction: str) -> dict:
    """Decode an SPP packet into a field tree for the analyzer.

    Decodes the actual bytes (not a hardcoded description).  For TM packets the
    known lab key is used to decrypt the application payload, mirroring
    spp_parser.py --key."""
    out: dict = {"direction": direction, "length": len(raw), "hex": raw.hex(),
                 "malformed": False, "tree": [], "summary": ""}
    try:
        pkt = pp.parse_spp(raw)
    except ValueError as exc:
        out["malformed"] = True
        out["summary"] = f"Malformed SPP: {exc}"
        out["tree"] = [{"field": "raw", "value": raw.hex(), "span": [0, len(raw)]}]
        return out

    apid = pkt.apid
    name = pp.TM_APID_NAMES.get(apid, f"0x{apid:03X}")
    ptype = "TC" if pkt.packet_type == pp.SPP_TYPE_TC else "TM"
    # V2: an uplink (command) whose Type bit says TM is a type-confused packet —
    # the firmware dispatches on APID and never checks the bit (worker.cpp:1556).
    confused = direction == "tx" and pkt.packet_type == pp.SPP_TYPE_TM
    type_val = f"{pkt.packet_type} ({ptype})"
    if confused:
        type_val += "  ⚠ type confusion: uplink declared as telemetry"
    out["tree"] = [
        {"field": "Primary Header", "value": "", "span": [0, 6], "children": [
            {"field": "Packet Version", "value": pkt.version, "span": [0, 2]},
            {"field": "Packet Type", "value": type_val, "span": [0, 2]},
            {"field": "Sec. Header Flag", "value": pkt.secondary_header, "span": [0, 2]},
            {"field": "APID", "value": f"0x{apid:03X} ({name})", "span": [0, 2]},
            {"field": "Sequence Flags", "value": pkt.sequence_flags, "span": [2, 4]},
            {"field": "Sequence Count", "value": pkt.sequence_count, "span": [2, 4]},
            {"field": "Data Length", "value": f"{len(pkt.data)} (field={len(pkt.data) - 1})",
             "span": [4, 6]},
        ]},
    ]

    app = pkt.data
    data_node = {"field": "Data Field", "value": f"{len(app)} bytes",
                 "span": [6, 6 + len(app)], "children": []}
    # Decode by DIRECTION, not by the (spoofable) type bit: an uplink is a command,
    # a downlink is telemetry.
    if direction == "rx" and app:
        flag = app[0]
        data_node["children"].append(
            {"field": "Security Flag", "value": "0x01 (encrypted)" if flag == 0x01
             else "0x00 (cleartext)", "span": [6, 7]})
        try:
            plain, enc = pp.decode_tm_payload(app)
            label = "Decrypted Payload" if enc else "Payload"
            data_node["children"].append(
                {"field": label, "value": _printable(plain), "span": [7, 6 + len(app)],
                 "children": _app_fields(plain, apid)})
        except ValueError as exc:
            data_node["children"].append({"field": "Payload", "value": f"<{exc}>",
                                          "span": [7, 6 + len(app)]})
    elif direction == "tx" and app:
        decoded = None
        if len(app) % 16 == 0:
            try:
                decoded = pp.secure_decode(app)
            except ValueError:
                decoded = None
        label = "Decrypted Command" if decoded is not None else "Command Payload"
        body = decoded if decoded is not None else app
        data_node["children"].append({"field": label, "value": _printable(body),
                                       "span": [6, 6 + len(app)]})
    else:
        data_node["children"].append({"field": "Payload", "value": _printable(app),
                                      "span": [6, 6 + len(app)]})
    out["tree"].append(data_node)
    tag = "  ⚠ type-confused" if confused else ""
    out["summary"] = f"{ptype} 0x{apid:03X} {name}  seq={pkt.sequence_count}  len={len(app)}{tag}"
    return out


def _printable(data: bytes) -> str:
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)
    return f"{data.hex()}  |{text}|"


def _app_fields(plain: bytes, apid: int = 0) -> list[dict]:
    import struct
    if not plain:
        return []
    if apid == 0x06:  # BROADCAST relay: payload is the attacker's message verbatim
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in plain)
        return [{"field": "Relayed message", "value": f"{plain.hex()}  |{text}|",
                 "span": [0, len(plain)]}]
    fields = [{"field": "Spacecraft ID", "value": f"0x{plain[0]:02X}", "span": [0, 1]}]
    # Surface the ground-station challenge (the cleartext leak that enables V3).
    ch_off = 4 if apid == 0x12 else 2 if apid in (0x11, 0x13) else None
    if ch_off is not None and len(plain) >= ch_off + 4:
        challenge = struct.unpack("<I", plain[ch_off:ch_off + 4])[0]
        fields.append({"field": "GS Challenge (cleartext leak)", "value": f"0x{challenge:08X}",
                       "span": [ch_off, ch_off + 4]})
    tail = plain[1:]
    text = "".join(chr(b) for b in tail if 0x20 <= b < 0x7F)
    if "PWNSAT{" in text:
        fields.append({"field": "FLAG", "value": text[text.index("PWNSAT{"):], "span": [1, len(plain)]})
    return fields
