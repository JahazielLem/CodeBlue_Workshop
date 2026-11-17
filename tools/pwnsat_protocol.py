"""Protocol helpers shared by the command-and-control and attack tools.

The firmware transport is:

    AA 55 | payload length, big endian | CCSDS SPP packet

The SPP primary header remains six bytes and its data field is the payload
used by the existing firmware.  The AES implementation intentionally mirrors
the small AES-128 ECB implementation in secure_link.cpp so the tools do not
need an external crypto package.
"""

from __future__ import annotations

import string
import struct
from dataclasses import dataclass


def parse_hex(value: str) -> bytes:
    """Parse a hex string into bytes, tolerating common separators.

    Accepts an optional ``0x`` prefix and spaces, commas, colons, underscores,
    tabs and newlines as separators. This is the superset of the historical
    per-tool hex parsers; it raises :class:`ValueError` on invalid input so a
    CLI caller can turn that into whatever message/exit it prefers.
    """
    cleaned = value
    for sep in (" ", ",", ":", "_", "\n", "\r", "\t"):
        cleaned = cleaned.replace(sep, "")
    cleaned = cleaned.replace("0x", "").replace("0X", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hexadecimal input: {value!r}") from exc


def hexdump(data: bytes, width: int = 16) -> str:
    """Return an offset / hex / ASCII dump (8-digit offset, ``width``-byte rows)."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{byte:02X}" for byte in chunk).ljust(width * 3)
        ascii_bytes = "".join(
            chr(byte) if byte >= 0x20 and chr(byte) in string.printable else "."
            for byte in chunk
        )
        lines.append(f"{offset:08X}  {hex_bytes}  {ascii_bytes}")
    return "\n".join(lines)

FRAME_SYNC = b"\xAA\x55"
FRAME_HEADER_LEN = 4
FRAME_MAX_PAYLOAD = 512
SPP_PRIMARY_HEADER_LEN = 6
SPP_MAX_PAYLOAD_CHUNK = 200
SPP_MAX_PACKET_LEN = SPP_PRIMARY_HEADER_LEN + SPP_MAX_PAYLOAD_CHUNK

SPP_VERSION = 0
SPP_TYPE_TM = 0
SPP_TYPE_TC = 1
SPP_GROUP_UNSEGMENTED = 3
SPP_SEC_HEADER_NONE = 0
SPACECRAFT_ID = 0x01
SECURE_KEY = b"PWNsatLabKey1234"
GROUND_STATION_AUTH_KEY = 0xC0DEFACE

TC_APIDS = {
    "ping": 0x01,
    "reset": 0x02,
    "version": 0x03,
    "thruster": 0x04,
    "beacon": 0x05,
    "broadcast": 0x06,
    "flash": 0x07,
    "aes": 0x0A,
    "flash-read": 0x0B,
    "status": 0x0C,
    "mission": 0x0D,
    "nav": 0x0E,
    "payload": 0x0F,
    "debug": 0x10,
    "gs-mode": 0x11,
    "gs-access": 0x12,
    "gs-status": 0x13,
    "mode": 0x14,
}

TM_APID_NAMES = {
    0x01: "PING",
    0x02: "RESET",
    0x03: "VERSION",
    0x04: "SET_THRUSTER",
    0x05: "SET_BEACON",
    0x06: "BROADCAST",
    0x07: "FLASH",
    0x08: "SENSOR_TM",
    0x09: "ERROR",
    0x0A: "AES_STATUS",
    0x0B: "FLASH_READ",
    0x0C: "STATUS",
    0x0D: "MISSION_MODE",
    0x0E: "NAV",
    0x0F: "PAYLOAD_STATUS",
    0x10: "DEBUG_STATUS",
    0x11: "GS_MODE",
    0x12: "GS_ACCESS",
    0x13: "GS_STATUS",
    0x14: "SYSTEM_MODE",
    0x3FF: "IDLE",
}


@dataclass
class SppPacket:
    identification: int
    sequence: int
    data: bytes

    @property
    def version(self) -> int:
        return (self.identification >> 13) & 0x07

    @property
    def packet_type(self) -> int:
        return (self.identification >> 12) & 0x01

    @property
    def secondary_header(self) -> int:
        return (self.identification >> 11) & 0x01

    @property
    def apid(self) -> int:
        return self.identification & 0x07FF

    @property
    def sequence_flags(self) -> int:
        return (self.sequence >> 14) & 0x03

    @property
    def sequence_count(self) -> int:
        return self.sequence & 0x3FFF

    def to_bytes(self) -> bytes:
        if not self.data or len(self.data) > SPP_MAX_PAYLOAD_CHUNK:
            raise ValueError("SPP data length must be between 1 and 200 bytes")
        length_field = len(self.data) - 1
        return struct.pack(">HHH", self.identification, self.sequence, length_field) + self.data


def build_spp(
    apid: int,
    data: bytes = b"\x00",
    *,
    packet_type: int = SPP_TYPE_TC,
    sequence_count: int = 1,
    sequence_flags: int = SPP_GROUP_UNSEGMENTED,
    secondary_header: int = SPP_SEC_HEADER_NONE,
) -> bytes:
    """Build a raw six-byte-header SPP packet."""

    if not 0 <= apid <= 0x07FF:
        raise ValueError("APID must fit in 11 bits")
    if not 0 <= sequence_count <= 0x3FFF:
        raise ValueError("sequence count must fit in 14 bits")
    if not data or len(data) > SPP_MAX_PAYLOAD_CHUNK:
        raise ValueError("SPP data length must be between 1 and 200 bytes")

    identification = (
        ((SPP_VERSION & 0x07) << 13)
        | ((packet_type & 0x01) << 12)
        | ((secondary_header & 0x01) << 11)
        | (apid & 0x07FF)
    )
    sequence = ((sequence_flags & 0x03) << 14) | (sequence_count & 0x3FFF)
    return struct.pack(">HHH", identification, sequence, len(data) - 1) + data


def parse_spp(packet: bytes) -> SppPacket:
    if len(packet) < SPP_PRIMARY_HEADER_LEN:
        raise ValueError("SPP packet is shorter than the primary header")
    identification, sequence, length_field = struct.unpack(">HHH", packet[:6])
    if ((identification >> 13) & 0x07) != SPP_VERSION:
        raise ValueError("unsupported SPP version")
    if length_field >= SPP_MAX_PAYLOAD_CHUNK:
        raise ValueError("SPP data length exceeds firmware limit")
    data_len = length_field + 1
    expected = SPP_PRIMARY_HEADER_LEN + data_len
    if len(packet) != expected:
        raise ValueError(f"SPP length mismatch: header says {expected}, got {len(packet)}")
    return SppPacket(identification, sequence, packet[6:])


def make_frame(spp_packet: bytes) -> bytes:
    if not 0 < len(spp_packet) <= FRAME_MAX_PAYLOAD:
        raise ValueError("serial frame payload length is outside 1..512")
    return FRAME_SYNC + struct.pack(">H", len(spp_packet)) + spp_packet


class FrameParser:
    """Incremental parser that tolerates startup text and corrupted bytes."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> list[bytes]:
        self._buffer.extend(chunk)
        frames: list[bytes] = []

        while True:
            start = self._buffer.find(FRAME_SYNC)
            if start < 0:
                # Preserve a possible first byte of the two-byte sync word.
                if self._buffer[-1:] == FRAME_SYNC[:1]:
                    self._buffer[:] = self._buffer[-1:]
                else:
                    self._buffer.clear()
                break
            if start:
                del self._buffer[:start]
            if len(self._buffer) < FRAME_HEADER_LEN:
                break

            payload_len = struct.unpack(">H", self._buffer[2:4])[0]
            if payload_len == 0 or payload_len > FRAME_MAX_PAYLOAD:
                del self._buffer[:1]
                continue

            frame_len = FRAME_HEADER_LEN + payload_len
            if len(self._buffer) < frame_len:
                break
            frames.append(bytes(self._buffer[4:frame_len]))
            del self._buffer[:frame_len]

        return frames


class MixedSerialParser:
    """Parse binary AA55 frames while preserving firmware text logs.

    CDC0 carries both diagnostic ``Serial`` text and framed TM packets.  The
    original FrameParser intentionally discarded bytes before the sync word;
    the C&C console uses this variant so TC acceptance/rejection logs remain
    visible to the ground station.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> tuple[list[bytes], bytes]:
        self._buffer.extend(chunk)
        frames: list[bytes] = []
        logs: list[bytes] = []

        while True:
            start = self._buffer.find(FRAME_SYNC)
            if start < 0:
                # Keep a possible first sync byte for the next read, while
                # returning all preceding ASCII diagnostics to the caller.
                keep = 1 if self._buffer[-1:] == FRAME_SYNC[:1] else 0
                if len(self._buffer) > keep:
                    logs.append(bytes(self._buffer[:-keep] if keep else self._buffer))
                    del self._buffer[: len(self._buffer) - keep]
                break

            if start:
                logs.append(bytes(self._buffer[:start]))
                del self._buffer[:start]

            if len(self._buffer) < FRAME_HEADER_LEN:
                break

            payload_len = struct.unpack(">H", self._buffer[2:4])[0]
            if payload_len == 0 or payload_len > FRAME_MAX_PAYLOAD:
                # It is not a valid frame; release one byte and resynchronize.
                logs.append(bytes(self._buffer[:1]))
                del self._buffer[:1]
                continue

            frame_len = FRAME_HEADER_LEN + payload_len
            if len(self._buffer) < frame_len:
                break

            frames.append(bytes(self._buffer[4:frame_len]))
            del self._buffer[:frame_len]

        return frames, b"".join(logs)


def _rotl8(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _gf_mul(left: int, right: int) -> int:
    result = 0
    while right:
        if right & 1:
            result ^= left
        hi_bit = left & 0x80
        left = (left << 1) & 0xFF
        if hi_bit:
            left ^= 0x1B
        right >>= 1
    return result


def _gf_pow(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, value)
        value = _gf_mul(value, value)
        exponent >>= 1
    return result


def _make_sboxes() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inverse = [0] * 256
    for value in range(256):
        inv = 0 if value == 0 else _gf_pow(value, 254)
        transformed = (
            0x63
            ^ inv
            ^ _rotl8(inv, 1)
            ^ _rotl8(inv, 2)
            ^ _rotl8(inv, 3)
            ^ _rotl8(inv, 4)
        )
        sbox[value] = transformed
        inverse[transformed] = value
    return sbox, inverse


SBOX, INV_SBOX = _make_sboxes()
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _round_keys(key: bytes) -> bytearray:
    if len(key) != 16:
        raise ValueError("AES-128 key must contain 16 bytes")
    keys = bytearray(key)
    generated = 16
    rcon_index = 1
    while generated < 176:
        temp = list(keys[generated - 4 : generated])
        if generated % 16 == 0:
            first = temp[0]
            temp = [SBOX[temp[1]] ^ RCON[rcon_index], SBOX[temp[2]], SBOX[temp[3]], SBOX[first]]
            rcon_index += 1
        for value in temp:
            keys.append(keys[generated - 16] ^ value)
            generated += 1
    return keys


def _add_round_key(state: list[int], key: bytearray, offset: int) -> None:
    for index in range(16):
        state[index] ^= key[offset + index]


def _sub_bytes(state: list[int], box: list[int]) -> None:
    for index in range(16):
        state[index] = box[state[index]]


def _shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _inv_shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def _mix_columns(state: list[int]) -> None:
    for column in range(4):
        offset = column * 4
        s0, s1, s2, s3 = state[offset : offset + 4]
        state[offset] = _gf_mul(s0, 2) ^ _gf_mul(s1, 3) ^ s2 ^ s3
        state[offset + 1] = s0 ^ _gf_mul(s1, 2) ^ _gf_mul(s2, 3) ^ s3
        state[offset + 2] = s0 ^ s1 ^ _gf_mul(s2, 2) ^ _gf_mul(s3, 3)
        state[offset + 3] = _gf_mul(s0, 3) ^ s1 ^ s2 ^ _gf_mul(s3, 2)


def _inv_mix_columns(state: list[int]) -> None:
    for column in range(4):
        offset = column * 4
        s0, s1, s2, s3 = state[offset : offset + 4]
        state[offset] = _gf_mul(s0, 0x0E) ^ _gf_mul(s1, 0x0B) ^ _gf_mul(s2, 0x0D) ^ _gf_mul(s3, 0x09)
        state[offset + 1] = _gf_mul(s0, 0x09) ^ _gf_mul(s1, 0x0E) ^ _gf_mul(s2, 0x0B) ^ _gf_mul(s3, 0x0D)
        state[offset + 2] = _gf_mul(s0, 0x0D) ^ _gf_mul(s1, 0x09) ^ _gf_mul(s2, 0x0E) ^ _gf_mul(s3, 0x0B)
        state[offset + 3] = _gf_mul(s0, 0x0B) ^ _gf_mul(s1, 0x0D) ^ _gf_mul(s2, 0x09) ^ _gf_mul(s3, 0x0E)


def _encrypt_block(block: bytes, key: bytes) -> bytes:
    state = list(block)
    round_keys = _round_keys(key)
    _add_round_key(state, round_keys, 0)
    for round_index in range(1, 10):
        _sub_bytes(state, SBOX)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys, round_index * 16)
    _sub_bytes(state, SBOX)
    _shift_rows(state)
    _add_round_key(state, round_keys, 160)
    return bytes(state)


def _decrypt_block(block: bytes, key: bytes) -> bytes:
    state = list(block)
    round_keys = _round_keys(key)
    _add_round_key(state, round_keys, 160)
    for round_index in range(9, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, INV_SBOX)
        _add_round_key(state, round_keys, round_index * 16)
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes(state, INV_SBOX)
    _add_round_key(state, round_keys, 0)
    return bytes(state)


def secure_encode(payload: bytes) -> bytes:
    total = len(payload) + 2
    padded_len = (total + 15) & ~15
    if padded_len > SPP_MAX_PAYLOAD_CHUNK:
        raise ValueError("secure payload exceeds firmware limit")
    plain = struct.pack(">H", len(payload)) + payload + bytes(padded_len - total)
    return b"".join(_encrypt_block(plain[offset : offset + 16], SECURE_KEY) for offset in range(0, padded_len, 16))


def secure_decode(payload: bytes) -> bytes:
    if not payload or len(payload) % 16 or len(payload) > SPP_MAX_PAYLOAD_CHUNK:
        raise ValueError("secure payload is not AES block aligned")
    plain = b"".join(_decrypt_block(payload[offset : offset + 16], SECURE_KEY) for offset in range(0, len(payload), 16))
    plain_len = struct.unpack(">H", plain[:2])[0]
    if plain_len > len(payload) - 2:
        raise ValueError("secure payload length marker is invalid")
    return plain[2 : 2 + plain_len]


def encode_tm_payload(payload: bytes, encrypted: bool) -> bytes:
    """Prefix a TM application payload with its cleartext/encryption flag."""
    if encrypted:
        return b"\x01" + secure_encode(payload)
    return b"\x00" + payload


def decode_tm_payload(payload: bytes) -> tuple[bytes, bool]:
    """Read the TM security flag and return (application payload, encrypted)."""
    if not payload:
        raise ValueError("TM payload is missing its security flag")
    if payload[0] == 0x00:
        return payload[1:], False
    if payload[0] == 0x01:
        return secure_decode(payload[1:]), True
    raise ValueError(f"unknown TM security flag 0x{payload[0]:02X}")
