"""Headless self-tests for the Stage-2 vertical slice.

Run: python3 lab/test_slice.py   (exit 0 = all pass). No external deps.
Validates the end-to-end V4 flash-window chain, the AES-on-the-wire path,
per-session isolation, and the dissector against the real protocol module.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import pwnsat_protocol as pp
import satellite_sim as sim


def tc_frame(apid, data, *, secure):
    """Build an uplink AA55 frame the way the student terminal does."""
    payload = pp.secure_encode(data) if secure else data
    spp = pp.build_spp(apid, payload, packet_type=pp.SPP_TYPE_TC)
    return pp.make_frame(spp)


def tm_flag_bytes(sat, out):
    """Decode every TM in a reaction, return concatenated decoded payloads."""
    blob = b""
    for p in out.tm:
        pkt = pp.parse_spp(p.spp)
        try:
            plain, _ = pp.decode_tm_payload(pkt.data)
            blob += plain
        except ValueError:
            pass
    return blob


def flash_read_data(window_id, offset, length, unlock):
    return bytes([window_id, offset & 0xFF, (offset >> 8) & 0xFF, length,
                  (unlock >> 8) & 0xFF, unlock & 0xFF])


passed = 0
def check(name, cond):
    global passed
    assert cond, f"FAIL: {name}"
    passed += 1
    print(f"  ok  {name}")


print("Stage-2 slice self-test")

# 1. PING -> ACK
s = sim.SatelliteSim("t1")
out = s.ingest_frame_bytes(tc_frame(sim.TC_PING, b"\x00", secure=True))
check("PING yields one TM", len(out.tm) == 1)
check("PING ACK decodes", b"ACK" in tm_flag_bytes(s, out))

# 2. FLASH_READ correct magic (secure link on) -> flag recovered
s = sim.SatelliteSim("t2")
out = s.ingest_frame_bytes(
    tc_frame(sim.TC_FLASH_READ, flash_read_data(0xA5, 83, 32, 0xC35A), secure=True))
blob = tm_flag_bytes(s, out)
check("FLASH_READ returns a TM", len(out.tm) == 1)
check("FLASH_READ (secure) leaks PWNSAT flag", b"PWNSAT{" in blob)
check("TC was decrypted by sim (no AES DECRYPT FAIL)",
      not any("DECRYPT" in t for _, t in out.logs))

# 3. FLASH_READ wrong unlock -> locked error, no flag
s = sim.SatelliteSim("t3")
out = s.ingest_frame_bytes(
    tc_frame(sim.TC_FLASH_READ, flash_read_data(0xA5, 83, 32, 0x0000), secure=True))
check("Wrong unlock is rejected", b"PWNSAT{" not in tm_flag_bytes(s, out))
check("Locked error emitted", any("LOCKED" in t for _, t in out.logs) or
      any(b"LOCKED" in tm_flag_bytes(s, type("o", (), {"tm": [p]})) for p in out.tm))

# 4. Disable AES, then cleartext command works
s = sim.SatelliteSim("t4")
s.ingest_frame_bytes(tc_frame(sim.TC_AES_CONFIG, b"\x00", secure=True))  # aes off (encrypted)
check("secure link now off", s.secure_link_enabled is False)
out = s.ingest_frame_bytes(tc_frame(sim.TC_PING, b"\x00", secure=False))  # cleartext ping
check("cleartext PING works after AES off", b"ACK" in tm_flag_bytes(s, out))

# 5. Isolation: reset one sat, another is unaffected
a = sim.SatelliteSim("A")
b = sim.SatelliteSim("B")
a.ingest_frame_bytes(tc_frame(sim.TC_AES_CONFIG, b"\x00", secure=True))  # A: aes off
a.ingest_frame_bytes(tc_frame(sim.TC_SET_MISSION_MODE, b"\x02", secure=False))  # A: PAYLOAD
check("A state changed", a.secure_link_enabled is False and a.mission_mode == 2)
check("B unaffected by A", b.secure_link_enabled is True and b.mission_mode == 1)
a.reset()
check("A reset restores defaults", a.secure_link_enabled is True and a.mission_mode == 1)
check("B still independent after A reset", b.mission_mode == 1 and b.secure_link_enabled)

# 6. Dissector decodes actual bytes, incl. flag
s = sim.SatelliteSim("t6")
s.ingest_frame_bytes(tc_frame(sim.TC_DEBUG_CONFIG, b"\x01", secure=True))  # debug on -> cleartext
out = s.ingest_frame_bytes(
    tc_frame(sim.TC_FLASH_READ, flash_read_data(0xA5, 83, 32, 0xC35A), secure=False))
d = sim.dissect(out.tm[0].spp, "rx")
check("dissector parses TM", not d["malformed"] and d["tree"])
check("dissector exposes FLASH_READ APID", "0x00B" in d["summary"])
flag_found = "PWNSAT{" in str(d["tree"])
check("dissector surfaces the flag", flag_found)

# 7. Malformed packet flagged, not crashed
d = sim.dissect(b"\xff\xff", "rx")
check("malformed packet flagged", d["malformed"] is True)


def gs_challenge_from(out, apid=0x12):
    """Pull the leaked challenge out of a GS TM reply."""
    import struct
    for p in out.tm:
        pkt = pp.parse_spp(p.spp)
        if pkt.apid != apid:
            continue
        plain, _ = pp.decode_tm_payload(pkt.data)
        off = 4 if apid == 0x12 else 2
        return struct.unpack("<I", plain[off:off + 4])[0]
    return None


# 8. V3 — ground-station auth: mode on gates commands
s = sim.SatelliteSim("v3")
s.ingest_frame_bytes(tc_frame(sim.TC_GS_MODE, b"\x01", secure=True))
check("GS mode enabled", s.gs_mode_enabled is True)
out = s.ingest_frame_bytes(tc_frame(sim.TC_PING, b"\x00", secure=True))
check("PING blocked without session", b"ACK" not in tm_flag_bytes(s, out))
check("gate reason is AUTH REQUIRED", any("AUTH REQUIRED" in t for _, t in out.logs))

# 9. V3 — forged response (challenge XOR 0xC0DEFACE) opens a session
out = s.ingest_frame_bytes(tc_frame(sim.TC_GS_ACCESS, b"\x00", secure=True))  # challenge
challenge = gs_challenge_from(out)
check("challenge issued + leaked in TM", challenge not in (None, 0))
forged = (challenge ^ 0xC0DEFACE) & 0xFFFFFFFF
out = s.ingest_frame_bytes(
    tc_frame(sim.TC_GS_ACCESS, b"\x01" + forged.to_bytes(4, "big"), secure=True))
check("forged response accepted (session active)", s._gs_session_active() is True)
out = s.ingest_frame_bytes(tc_frame(sim.TC_PING, b"\x00", secure=True))
check("PING works after forged auth", b"ACK" in tm_flag_bytes(s, out))

# 10. V3 — a wrong response is rejected
s2 = sim.SatelliteSim("v3b")
s2.ingest_frame_bytes(tc_frame(sim.TC_GS_MODE, b"\x01", secure=True))
s2.ingest_frame_bytes(tc_frame(sim.TC_GS_ACCESS, b"\x00", secure=True))
out = s2.ingest_frame_bytes(
    tc_frame(sim.TC_GS_ACCESS, b"\x01" + (0xDEADBEEF).to_bytes(4, "big"), secure=True))
check("wrong response rejected", s2._gs_session_active() is False)
check("auth fail logged", any("handshake failed" in t for _, t in out.logs))

# V2 — type confusion: a TM-typed uplink still executes as a command
sv2 = sim.SatelliteSim("v2")
payload = pp.secure_encode(b"\x02")  # mission mode PAYLOAD, secure link on
spp_tm = pp.build_spp(sim.TC_SET_MISSION_MODE, payload, packet_type=pp.SPP_TYPE_TM)
check("packet really carries the TM type bit", pp.parse_spp(spp_tm).packet_type == pp.SPP_TYPE_TM)
sv2.ingest_frame_bytes(pp.make_frame(spp_tm))
check("TM-typed command still executed (type bit not validated)", sv2.mission_mode == 2)
dv2 = sim.dissect(spp_tm, "tx")
check("dissector flags the type confusion", "confus" in str(dv2["tree"]).lower())
dv2rx = sim.dissect(spp_tm, "rx")  # same bytes seen as downlink: not flagged
check("same packet as downlink is not flagged", "confus" not in str(dv2rx["tree"]).lower())

# 11. V3 — dissector surfaces the challenge field
d = sim.dissect(out.tm[0].spp if False else
                s.ingest_frame_bytes(tc_frame(sim.TC_GS_STATUS, b"\x00", secure=True)).tm[0].spp, "rx")
check("dissector surfaces GS challenge", "GS Challenge" in str(d["tree"]))

# V7 — payload relay abuse: forwards attacker content outside payload mode
s7 = sim.SatelliteSim("v7")
check("payload not armed by default", s7.payload_armed is False)
msg = b"HELLO-SAT"
out = s7.ingest_frame_bytes(
    tc_frame(sim.TC_BROADCAST_MSG, (0x1A2B).to_bytes(2, "big") + msg, secure=True))
check("relay forwards one TM", len(out.tm) == 1)
relayed, _ = pp.decode_tm_payload(pp.parse_spp(out.tm[0].spp).data)
check("relayed message echoed verbatim", relayed == msg)
check("warned: relay outside payload mode", any("outside payload mode" in t for _, t in out.logs))
check("forward counter incremented", s7.payload_forward_count == 1)
check("attacker frequency recorded", s7.last_payload_frequency == 0x1A2B)
d7 = sim.dissect(out.tm[0].spp, "rx")
check("dissector shows the relayed message", "Relayed message" in str(d7["tree"]))

# V6 — AES-128 key recovery by dictionary attack on captured ciphertext
s6 = sim.SatelliteSim("v6")
s6.ingest_frame_bytes(tc_frame(sim.TC_GET_STATUS, b"\x00", secure=True))  # encrypted TM
check("encrypted ciphertext captured", s6.last_tm_cipher is not None)
rows = sim.dictionary_attack(s6.last_tm_cipher)
matches = [r for r in rows if r["result"] == "MATCH"]
check("exactly one candidate key matches", len(matches) == 1)
check("recovered key is PWNsatLabKey1234", matches[0]["key"] == "PWNsatLabKey1234")
check("a wrong key does not match", any(r["result"] == "no" for r in rows))

# V5 — debug backdoor strips link encryption
s5 = sim.SatelliteSim("v5")
r = s5.ingest_frame_bytes(tc_frame(sim.TC_GET_STATUS, b"\x00", secure=True))
check("status encrypted by default", pp.parse_spp(r.tm[0].spp).data[0] == 0x01)
s5.ingest_frame_bytes(tc_frame(sim.TC_DEBUG_CONFIG, b"\x01", secure=True))
check("usb debug enabled", s5.usb_debug_enabled is True)
r = s5.ingest_frame_bytes(tc_frame(sim.TC_GET_STATUS, b"\x00", secure=False))
check("status cleartext after debug (crypto stripped)", pp.parse_spp(r.tm[0].spp).data[0] == 0x00)

# V5 — debug also bypasses the GS-mode disable gate
s5b = sim.SatelliteSim("v5b")
s5b.ingest_frame_bytes(tc_frame(sim.TC_GS_MODE, b"\x01", secure=True))   # GS on
s5b.ingest_frame_bytes(tc_frame(sim.TC_GS_MODE, b"\x00", secure=True))   # off w/o auth
check("gs-off blocked without auth", s5b.gs_mode_enabled is True)
s5b.ingest_frame_bytes(tc_frame(sim.TC_DEBUG_CONFIG, b"\x01", secure=True))
s5b.ingest_frame_bytes(tc_frame(sim.TC_GS_MODE, b"\x00", secure=False))  # off via debug backdoor
check("gs-off allowed once debug on (backdoor)", s5b.gs_mode_enabled is False)

# V1 — the REAL firmware parser over-read (compiles + runs firmware/spp.cpp)
import v1_overread as v1
_ok, _msg = v1.ensure_built()
if _ok:
    res = v1.run_overread("1001c0000040aabb")  # 8 bytes sent, declared length 64
    check("firmware parser ignores the length check (copies 65)", res.get("copied") == "65")
    check("over-read leaks adjacent memory (PWNSAT flag)",
          b"PWNSAT{" in bytes.fromhex(res.get("data", "")))
    try:
        pp.parse_spp(bytes.fromhex("1001c0000040aabb"))
        _rejected = False
    except ValueError:
        _rejected = True
    check("hardened ground-tool parser rejects the same packet", _rejected)
else:
    print(f"  -- V1 skipped (no C++ compiler): {_msg}")

print(f"\n{passed} checks passed.")
