# Pwnsat Browser Lab

**English** · [日本語](README.ja.md)

A browser-based, multi-student cybersecurity training lab for a simulated
CCSDS satellite. Each student gets an isolated satellite instance and attacks
it from a web UI — packet analyzer, terminal, satellite console — with seven
reproducible vulnerability exercises (EN/JA). Python 3 stdlib only.

A single, isolated satellite session proving the full chain end-to-end:

```
terminal command → real CCSDS SPP frame → SatelliteSim dispatch → TM reply
    → packet analyzer (CCSDS dissector + AES decrypt) → satellite console
```

Implemented exercises (switch via the Wiki panel's Exercise selector):

- **V4 — flash-window flag**: a hardcoded unlock constant leaks a secret blob.
- **V3 — ground-station auth bypass**: the challenge/response gate is forgeable
  because the expected answer is `challenge XOR 0xC0DEFACE`.
- **V2 — telecommand type confusion**: the firmware dispatches on APID and never
  checks the TM/TC type bit, so a command declared as telemetry still executes.
- **V7 — payload relay abuse**: `BROADCAST_MSG` relays attacker content outside
  payload mode (only a warning), a bent-pipe transponder hijack.
- **V6 — AES key dictionary attack**: the static AES-128 link key (`PWNsatLabKey1234`)
  is recovered from captured ciphertext with the lab wordlist.
- **V5 — maintenance debug backdoor**: `DEBUG_CONFIG` strips link encryption (and
  lets ground-station mode be disabled without auth).
- **V1 — SPP parser over-read**: runs the **real** `firmware/spp.cpp` in an isolated
  subprocess; a short packet with a large declared length leaks adjacent memory.

## Repository layout

```
lab/        the platform (server, simulator, web UI, tests)
tools/      pwnsat_protocol.py — the CCSDS SPP + AES-128 core the lab reuses
firmware/   spp.cpp / spp.h — the real parser compiled for exercise V1
keys.txt    AES-128 candidate wordlist for exercise V6
```

`tools/pwnsat_protocol.py` and `firmware/spp.*` are the only files vendored
from the original Pwnsat workshop (by astrobyte, GPL-2.0-or-later — see NOTICE);
the workshop book, captures and full tooling are intentionally not included.

## Run

No dependencies — Python 3 standard library only.

```bash
python3 lab/server.py --host 0.0.0.0 --port 8080
```

Open `http://<instructor-ip>:8080/` in each student browser. Each browser gets its
own session id (stored in `localStorage`); the satellite state is per-session and
never shared. Bind to `127.0.0.1` for local-only; do **not** expose to the public
internet (it is intentionally vulnerable).

## Try the exercises

In the terminal (or click the commands in the Wiki panel).

**V4 — flash-window flag:**

```
debug on
flash-read 0xA5 83 32 0xC35A
```

Select the returned `APID 0x0B` packet, expand **Data Field → Payload** — the
dissector surfaces the `FLAG` field. The firmware caps a read at 32 bytes, so read
again at offset 115 for the remainder (`flash-read 0xA5 115 32 0xC35A`). Leave
secure link ON and the downlink is AES-encrypted on the wire; the analyzer decrypts
it with the known lab key (`PWNsatLabKey1234`). A wrong unlock gives `FLASH WINDOW
LOCKED`.

**V3 — ground-station auth bypass:**

```
gs-mode on
ping                      # blocked: GS AUTH REQUIRED
gs-access challenge       # read the leaked challenge in the reply / console
xor <challenge> 0xC0DEFACE
gs-access respond <result>
ping                      # now returns PING ACK
```

The challenge expires after 60 s (firmware-faithful), so forge and respond promptly.

**V2 — type confusion:**

```
mode 1                    # baseline NOMINAL
send-tm 0x0D 02           # MISSION_MODE command declared as telemetry (Type=0)
```

The Mode changes to PAYLOAD anyway. Select the uplink packet: its Packet Type reads
`0 (TM) ⚠ type confusion`, yet it executed. The dissector decodes by direction, so the
uplink is shown as a command even though its type bit lies.

**V7 — payload relay abuse:**

```
mode 1                            # NOT in payload mode
broadcast 0x1A2B 486920536174     # relay "Hi Sat" on an arbitrary frequency
payload-status                    # forward counter + recorded frequency
```

The satellite re-broadcasts the message as TM 0x06 (select it → `Relayed message`)
and only logs `Payload relay used outside payload mode` — it never refuses.

**V6 — AES key dictionary attack:**

```
brute-force     # attacks the session's own captured encrypted telemetry
```

Keep the secure link ON so encrypted STATUS packets are captured, then run it: the
attack tries each key in `keys.txt` and recovers `PWNsatLabKey1234`.

**V5 — debug backdoor:**

```
debug on        # STATUS telemetry flips to cleartext (Security Flag 0x00)
debug off       # encryption restored
```

With the secure link ON, STATUS packets carry Security Flag 0x01; after `debug on`
they drop to 0x00 (and shrink from 23 to 15 bytes) — no key needed. Debug also lets
`gs-mode off` succeed without an authenticated session.

**V1 — SPP parser over-read (runs real firmware code):**

```
overread 64     # 8-byte packet, declared length 64
```

The hardened `spp_parser.py` rejects it (length mismatch); the real
`spp_unpack_packet` copies 65 bytes from the 8-byte buffer and leaks the planted
secret `PWNSAT{spp_overread_leaks_adjacent_memory}`. **V1 needs a C++ compiler**
(`clang++` or `g++`); the server builds `lab/v1/spp_harness` on first use and runs
it in an isolated subprocess. The other six exercises need no compiler.

## Test

```bash
python3 lab/test_slice.py      # 17 checks: V4 chain, AES path, isolation, dissector
```

## Files

| File | Role |
|---|---|
| `satellite_sim.py` | behavioral port of `firmware/worker.cpp` dispatch + CCSDS dissector; reuses `tools/pwnsat_protocol.py` as the SPP/AES core |
| `terminal.py` | restricted `pwnsat>` command shell (compatibility layer, no host access) |
| `server.py` | stdlib HTTP + hand-rolled WebSocket; one `SatelliteSim` per session |
| `static/` | SPA: 3-pane packet analyzer, terminal, satellite console, wiki, en/ja i18n |
| `test_slice.py` | headless self-tests |

## Branding, theme & instructor console

- GSpace palette (`paleta/GSPACE-colores.json`): near-black `#0A0A0A`, cyan accent
  `#00E5FF`. The GSpace logo (`static/gspace-logo.png`) sits beside "PWNSAT LAB".
- Dark/light theme toggle (◐ in the top bar), persisted per browser and shared with
  the instructor page.
- **Instructor console** at `/instructor.html`, password-gated: server checks the
  password (constant-time) and issues a short-lived token; actions require it.
  Shows active sessions, per-session health/mode/flags/counts, server RSS & uptime
  (auto-refresh 3 s), and per-session **Reset**/**Delete** plus **Reset all**.
  Set the password with the `INSTRUCTOR_PASSWORD` env var (defaults to the one
  provided); run only on a trusted LAN, never the public internet.

```bash
INSTRUCTOR_PASSWORD='your-pass' python3 lab/server.py --host 0.0.0.0 --port 8080
```

## Measured capacity (tested, not estimated)

Measured with `python3 lab/loadtest.py`, which opens N independent WebSocket
sessions that each set a **unique** mission mode and read it back (so cross-talk
would be detected) and recover the flash flag, while sampling the server process's
peak RSS and CPU. Host: Apple M4 (10 cores), macOS 26.6, Python 3.10.21.

Secure link **ON** is the realistic default (pure-Python AES on every telemetry
packet); the debug/cleartext row is the floor.

| Students | RSS (secure ON) | server CPU (secure ON) | RSS (cleartext) | CPU (cleartext) |
|---|---|---|---|---|
| idle | 24.6 MB | — | 24.6 MB | — |
| 10 | 26.2 MB | 0.8 % | 25.5 MB | 0.3 % |
| 20 | 26.5 MB | 1.5 % | 26.1 MB | 0.6 % |
| 30 | 27.0 MB | 2.3 % | 26.8 MB | 0.7 % |
| 50 | 29.3 MB | 3.6 % | 27.9 MB | 1.3 % |
| 100 | 31.1 MB | 7.0 % | 30.8 MB | 2.4 % |

All rows are direct measurements. In every run all N sessions recovered their flag
with **0 isolation failures**. RSS grows ~60 KB per session and CPU ~0.07 %/session
(secure). 30 students fit in well under 30 MB and a few percent of one core — any
laptop handles it; the practical limit is OS file-descriptor/thread limits, not CPU
or memory, far beyond 30. Storage is negligible: sessions are in-memory only, and
the whole lab (code + static assets + compiled V1 harness) is ~250 KB.

## Ports & scope

- One TCP port (default 8080), HTTP + WebSocket on the same port.
- Isolation model: one `SatelliteSim` object per session id, no shared satellite
  state; the terminal can only emit SPP packets into its own sim (no shell, no `/dev`).

## Limitations (honest)

- All seven catalogued vulnerabilities (V1–V7) are implemented. V2–V7 run against
  the `SatelliteSim` behavioral port; V1 runs the real compiled `firmware/spp.cpp`.
- Implements the APIDs these exercises use (PING, VERSION, STATUS, MISSION_MODE,
  AES/DEBUG config, FLASH_READ, BROADCAST_MSG, PAYLOAD_STATUS, GS_MODE/ACCESS/STATUS)
  + periodic STATUS/idle telemetry. APIDs outside the exercises (SET_THRUSTER,
  SET_BEACON_RATE, the firmware-image FLASH stream) are not yet handled.
- `SatelliteSim` is a **behavioral** port: bytes are produced by the real protocol
  module (wire fidelity is exact), mission logic is reproduced, not original machine
  code. Only V1 executes unmodified firmware C. GPS is abstracted to "usable + in
  range" so V3 focuses on the auth forge; the full geofence / GPS-spoofing surface
  is a later exercise.
- V6's dictionary attack runs against the session's own captured ciphertext, not the
  provided `material/tm_capture_encrypted.pcapng`; it recovers the same key.
- Server is stdlib threading (chosen for zero-install/offline), one thread per
  session. Load-tested to 100 concurrent sessions (see **Measured capacity**);
  10–30 students use ~27 MB and a few percent of one core, with isolation verified
  under load. Beyond ~100 the limit is OS thread/fd count, where an asyncio
  (FastAPI+websockets) rewrite would scale further.
