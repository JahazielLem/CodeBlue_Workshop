"use strict";
// --- i18n -----------------------------------------------------------------
const I18N = {
  en: {
    session: "Session", link: "Secure link", mode: "Mode", exercise: "Exercise",
    wiki: "Wiki", reset: "Reset satellite", pause: "Pause", resume: "Resume",
    clear: "Clear", export: "Export", terminal: "Student terminal", console: "Satellite console",
    instructor: "Instructor", hardware: "Hardware lab",
    wiki_title: "Exercise V4 — Flash-window flag",
    wiki_goal: "Goal: recover the secret stored behind the maintenance flash window.",
    wiki_h_bg: "Background",
    wiki_bg: "The FLASH_READ command (APID 0x0B) reads a maintenance blob, but only if the request carries the correct window id and unlock tag. These constants are hardcoded in the firmware (worker.cpp): window 0xA5, unlock 0xC35A. The hint line in the blob itself confirms them: MAINT:FLASH_WINDOW=A5:C35A.",
    wiki_h_steps: "Steps",
    wiki_s1: "Disable encryption so the reply is readable:",
    wiki_s2: "Read the window at the offset of the FLAG line (click to run):",
    wiki_s3: "The reply (APID 0x0B) appears in the packet list. Select it and open the Data Field in the tree — the FLAG field shows the secret.",
    wiki_h_try: "Try also",
    wiki_try: "Leave the secure link ON and read again: the downlink is AES-encrypted on the wire, but the analyzer decrypts it with the known lab key. Send a wrong unlock (e.g. 0x0000) to see FLASH WINDOW LOCKED.",
    wiki_h_vuln: "Why it matters",
    wiki_vuln: "A hardcoded unlock constant is not authentication. Anyone who can read the firmware or sniff one request can replay it. The defensive fix is per-command authentication and authorization, not a shared magic value.",
    col_time: "Time", col_dir: "Dir", col_apid: "APID", col_seq: "Seq", col_len: "Len", col_info: "Info",
    empty: "No packets yet. Run a command in the terminal below.",
    ex_pick: "Exercise:",
    v3_title: "Exercise V3 — Ground-station auth bypass",
    v3_goal: "Goal: defeat the ground-station command gate by forging the challenge response.",
    v3_h_bg: "Background",
    v3_bg: "When ground-station mode is on, commands require an authenticated session. The satellite issues a random challenge; the expected answer is simply challenge XOR 0xC0DEFACE — a shared constant baked into the firmware (worker.cpp:234). The challenge is sent back in cleartext, so an attacker who sees it can compute the answer.",
    v3_h_steps: "Steps",
    v3_s1: "Enable the gate, then confirm a command is blocked:",
    v3_s2: "Request a challenge and read the 'GS Challenge' field in the reply (packet tree or console):",
    v3_s3: "Forge the response — XOR the challenge with the shared key:",
    v3_s4: "Send the forged response, then the blocked command now works:",
    v3_h_vuln: "Why it matters",
    v3_vuln: "A challenge-response is only as strong as its secret. A fixed XOR key is equivalent to no authentication: one sniffed exchange reveals it forever. The fix is a per-session secret and a real MAC (e.g. HMAC) over each command, with freshness.",
    v2_title: "Exercise V2 — Telecommand type confusion",
    v2_goal: "Goal: execute a command that is framed as telemetry, proving the satellite ignores the packet Type bit.",
    v2_h_bg: "Background",
    v2_bg: "The CCSDS header has a Type bit: 1 = telecommand (uplink), 0 = telemetry (downlink). The firmware dispatches purely by APID and never checks this bit (worker.cpp:1556). So an uplink packet marked as telemetry is still executed. A filter that blocks only 'commands' by type would be bypassed.",
    v2_s1: "Baseline — send a normal command and watch the Mode change to PAYLOAD:",
    v2_s2: "Reset the mode:",
    v2_s3: "Now send the SAME command, but declared as telemetry (Type=0):",
    v2_s4: "The Mode changes to PAYLOAD anyway. Select the uplink packet — its Packet Type reads 0 (TM), flagged as type confusion, yet it executed.",
    v2_h_vuln: "Why it matters",
    v2_vuln: "Type, APID, and length must be validated at the trust boundary. Dispatching on APID alone lets telemetry-shaped traffic drive commands, defeating naive direction/type filters. The fix is to reject any command-ingress packet whose Type bit is not TC.",
    v7_title: "Exercise V7 — Payload relay abuse",
    v7_goal: "Goal: use the satellite as a bent-pipe transponder to rebroadcast arbitrary content outside payload mode.",
    v7_h_bg: "Background",
    v7_bg: "The BROADCAST_MSG command (APID 0x06) carries a frequency and a message, and the satellite retransmits the message as telemetry. It is meant for authorized payload operations, but the firmware only logs a warning when used outside payload mode (worker.cpp:1465) — it never refuses, and bumps a forward counter each time.",
    v7_s1: "Confirm the satellite is NOT in payload mode:",
    v7_s2: "Relay an arbitrary message on an arbitrary frequency (hex = 'Hi Sat'):",
    v7_s3: "The satellite re-broadcasts it (TM 0x06) and warns 'Payload relay used outside payload mode'. Select the TM packet — 'Relayed message' shows your content.",
    v7_s4: "Check the abuse counters — the forward count climbs and your frequency is recorded:",
    v7_h_vuln: "Why it matters",
    v7_vuln: "A transponder that relays without mode enforcement or authorization can be hijacked to rebroadcast attacker content on arbitrary frequencies. The fix is to gate the relay behind payload-armed mode, authenticate the command, and rate-limit it.",
    v6_title: "Exercise V6 — AES key dictionary attack",
    v6_goal: "Goal: recover the AES-128 link key from captured encrypted telemetry.",
    v6_h_bg: "Background",
    v6_bg: "The secure link uses AES-128-ECB with a single static key. A static key from a small or guessable space falls to a dictionary attack. Capture encrypted telemetry (secure link ON → Security Flag 0x01), then try candidate keys until one yields valid plaintext.",
    v6_s1: "Keep the secure link ON (default). An encrypted STATUS packet appears (Security Flag 0x01).",
    v6_s2: "Run the dictionary attack against your captured ciphertext:",
    v6_s3: "The attack reports the matching key — PWNsatLabKey1234, a weak human-readable string. It is also line 3 of the lab wordlist keys.txt.",
    v6_h_vuln: "Why it matters",
    v6_vuln: "ECB plus a static, low-entropy key is confidentiality theatre — one wordlist breaks it, and ECB also leaks structure. The fix is per-session keys from a KDF, authenticated encryption (AES-GCM), and key rotation.",
    v5_title: "Exercise V5 — Maintenance debug backdoor",
    v5_goal: "Goal: use the debug mode to strip link encryption (and bypass the ground-station gate).",
    v5_h_bg: "Background",
    v5_bg: "DEBUG_CONFIG (APID 0x10) toggles a USB debug flag reachable from the command link. When on, the firmware sends telemetry in cleartext and no longer requires authentication to disable ground-station mode (worker.cpp:603, 363).",
    v5_s1: "With the secure link ON, STATUS telemetry is encrypted — select a STATUS packet and note Security Flag 0x01.",
    v5_s2: "Enable debug mode:",
    v5_s3: "STATUS telemetry is now cleartext (Security Flag 0x00) — no key needed. The maintenance flag defeated the link crypto.",
    v5_s4: "Turn it back off to restore encryption:",
    v5_h_vuln: "Why it matters",
    v5_vuln: "A debug/maintenance path that disables security controls must not be reachable over the operational link, or must require strong authentication. The fix is to remove the backdoor or gate it behind physical access — never let it disable crypto on the live link.",
    v1_title: "Exercise V1 — SPP parser over-read",
    v1_goal: "Goal: make the real firmware parser leak adjacent memory by declaring a length larger than the packet.",
    v1_h_bg: "Background",
    v1_bg: "This exercise runs the ACTUAL firmware C code — firmware/spp.cpp, compiled on the host and executed in an isolated subprocess, not a behavioural port. spp_unpack_packet trusts the packet's declared length and never checks that the input buffer holds that many bytes (spp.cpp:100). A secret is planted in memory right after your packet, so an over-read copies it into space_packet.data.",
    v1_s1: "Craft a short packet (8 bytes) with a large declared length and hand it to the real parser:",
    v1_s2: "The hardened ground-tool parser rejects it (length mismatch). The firmware parser copies declared_len+1 bytes anyway, reading past your packet.",
    v1_s3: "The leaked space_packet.data contains the planted secret from adjacent memory — PWNSAT{spp_overread_leaks_adjacent_memory}.",
    v1_h_vuln: "Why it matters",
    v1_vuln: "Trusting a length field from the wire is a classic memory-safety bug: it leaks adjacent memory (keys, secrets), and the off-by-one at length=200 writes one byte past the buffer. The fix is to check the input holds declared_len+1 bytes and bound the copy to the destination size.",
  },
  ja: {
    session: "セッション", link: "セキュアリンク", mode: "モード", exercise: "演習",
    wiki: "ウィキ", reset: "衛星をリセット", pause: "一時停止", resume: "再開",
    clear: "クリア", export: "エクスポート", terminal: "受講者ターミナル", console: "衛星コンソール",
    instructor: "教官", hardware: "ハードウェアラボ",
    wiki_title: "演習 V4 — フラッシュウィンドウのフラグ",
    wiki_goal: "目標：メンテナンス用フラッシュウィンドウに隠された秘密値を取得する。",
    wiki_h_bg: "背景",
    wiki_bg: "FLASH_READ コマンド（APID 0x0B）はメンテナンス用データを読み出しますが、正しいウィンドウIDとアンロックタグが必要です。これらの定数はファームウェア（worker.cpp）にハードコードされています：ウィンドウ 0xA5、アンロック 0xC35A。データ内のヒント行 MAINT:FLASH_WINDOW=A5:C35A がこれを裏付けます。",
    wiki_h_steps: "手順",
    wiki_s1: "応答を読めるように暗号化を無効化します：",
    wiki_s2: "FLAG 行のオフセットでウィンドウを読み出します（クリックで実行）：",
    wiki_s3: "応答（APID 0x0B）がパケット一覧に表示されます。選択してツリーの Data Field を開くと、FLAG フィールドに秘密値が表示されます。",
    wiki_h_try: "さらに試す",
    wiki_try: "セキュアリンクを ON のまま再度読み出すと、ダウンリンクは回線上では AES 暗号化されますが、アナライザーは既知のラボ鍵で復号します。誤ったアンロック（例：0x0000）を送ると FLASH WINDOW LOCKED が表示されます。",
    wiki_h_vuln: "なぜ重要か",
    wiki_vuln: "ハードコードされたアンロック定数は認証ではありません。ファームウェアを読める者や1回の要求を傍受できる者は再送できます。防御策は共有マジック値ではなく、コマンドごとの認証と認可です。",
    col_time: "時刻", col_dir: "方向", col_apid: "APID", col_seq: "Seq", col_len: "長さ", col_info: "情報",
    empty: "パケットはまだありません。下のターミナルでコマンドを実行してください。",
    ex_pick: "演習：",
    v3_title: "演習 V3 — 地上局認証バイパス",
    v3_goal: "目標：チャレンジ応答を偽造して地上局コマンドゲートを突破する。",
    v3_h_bg: "背景",
    v3_bg: "地上局モードが有効なとき、コマンドには認証済みセッションが必要です。衛星はランダムなチャレンジを発行しますが、期待される応答は単に チャレンジ XOR 0xC0DEFACE です。これはファームウェアに埋め込まれた共有定数です（worker.cpp:234）。チャレンジは平文で返送されるため、それを観測した攻撃者は応答を計算できます。",
    v3_h_steps: "手順",
    v3_s1: "ゲートを有効化し、コマンドがブロックされることを確認します：",
    v3_s2: "チャレンジを要求し、応答内の「GS Challenge」フィールドを読み取ります（パケットツリーまたはコンソール）：",
    v3_s3: "応答を偽造します — チャレンジと共有鍵を XOR します：",
    v3_s4: "偽造した応答を送信すると、ブロックされていたコマンドが通ります：",
    v3_h_vuln: "なぜ重要か",
    v3_vuln: "チャレンジ応答はその秘密の強さ次第です。固定XOR鍵は認証がないのと同じで、1回の傍受で永久に露見します。対策はセッションごとの秘密と、各コマンドに対する本物のMAC（例：HMAC）、そして新鮮性です。",
    v2_title: "演習 V2 — テレコマンド型混同",
    v2_goal: "目標：テレメトリとして整形されたコマンドを実行させ、衛星がパケットのType ビットを無視することを証明する。",
    v2_h_bg: "背景",
    v2_bg: "CCSDSヘッダにはTypeビットがあります：1＝テレコマンド（アップリンク）、0＝テレメトリ（ダウンリンク）。ファームウェアはAPIDのみで振り分け、このビットを一切検査しません（worker.cpp:1556）。そのため、テレメトリと記したアップリンクパケットも実行されます。Typeでコマンドのみを遮断するフィルタは回避されます。",
    v2_s1: "基準 — 通常のコマンドを送信し、モードが PAYLOAD に変わることを確認します：",
    v2_s2: "モードをリセットします：",
    v2_s3: "次に、同じコマンドをテレメトリ（Type=0）として送信します：",
    v2_s4: "それでもモードは PAYLOAD に変わります。アップリンクパケットを選択すると、Packet Type は 0 (TM) と表示され型混同として警告されますが、実行されています。",
    v2_h_vuln: "なぜ重要か",
    v2_vuln: "Type・APID・長さは信頼境界で検証しなければなりません。APIDのみで振り分けると、テレメトリ形のトラフィックがコマンドを駆動でき、素朴な方向／Typeフィルタを突破します。対策は、TypeビットがTCでないコマンド入力パケットを拒否することです。",
    v7_title: "演習 V7 — ペイロード中継の悪用",
    v7_goal: "目標：衛星をベントパイプ中継器として使い、ペイロードモード外で任意の内容を再送信する。",
    v7_h_bg: "背景",
    v7_bg: "BROADCAST_MSG コマンド（APID 0x06）は周波数とメッセージを運び、衛星はそのメッセージをテレメトリとして再送信します。本来は認可されたペイロード運用向けですが、ファームウェアはペイロードモード外で使われても警告を記録するだけで（worker.cpp:1465）、拒否せず、毎回転送カウンタを増やします。",
    v7_s1: "衛星がペイロードモードでないことを確認します：",
    v7_s2: "任意の周波数で任意のメッセージを中継します（16進＝'Hi Sat'）：",
    v7_s3: "衛星はそれを再送信し（TM 0x06）、「Payload relay used outside payload mode」と警告します。TMパケットを選択すると「Relayed message」に送信内容が表示されます。",
    v7_s4: "悪用カウンタを確認します — 転送回数が増え、あなたの周波数が記録されています：",
    v7_h_vuln: "なぜ重要か",
    v7_vuln: "モード強制や認可なしに中継する中継器は、攻撃者の内容を任意の周波数で再送信するよう乗っ取られ得ます。対策は、中継をペイロード武装モードで制限し、コマンドを認証し、レート制限することです。",
    v6_title: "演習 V6 — AES鍵辞書攻撃",
    v6_goal: "目標：捕捉した暗号化テレメトリから AES-128 リンク鍵を復元する。",
    v6_h_bg: "背景",
    v6_bg: "セキュアリンクは単一の固定鍵で AES-128-ECB を使用します。小さい／推測可能な空間からの固定鍵は辞書攻撃で破られます。暗号化テレメトリ（セキュアリンクON → Security Flag 0x01）を捕捉し、正しい平文が得られるまで候補鍵を試します。",
    v6_s1: "セキュアリンクを ON のままにします（既定）。暗号化された STATUS パケットが現れます（Security Flag 0x01）。",
    v6_s2: "捕捉した暗号文に対して辞書攻撃を実行します：",
    v6_s3: "攻撃は一致した鍵を報告します — PWNsatLabKey1234、弱く人間可読な文字列です。ラボのワードリスト keys.txt の3行目でもあります。",
    v6_h_vuln: "なぜ重要か",
    v6_vuln: "ECB に固定・低エントロピー鍵を加えたものは機密性の見せかけに過ぎず、1つのワードリストで破れ、ECBは構造も漏らします。対策はKDFによるセッションごとの鍵、認証付き暗号（AES-GCM）、鍵のローテーションです。",
    v5_title: "演習 V5 — 保守用デバッグバックドア",
    v5_goal: "目標：デバッグモードを使ってリンク暗号化を無効化する（および地上局ゲートを回避する）。",
    v5_h_bg: "背景",
    v5_bg: "DEBUG_CONFIG（APID 0x10）はコマンドリンクから到達可能なUSBデバッグフラグを切り替えます。ONのとき、ファームウェアはテレメトリを平文で送信し、地上局モードの無効化に認証を要求しなくなります（worker.cpp:603, 363）。",
    v5_s1: "セキュアリンクが ON のとき、STATUS テレメトリは暗号化されています — STATUS パケットを選択し Security Flag 0x01 を確認します。",
    v5_s2: "デバッグモードを有効化します：",
    v5_s3: "STATUS テレメトリが平文になりました（Security Flag 0x00）— 鍵は不要です。保守フラグがリンク暗号を無効化しました。",
    v5_s4: "暗号化を戻すには再び無効化します：",
    v5_h_vuln: "なぜ重要か",
    v5_vuln: "セキュリティ制御を無効化する保守／デバッグ経路は、運用リンクから到達可能であってはならず、または強力な認証を要求すべきです。対策はバックドアを削除するか物理アクセスで制限することで、稼働リンク上で暗号を無効化させてはなりません。",
    v1_title: "演習 V1 — SPPパーサのオーバーリード",
    v1_goal: "目標：パケットより大きな長さを宣言して、実ファームウェアのパーサに隣接メモリを漏洩させる。",
    v1_h_bg: "背景",
    v1_bg: "この演習は実際のファームウェアCコード（firmware/spp.cpp）を実行します。ホスト上でコンパイルし、隔離された子プロセスで実行するもので、挙動の移植ではありません。spp_unpack_packet はパケットの宣言された長さを信頼し、入力バッファが実際にその長さを保持しているか検査しません（spp.cpp:100）。パケットの直後のメモリに秘密値が置かれているため、オーバーリードがそれを space_packet.data にコピーします。",
    v1_s1: "大きな宣言長を持つ短いパケット（8バイト）を作り、実パーサに渡します：",
    v1_s2: "堅牢化された地上ツールのパーサはこれを拒否します（長さ不一致）。ファームウェアのパーサは宣言長+1バイトをそのままコピーし、パケットの先を読みます。",
    v1_s3: "漏洩した space_packet.data には隣接メモリの秘密値が含まれます — PWNSAT{spp_overread_leaks_adjacent_memory}。",
    v1_h_vuln: "なぜ重要か",
    v1_vuln: "回線からの長さフィールドを信頼するのは典型的なメモリ安全性のバグで、隣接メモリ（鍵・秘密）を漏洩させ、length=200 のオフバイワンはバッファの1バイト先に書き込みます。対策は、入力が宣言長+1バイトを保持しているか確認し、コピーを宛先サイズに制限することです。",
  }
};
let lang = localStorage.getItem("pwnsat_lang") || "en";
const t = k => (I18N[lang][k] || I18N.en[k] || k);

// --- state ----------------------------------------------------------------
let packets = [], selected = -1, paused = false, logs = [];
let ws = null;
const sid = localStorage.getItem("pwnsat_sid") || "";
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const hhmmss = ts => new Date(ts * 1000).toLocaleTimeString("en-GB", { hour12: false }) +
  "." + String(Math.floor((ts % 1) * 1000)).padStart(3, "0");

// --- websocket ------------------------------------------------------------
function connect() {
  const q = sid ? ("?session=" + encodeURIComponent(sid)) : "";
  ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws" + q);
  ws.onmessage = ev => handle(JSON.parse(ev.data));
  ws.onclose = () => { termLine("* disconnected — reconnecting…", "txt"); setTimeout(connect, 1500); };
}
function send(obj) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); }

function handle(m) {
  switch (m.type) {
    case "hello":
      $("sid").textContent = m.session; localStorage.setItem("pwnsat_sid", m.session);
      $("exval").textContent = m.exercise; break;
    case "packet":
      if (!paused) { packets.push(m); renderList(); if (selected < 0) select(packets.length - 1); }
      break;
    case "log": logs.push(m); applyStatus(m); renderConsole(); break;
    case "term": termLine(m.text, "txt"); break;
    case "clear": packets = []; selected = -1; renderList(); $("tree").innerHTML = ""; $("hex").innerHTML = ""; break;
  }
}
// track link/mode from log text (keeps the top bar live without a side channel)
function applyStatus(m) {
  const x = m.text.toLowerCase();
  if (x.includes("secure link enabled")) setLink(true);
  if (x.includes("secure link disabled") || x.includes("debug mode enabled")) setLink(false);
  if (x.includes("restored to defaults") || x.includes("reinitialised")) setLink(true);
  const mm = m.text.match(/Mission mode -> (\w+)/); if (mm) $("modeval").textContent = mm[1];
}
function setLink(on) {
  const p = $("linkpill"); p.textContent = on ? "ON" : "OFF"; p.className = "pill " + (on ? "on" : "off");
}

// --- packet list ----------------------------------------------------------
function passesFilter(p) {
  const f = $("filter").value.trim().toLowerCase();
  if (!f) return true;
  return f.split(/\s+/).every(tok => {
    if (tok === "malformed") return p.malformed;
    if (tok === "tc") return p.dir === "tx";
    if (tok === "tm") return p.dir === "rx";
    let mm = tok.match(/^apid==?(.+)$/); if (mm) return p.summary.toLowerCase().includes(mm[1]);
    mm = tok.match(/^dir==?(.+)$/); if (mm) return p.dir === mm[1];
    return p.summary.toLowerCase().includes(tok) || (p.note || "").toLowerCase().includes(tok);
  });
}
function renderList() {
  const view = packets.map((p, i) => [p, i]).filter(([p]) => passesFilter(p));
  $("capcount").textContent = packets.length + " packets" + (view.length !== packets.length ? ` (${view.length} shown)` : "");
  if (!packets.length) { $("list").innerHTML = `<div style="padding:20px;color:var(--dim)">${esc(t("empty"))}</div>`; return; }
  const rows = view.map(([p, i]) => {
    const apid = (p.summary.match(/0x[0-9A-Fa-f]{3}/) || ["—"])[0];
    const seq = (p.summary.match(/seq=(\d+)/) || [, "—"])[1];
    const info = p.malformed ? p.summary : (p.note ? p.note + " · " : "") + p.summary.replace(/seq=\d+\s+len=\d+/, "").trim();
    const cls = (p.malformed ? "mal " : "") + "dir-" + p.dir;
    return `<tr data-i="${i}" class="${i === selected ? "sel" : ""}">
      <td class="ts">${hhmmss(p.ts)}</td><td class="${cls}">${p.dir.toUpperCase()}</td>
      <td class="${cls}">${apid}</td><td>${seq}</td><td>${p.length}</td><td>${esc(info)}</td></tr>`;
  }).join("");
  $("list").innerHTML = `<table class="plist"><thead><tr>
    <th>${t("col_time")}</th><th>${t("col_dir")}</th><th>${t("col_apid")}</th>
    <th>${t("col_seq")}</th><th>${t("col_len")}</th><th>${t("col_info")}</th></tr></thead><tbody>${rows}</tbody></table>`;
  $("list").querySelectorAll("tr[data-i]").forEach(tr => tr.onclick = () => select(+tr.dataset.i));
}
function select(i) { selected = i; renderList(); renderDetail(packets[i]); }

// --- detail tree + hex ----------------------------------------------------
let curHex = "";
function renderDetail(p) {
  if (!p) return;
  curHex = p.hex;
  $("tree").innerHTML = p.tree.map(n => treeNode(n)).join("");
  bindTree();
  renderHex(null);
}
function treeNode(n) {
  const kids = n.children && n.children.length;
  const span = n.span ? ` data-s="${n.span[0]}" data-e="${n.span[1]}"` : "";
  const caret = kids ? "▾" : "&nbsp;";
  const val = n.value === "" ? "" : `: <span class="fval">${esc(n.value)}</span>`;
  return `<div class="node"><div class="row"${span}><span class="caret">${caret}</span>
    <span class="fname">${esc(n.field)}</span>${val}</div>
    ${kids ? n.children.map(treeNode).join("") : ""}</div>`;
}
function bindTree() {
  $("tree").querySelectorAll(".row").forEach(r => {
    r.onclick = () => {
      $("tree").querySelectorAll(".row").forEach(x => x.classList.remove("hl"));
      r.classList.add("hl");
      renderHex(r.dataset.s != null ? [+r.dataset.s, +r.dataset.e] : null);
    };
  });
}
function renderHex(span) {
  const bytes = curHex.match(/../g) || [];
  let out = "";
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i + 16);
    const hex = row.map((b, j) => {
      const idx = i + j, hl = span && idx >= span[0] && idx < span[1];
      return `<span class="hexbyte${hl ? " hl" : ""}">${b}</span>`;
    }).join(" ");
    const ascii = row.map(b => { const v = parseInt(b, 16); return v >= 32 && v < 127 ? String.fromCharCode(v) : "."; })
      .join("").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
    out += String(i).padStart(4, "0") + "  " + hex.padEnd(16 * 3 * 7) + "  " + ascii + "\n";
  }
  $("hex").innerHTML = out;
}

// --- terminal -------------------------------------------------------------
let history = [], hpos = -1;
function termLine(txt, cls) {
  const d = document.createElement("div"); d.className = cls || ""; d.textContent = txt;
  $("termout").appendChild(d); $("termout").scrollTop = $("termout").scrollHeight;
}
$("termin").addEventListener("keydown", e => {
  if (e.key === "Enter") {
    const line = e.target.value; e.target.value = "";
    if (!line.trim()) return;
    history.push(line); hpos = history.length;
    termLine("pwnsat> " + line, "cmd");
    if (line.trim() === "clear") { $("termout").innerHTML = ""; }
    send({ type: "cmd", line });
  } else if (e.key === "ArrowUp") { if (hpos > 0) e.target.value = history[--hpos]; e.preventDefault(); }
  else if (e.key === "ArrowDown") { hpos = Math.min(history.length, hpos + 1); e.target.value = history[hpos] || ""; }
});

// --- console --------------------------------------------------------------
function renderConsole() {
  const q = $("consearch").value.toLowerCase();
  $("conout").innerHTML = logs.filter(l => !q || l.text.toLowerCase().includes(q))
    .map(l => `<div class="log-${l.level}"><span class="ts">${hhmmss(l.ts)}</span> [${l.level}] ${esc(l.text)}</div>`).join("");
  $("conout").scrollTop = $("conout").scrollHeight;
}

// --- controls -------------------------------------------------------------
$("pausebtn").onclick = () => { paused = !paused; $("pausebtn").textContent = paused ? t("resume") : t("pause"); };
$("clearcap").onclick = () => { packets = []; selected = -1; renderList(); $("tree").innerHTML = ""; $("hex").innerHTML = ""; };
$("exportcap").onclick = () => download("pwnsat_capture.json", JSON.stringify(packets, null, 2));
$("conclear").onclick = () => { logs = []; renderConsole(); };
$("conexport").onclick = () => download("pwnsat_console.log",
  logs.map(l => `${hhmmss(l.ts)} [${l.level}] ${l.text}`).join("\n"));
$("consearch").oninput = renderConsole;
$("filter").oninput = renderList;
$("resetbtn").onclick = () => send({ type: "reset" });
$("wikitoggle").onclick = () => $("wiki").classList.toggle("collapsed");
// theme (GSpace dark default; light optional), persisted per viewer
function applyTheme(th) {
  document.documentElement.setAttribute("data-theme", th);
  try { localStorage.setItem("pwnsat_theme", th); } catch (e) {}
  $("themetoggle").textContent = th === "light" ? "☀" : "◐";
}
$("themetoggle").onclick = () =>
  applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
applyTheme((() => { try { return localStorage.getItem("pwnsat_theme") || "dark"; } catch (e) { return "dark"; } })());
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

// --- wiki + i18n ----------------------------------------------------------
let currentEx = localStorage.getItem("pwnsat_ex") || "v4";
const run = cmd => `<code data-cmd="${cmd}">${cmd}</code>`;         // clickable
const lit = cmd => `<code>${cmd}</code>`;                           // plain (parameterized)
function exV4() {
  return `<p>1. ${esc(t("wiki_s1"))}</p><p>${run("debug on")}</p>
    <p>2. ${esc(t("wiki_s2"))}</p><p>${run("flash-read 0xA5 83 32 0xC35A")}</p>
    <p>3. ${esc(t("wiki_s3"))}</p>
    <h3>${esc(t("wiki_h_try"))}</h3><p>${esc(t("wiki_try"))}</p>`;
}
function exV3() {
  return `<p>1. ${esc(t("v3_s1"))}</p><p>${run("gs-mode on")} &nbsp; ${run("ping")}</p>
    <p>2. ${esc(t("v3_s2"))}</p><p>${run("gs-access challenge")}</p>
    <p>3. ${esc(t("v3_s3"))}</p><p>${lit("xor &lt;challenge&gt; 0xC0DEFACE")}</p>
    <p>4. ${esc(t("v3_s4"))}</p><p>${lit("gs-access respond &lt;forged&gt;")} &nbsp; ${run("ping")}</p>`;
}
function exV2() {
  return `<p>1. ${esc(t("v2_s1"))}</p><p>${run("mode 2")}</p>
    <p>2. ${esc(t("v2_s2"))}</p><p>${run("mode 1")}</p>
    <p>3. ${esc(t("v2_s3"))}</p><p>${run("send-tm 0x0D 02")}</p>
    <p>4. ${esc(t("v2_s4"))}</p>`;
}
function exV7() {
  return `<p>1. ${esc(t("v7_s1"))}</p><p>${run("mode 1")}</p>
    <p>2. ${esc(t("v7_s2"))}</p><p>${run("broadcast 0x1A2B 486920536174")}</p>
    <p>3. ${esc(t("v7_s3"))}</p>
    <p>4. ${esc(t("v7_s4"))}</p><p>${run("payload-status")}</p>`;
}
function exV6() {
  return `<p>1. ${esc(t("v6_s1"))}</p>
    <p>2. ${esc(t("v6_s2"))}</p><p>${run("brute-force")}</p>
    <p>3. ${esc(t("v6_s3"))}</p>`;
}
function exV5() {
  return `<p>1. ${esc(t("v5_s1"))}</p>
    <p>2. ${esc(t("v5_s2"))}</p><p>${run("debug on")}</p>
    <p>3. ${esc(t("v5_s3"))}</p>
    <p>4. ${esc(t("v5_s4"))}</p><p>${run("debug off")}</p>`;
}
function exV1() {
  return `<p>1. ${esc(t("v1_s1"))}</p><p>${run("overread 64")}</p>
    <p>2. ${esc(t("v1_s2"))}</p>
    <p>3. ${esc(t("v1_s3"))}</p>`;
}
const EXERCISES = {
  v4: { title: "wiki_title", goal: "wiki_goal", h_bg: "wiki_h_bg", bg: "wiki_bg",
        h_vuln: "wiki_h_vuln", vuln: "wiki_vuln", body: exV4 },
  v3: { title: "v3_title", goal: "v3_goal", h_bg: "v3_h_bg", bg: "v3_bg",
        h_vuln: "v3_h_vuln", vuln: "v3_vuln", body: exV3 },
  v2: { title: "v2_title", goal: "v2_goal", h_bg: "v2_h_bg", bg: "v2_bg",
        h_vuln: "v2_h_vuln", vuln: "v2_vuln", body: exV2 },
  v7: { title: "v7_title", goal: "v7_goal", h_bg: "v7_h_bg", bg: "v7_bg",
        h_vuln: "v7_h_vuln", vuln: "v7_vuln", body: exV7 },
  v6: { title: "v6_title", goal: "v6_goal", h_bg: "v6_h_bg", bg: "v6_bg",
        h_vuln: "v6_h_vuln", vuln: "v6_vuln", body: exV6 },
  v5: { title: "v5_title", goal: "v5_goal", h_bg: "v5_h_bg", bg: "v5_bg",
        h_vuln: "v5_h_vuln", vuln: "v5_vuln", body: exV5 },
  v1: { title: "v1_title", goal: "v1_goal", h_bg: "v1_h_bg", bg: "v1_bg",
        h_vuln: "v1_h_vuln", vuln: "v1_vuln", body: exV1 },
};
function renderWiki() {
  const e = EXERCISES[currentEx];
  $("wiki").innerHTML = `
    <div style="margin-bottom:10px"><label class="stat">${esc(t("ex_pick"))}
      <select id="exsel">
        <option value="v4" ${currentEx === "v4" ? "selected" : ""}>V4 — flash flag</option>
        <option value="v3" ${currentEx === "v3" ? "selected" : ""}>V3 — auth bypass</option>
        <option value="v2" ${currentEx === "v2" ? "selected" : ""}>V2 — type confusion</option>
        <option value="v7" ${currentEx === "v7" ? "selected" : ""}>V7 — relay abuse</option>
        <option value="v6" ${currentEx === "v6" ? "selected" : ""}>V6 — AES key crack</option>
        <option value="v5" ${currentEx === "v5" ? "selected" : ""}>V5 — debug backdoor</option>
        <option value="v1" ${currentEx === "v1" ? "selected" : ""}>V1 — SPP over-read</option>
      </select></label></div>
    <h2>${esc(t(e.title))}</h2><p>${esc(t(e.goal))}</p>
    <h3>${esc(t(e.h_bg))}</h3><p>${esc(t(e.bg))}</p>
    <h3>${esc(t("wiki_h_steps") || t("v3_h_steps"))}</h3>
    ${e.body()}
    <h3>${esc(t(e.h_vuln))}</h3><p>${esc(t(e.vuln))}</p>`;
  $("exsel").onchange = ev => {
    currentEx = ev.target.value; localStorage.setItem("pwnsat_ex", currentEx);
    $("exval").textContent = { v4: "V4 — flash-window flag", v3: "V3 — GS auth bypass",
      v2: "V2 — type confusion", v7: "V7 — payload relay abuse",
      v6: "V6 — AES key crack", v5: "V5 — debug backdoor",
      v1: "V1 — SPP over-read" }[currentEx];
    renderWiki();
  };
  $("wiki").querySelectorAll("code[data-cmd]").forEach(c => c.onclick = () => {
    termLine("pwnsat> " + c.dataset.cmd, "cmd"); send({ type: "cmd", line: c.dataset.cmd });
  });
}
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach(el => el.textContent = t(el.dataset.i18n));
  $("pausebtn").textContent = paused ? t("resume") : t("pause");
  renderWiki(); renderList(); if (selected >= 0) renderDetail(packets[selected]);
}
$("lang").value = lang;
$("lang").onchange = e => { lang = e.target.value; localStorage.setItem("pwnsat_lang", lang); applyLang(); };

applyLang();
connect();
