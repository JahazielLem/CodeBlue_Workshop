"use strict";
/* Hardware lab — logic-analyzer simulator.
 * Real protocol waveforms are generated as edge traces, sampled at the chosen
 * rate into bit arrays, and decoded by real I2C/SPI/UART decoders (not canned
 * strings). Wrong pins, wrong roles or too-low a sample rate break the decode —
 * exactly as on real hardware. A self-check at load asserts each decoder
 * reproduces its source bytes. */
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const hx = b => b.toString(16).toUpperCase().padStart(2, "0");
const asc = b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".";

// --- i18n ---
const I = {
  en: {
    title: "Hardware Lab · Logic Analyzer", target: "Target under test", probe: "Probe points",
    srate: "Sample rate", cap: "▶ Start capture", back: "← Lab",
    armed: "Connecting — click a pad to attach this probe", unused: "unused",
    pinhint: "Pads are unlabeled. Attach probes, capture, and read the signal to find each one.",
    gnd: "⏚ Ground clip", gndOn: p => `⏚ ground → pad ${p}`,
    noGnd: "No common ground — attach the ground clip to the GND pad (the constant-LOW one) and capture again.",
    gndWrong: "The ground clip is on a signal pad — move it to the GND pad (constant LOW).",
    tag: "+ tag",
    mapProbed: p => `${p} pads probed.`,
    mapTag: (t, n) => `Tagged ${t} of ${n} — click a pad's tag to label it (Vcc, GND, Clock, Data…).`,
    mapDone: "All pads tagged. Your map carries into the UART, I2C and SPI exercises.",
    obj: {
      map: "<b>Exercise 0 — Map the header.</b> Probe every pad, capture once, read each lane's signal and tag each pad with what it could be. Your tags carry into the other exercises.",
      uart: "<b>UART dump.</b> The GPS emits NMEA on one pad. Find the TX pad, assign a probe as <b>UART RX</b>, capture and read the text.",
      i2c: "<b>I2C dump.</b> Two pads carry the sensor bus. Find <b>SDA</b> and <b>SCL</b>, assign the two probes, set a fast enough rate and decode the transaction.",
      spi: "<b>SPI dump.</b> The flash chip exposes CS, CLK, DI and DO. Probe all four, assign the roles and raise the sample rate until the bytes decode.",
    },
    constH: "constant HIGH (Vcc / idle line)", constL: "constant LOW (GND)",
    clock: f => `clock ≈ ${f}`, data: n => `serial data (${n} edges)`, flat: "flat / no probe",
    capdone: "Captured. Classify each lane, then set its role.", needroles: "Assign the protocol roles to your probed lanes.",
    under: "Sample rate too low for this bus — the decoder is undersampling. Raise it.",
    decoded: "Decoded:", success: "✓ Bus captured and decoded correctly.",
    failmap: "Decode failed — a role is on the wrong pad, or the rate is too low.",
    spb: n => `${n.toFixed(1)} samples / bit`,
    wikiBtn: "Wiki", w_bg: "Background", w_steps: "Steps", w_why: "Why it matters",
    ch: {
      map: {
        t: "Exercise 0 — Map the header",
        goal: "Build a pin map before attacking: probe every pad and tag what each one is.",
        bg: "On a real target you never know the pinout up front. The fast way is to probe the whole connector at once, capture, and read each lane: a constant HIGH is Vcc, a constant LOW is GND, a steady square wave is a clock, and irregular transitions are a data or serial line.",
        steps: ["Connect a probe (D0…) to every pad — you have 8 channels for 7 pads.",
          "Capture once. Each lane's class appears in the rack (HIGH, LOW, clock, serial data).",
          "Click a pad's ‘+ tag’ to cycle a label (Vcc, GND, Clock, Data…) onto it.",
          "The ground pad is hinted with a dotted ring — but you still attach the clip in the other exercises.",
          "Your tags persist; open UART / I2C / SPI to confirm or correct them."],
        why: "A clean pin map turns slow pad-by-pad guessing into a one-shot capture and documents the attack surface.",
      },
      uart: {
        t: "Challenge — UART dump (GPS)",
        goal: "Recover the NMEA text the GPS module streams.",
        bg: "The GPS talks to the on-board computer over a UART line (GP0/TX) at 9600 baud, 8N1. UART is asynchronous — there is no clock line, so the receiver must know the baud rate. The idle line sits high; each byte is a start bit (low), 8 data bits (LSB first) and a stop bit (high).",
        steps: ["Attach probes to pads and capture. The TX line shows serial data; Vcc reads constant HIGH, GND constant LOW.",
          "Attach the ground clip to the GND pad (the constant-LOW one) — no common ground, no valid dump.",
          "Assign the probe on the data pad the role UART RX.",
          "Any sample rate ≥ ~4× the baud is plenty (4 MHz here).",
          "Capture — the decoder frames the bits into ASCII."],
        why: "An unauthenticated debug UART leaks telemetry, position and often a login console.",
      },
      i2c: {
        t: "Challenge — I2C dump (accelerometer)",
        goal: "Decode the sensor transaction on the I2C bus.",
        bg: "I2C is a two-wire bus: SDA (data) and SCL (clock), shared by the sensors (the accelerometer answers at 0x19). SDA changes while SCL is low and is sampled while SCL is high. A START is SDA falling while SCL is high; a STOP is SDA rising; every byte is acknowledged (ACK/NAK).",
        steps: ["Capture: one pad is a clock (~100 kHz), another carries data — find them. Vcc HIGH, GND LOW.",
          "Attach the ground clip to the GND pad.",
          "Assign SDA (the data lane) and SCL (the clock lane).",
          "Sample rate ≥ ~4× the bus (≥ 500 kHz); 4 MHz is comfortable.",
          "Capture — the decoder shows the address, ACK/NAK and START/STOP."],
        why: "I2C has no authentication — anyone on the bus can read or spoof the sensors.",
      },
      spi: {
        t: "Challenge — SPI dump (flash)",
        goal: "Capture the flash read and recover the bytes it returns.",
        bg: "SPI is four wires — CS (select), SCK (clock), MOSI/DI (controller→chip) and MISO/DO (chip→controller) — full-duplex. The flash is clocked fast (1 MHz); mode 0 samples on the rising edge. A READ is 0x03 + a 24-bit address, then the flash streams bytes back on MISO.",
        steps: ["Capture: find the fast clock (SCK), the two data lines (MOSI/MISO) and the chip-select (CS). Vcc HIGH, GND LOW.",
          "Attach the ground clip to the GND pad.",
          "Assign CS, SCK, MOSI and MISO.",
          "SPI is fast: 1 MHz undersamples — raise the rate to ≥ 4 MHz.",
          "Capture — the decoder shows MOSI/MISO byte pairs."],
        why: "SPI flash usually holds firmware and secrets in the clear; a probe dumps it off-chip.",
      },
    },
  },
  ja: {
    title: "ハードウェアラボ · ロジックアナライザ", target: "対象デバイス", probe: "探針ポイント",
    srate: "サンプルレート", cap: "▶ キャプチャ開始", back: "← ラボ",
    armed: "接続中 — パッドをクリックして接続", unused: "未使用",
    pinhint: "パッドにはラベルがありません。探針を接続し、キャプチャして信号から各ピンを特定します。",
    gnd: "⏚ グランドクリップ", gndOn: p => `⏚ グランド → パッド ${p}`,
    noGnd: "共通グランドがありません — グランドクリップを GND パッド（常時 LOW のもの）に接続して再キャプチャしてください。",
    gndWrong: "グランドクリップが信号パッドにあります — GND パッド（常時 LOW）へ移動してください。",
    tag: "+ タグ",
    mapProbed: p => `${p} 個のパッドを探りました。`,
    mapTag: (t, n) => `${n} 個中 ${t} 個にタグ — パッドのタグをクリックして分類（Vcc・GND・Clock・Data…）。`,
    mapDone: "すべてのパッドにタグ付け完了。マップは UART・I2C・SPI の演習に引き継がれます。",
    obj: {
      map: "<b>演習 0 — ヘッダのマッピング。</b> すべてのパッドを探り、一度キャプチャして各レーンの信号を読み、各パッドに「何であり得るか」のタグを付けます。タグは他の演習に引き継がれます。",
      uart: "<b>UART ダンプ。</b> GPS が1つのパッドに NMEA を出力します。TX パッドを見つけ、探針を <b>UART RX</b> に割り当て、キャプチャして文字を読みます。",
      i2c: "<b>I2C ダンプ。</b> 2つのパッドがセンサーバスを運びます。<b>SDA</b> と <b>SCL</b> を見つけ、2本の探針を割り当て、十分速いレートにしてトランザクションを復号します。",
      spi: "<b>SPI ダンプ。</b> フラッシュが CS・CLK・DI・DO を露出します。4本を探り、役割を割り当て、バイトが復号できるまでサンプルレートを上げます。",
    },
    constH: "常時 HIGH（Vcc / アイドル）", constL: "常時 LOW（GND）",
    clock: f => `クロック ≈ ${f}`, data: n => `シリアルデータ（${n} エッジ）`, flat: "平坦 / 未接続",
    capdone: "キャプチャ完了。各レーンを分類し、役割を設定してください。", needroles: "探ったレーンにプロトコルの役割を割り当ててください。",
    under: "このバスにはサンプルレートが低すぎます — アンダーサンプリングです。上げてください。",
    decoded: "復号結果:", success: "✓ バスを正しくキャプチャ・復号しました。",
    failmap: "復号に失敗 — 役割が誤ったパッドにあるか、レートが低すぎます。",
    spb: n => `${n.toFixed(1)} サンプル / ビット`,
    wikiBtn: "ウィキ", w_bg: "背景", w_steps: "手順", w_why: "なぜ重要か",
    ch: {
      map: {
        t: "演習 0 — ヘッダのマッピング",
        goal: "攻撃の前にピンマップを作る：すべてのパッドを探り、各々が何かをタグ付けする。",
        bg: "実際の対象ではピン配置は最初は分かりません。速い方法はコネクタ全体を一度に探ってキャプチャし、各レーンを読むことです：常時 HIGH は Vcc、常時 LOW は GND、一定の矩形波はクロック、不規則な変化はデータ／シリアル線です。",
        steps: ["すべてのパッドに探針（D0…）を接続 — 7 パッドに対し 8 チャンネルあります。",
          "一度キャプチャ。各レーンの分類がラックに表示されます（HIGH・LOW・クロック・シリアルデータ）。",
          "パッドの「+ タグ」をクリックしてラベル（Vcc・GND・Clock・Data…）を循環させます。",
          "グランドパッドは点線リングで示されますが、他の演習ではクリップを接続する必要があります。",
          "タグは保持されます。UART / I2C / SPI を開いて確認・修正してください。"],
        why: "きれいなピンマップは、パッドごとの遅い推測を一度のキャプチャに変え、攻撃面を文書化します。",
      },
      uart: {
        t: "課題 — UART ダンプ（GPS）",
        goal: "GPS モジュールが流す NMEA テキストを取得する。",
        bg: "GPS は UART 回線（GP0/TX）で 9600 baud・8N1 によりオンボードコンピュータと通信します。UART は非同期でクロック線がないため、受信側はボーレートを知る必要があります。アイドル時は HIGH、各バイトはスタートビット（LOW）・8 データビット（LSB first）・ストップビット（HIGH）です。",
        steps: ["パッドに探針を接続してキャプチャ。TX 線はシリアルデータを示し、Vcc は常時 HIGH、GND は常時 LOW。",
          "グランドクリップを GND パッド（常時 LOW）に接続 — 共通グランドがないと有効なダンプになりません。",
          "データパッドの探針に UART RX の役割を割り当てる。",
          "サンプルレートはボーレートの約 4 倍以上で十分（ここでは 4 MHz）。",
          "キャプチャ — デコーダがビットを ASCII に組み立てます。"],
        why: "認証のないデバッグ UART は、テレメトリ・位置・多くの場合ログインコンソールを漏らします。",
      },
      i2c: {
        t: "課題 — I2C ダンプ（加速度センサー）",
        goal: "I2C バス上のセンサートランザクションを復号する。",
        bg: "I2C は2線式バスで、SDA（データ）と SCL（クロック）をセンサーが共有します（加速度センサーは 0x19 で応答）。SDA は SCL が LOW の間に変化し、HIGH の間にサンプリングされます。START は SCL HIGH 中に SDA が立ち下がること、STOP は立ち上がること。各バイトは ACK/NAK されます。",
        steps: ["キャプチャ：一方のパッドはクロック（約 100 kHz）、もう一方はデータ。見つけます。Vcc は HIGH、GND は LOW。",
          "グランドクリップを GND パッドに接続。",
          "SDA（データ）と SCL（クロック）を割り当てる。",
          "サンプルレートはバスの約 4 倍以上（≥ 500 kHz）。4 MHz が快適。",
          "キャプチャ — デコーダがアドレス・ACK/NAK・START/STOP を表示します。"],
        why: "I2C に認証はなく、バス上の誰もがセンサーを読み取り・偽装できます。",
      },
      spi: {
        t: "課題 — SPI ダンプ（フラッシュ）",
        goal: "フラッシュの読み出しを捕捉し、返されるバイトを取得する。",
        bg: "SPI は4線式 — CS（選択）・SCK（クロック）・MOSI/DI（コントローラ→チップ）・MISO/DO（チップ→コントローラ）で全二重です。フラッシュは高速（1 MHz）で、モード0は立ち上がりでサンプリングします。READ は 0x03 + 24 ビットアドレスで、その後フラッシュが MISO にバイトを流します。",
        steps: ["キャプチャ：高速クロック（SCK）、2本のデータ線（MOSI/MISO）、チップセレクト（CS）を見つけます。Vcc HIGH、GND LOW。",
          "グランドクリップを GND パッドに接続。",
          "CS・SCK・MOSI・MISO を割り当てる。",
          "SPI は高速：1 MHz ではアンダーサンプリング — レートを 4 MHz 以上に上げます。",
          "キャプチャ — デコーダが MOSI/MISO のバイト対を表示します。"],
        why: "SPI フラッシュは多くの場合ファームウェアや秘密を平文で保持し、探針でチップ外へダンプできます。",
      },
    },
  },
};
let lang = (() => { try { return localStorage.getItem("pwnsat_lang") || "en"; } catch (e) { return "en"; } })();
const T = () => I[lang];

// --- exercises: pins (hidden truth) + bus rate + role options ---
const COLORS = ["e0a33e", "00e5ff", "ff5c5c", "3fb6c9", "b07cf0", "7cc47c", "f0c674", "9a9a9a"];
const HEADER = [{ t: "VCC" }, { t: "TX" }, { t: "RX" }, { t: "SDA" }, { t: "SCL" }, { t: "GND" }, { t: "NC" }];
const FLASH = [{ t: "CS" }, { t: "MISO" }, { t: "NC" }, { t: "GND" }, { t: "MOSI" }, { t: "SCK" }, { t: "NC" }, { t: "VCC" }];
const EX = {
  map: { bus: 100000, marker: "33% 76% 24% 7%", roles: [""], pins: HEADER, primary: null, tgt: "header" },
  uart: { bus: 9600, marker: "33% 76% 24% 7%", roles: ["", "RX"], pins: HEADER, primary: "RX", tgt: "header" },
  i2c: { bus: 100000, marker: "33% 76% 24% 7%", roles: ["", "SDA", "SCL"], pins: HEADER, primary: "SDA", tgt: "header" },
  spi: { bus: 1000000, marker: "35% 38% 8% 10%", roles: ["", "CS", "SCK", "MOSI", "MISO"], pins: FLASH, primary: "MOSI", tgt: "flash" },
};
// student-assigned pad labels (hypotheses), per target, persisted across exercises
const LABEL_OPTS = ["", "Vcc", "GND", "Clock", "Data", "Serial", "NC"];
let labels = (() => { try { return JSON.parse(localStorage.getItem("pwnsat_hw_labels")) || { header: {}, flash: {} }; } catch (e) { return { header: {}, flash: {} }; } })();
const tgtKey = () => ex.tgt;
function saveLabels() { try { localStorage.setItem("pwnsat_hw_labels", JSON.stringify(labels)); } catch (e) {} }
function cycleLabel(i) {
  const k = tgtKey(); labels[k] = labels[k] || {};
  const next = LABEL_OPTS[(LABEL_OPTS.indexOf(labels[k][i] || "") + 1) % LABEL_OPTS.length];
  if (next) labels[k][i] = next; else delete labels[k][i];
  saveLabels(); renderPins();
}

// --- signal generation (edge traces) ---
// trace = { v0, e:[{t,v}], dur }  — v0 = level at t=0, e = transitions
function segTrace(segs) { // segs: [[durNs, level], ...]
  const tr = { v0: segs[0][1], e: [], t: 0, dur: 0 }; let last = segs[0][1], t = 0;
  for (const [d, v] of segs) { if (v !== last) { tr.e.push({ t, v }); last = v; } t += d; }
  tr.dur = t; return tr;
}
function genUart(str, baud) {
  const bit = 1e9 / baud, segs = [[bit * 4, 1]];
  for (const ch of str) { const c = ch.charCodeAt(0);
    segs.push([bit, 0]); for (let b = 0; b < 8; b++) segs.push([bit, (c >> b) & 1]); segs.push([bit, 1]); }
  segs.push([bit * 4, 1]);
  return { tx: segTrace(segs), bytes: [...str].map(c => c.charCodeAt(0)) };
}
function genI2C(freq) {
  const half = 1e9 / freq / 2, seg = []; const P = (scl, sda, d) => seg.push([d, scl, sda]);
  const bytes = [];
  P(1, 1, half * 2);
  P(1, 0, half); // START
  const byte = (v, ack) => { bytes.push(v);
    for (let b = 7; b >= 0; b--) { const bit = (v >> b) & 1; P(0, bit, half); P(1, bit, half); }
    P(0, ack ? 0 : 1, half); P(1, ack ? 0 : 1, half); };
  byte(0x32, true);  // write addr 0x19
  byte(0x27, true);  // register
  P(0, 1, half); P(1, 1, half); P(1, 0, half); // repeated START
  byte(0x33, true);  // read addr 0x19
  byte(0xFF, false); // data + NAK
  P(0, 0, half); P(1, 0, half); P(1, 1, half); // STOP
  P(1, 1, half * 3);
  const scl = segTrace(seg.map(s => [s[0], s[1]])), sda = segTrace(seg.map(s => [s[0], s[2]]));
  return { scl, sda, bytes };
}
function genSPI(mosi, miso, freq) {
  const half = 1e9 / freq / 2, seg = []; const P = (cs, sck, mo, mi, d) => seg.push([d, cs, sck, mo, mi]);
  P(1, 0, 0, 0, half * 2); P(0, 0, 0, 0, half);
  const n = Math.max(mosi.length, miso.length);
  for (let k = 0; k < n; k++) { const mo = mosi[k] || 0, mi = miso[k] || 0;
    for (let b = 7; b >= 0; b--) { const a = (mo >> b) & 1, c = (mi >> b) & 1; P(0, 0, a, c, half); P(0, 1, a, c, half); } }
  P(0, 0, 0, 0, half); P(1, 0, 0, 0, half * 2);
  const idx = i => segTrace(seg.map(s => [s[0], s[i]]));
  return { cs: idx(1), sck: idx(2), mosi: idx(3), miso: idx(4), bytes: mosi };
}

// --- sampling: trace -> Uint8Array at rate ---
function sample(tr, rate) {
  const dt = 1e9 / rate, n = Math.max(1, Math.floor(tr.dur / dt)), a = new Uint8Array(n);
  let v = tr.v0, ei = 0;
  for (let i = 0; i < n; i++) { const t = i * dt; while (ei < tr.e.length && tr.e[ei].t <= t) { v = tr.e[ei].v; ei++; } a[i] = v; }
  return a;
}
const constTrace = v => ({ v0: v, e: [], dur: 1 });

// --- real decoders (operate on sampled bit arrays) ---
function decUART(a, rate, baud) {
  const spb = rate / baud, ann = [], bytes = []; let i = 1;
  while (i < a.length) {
    if (a[i - 1] === 1 && a[i] === 0) {
      const start = i; let byte = 0, bad = false;
      for (let b = 0; b < 8; b++) { const k = Math.round(start + spb * (1.5 + b)); if (k >= a.length) { bad = true; break; } byte |= (a[k] & 1) << b; }
      const stopK = Math.round(start + spb * 9.5);
      if (bad || stopK >= a.length) break;
      bytes.push(byte);
      ann.push({ t0: start / rate * 1e9, t1: (start + spb * 10) / rate * 1e9, text: asc(byte), kind: a[stopK] ? "ok" : "bad" });
      // resync into the stop bit (high) and let edge detection catch the next
      // start — jumping a full frame can overshoot the next falling edge.
      i = Math.round(start + spb * 9);
    } else i++;
  }
  return { ann, bytes };
}
function decI2C(sda, scl, rate) {
  const ann = [], bytes = [], toT = s => s / rate * 1e9; let on = false, bits = 0, n = 0, t0 = 0;
  for (let i = 1; i < sda.length; i++) {
    const hi = scl[i] === 1 && scl[i - 1] === 1;
    if (hi && sda[i - 1] === 1 && sda[i] === 0) { ann.push({ t0: toT(i), t1: toT(i), text: "S", kind: "start" }); on = true; n = 0; bits = 0; continue; }
    if (hi && sda[i - 1] === 0 && sda[i] === 1) { ann.push({ t0: toT(i), t1: toT(i), text: "P", kind: "stop" }); on = false; n = 0; continue; }
    if (on && scl[i - 1] === 0 && scl[i] === 1) {
      if (n === 0) t0 = i;
      if (n < 8) { bits = (bits << 1) | (sda[i] & 1); n++; }
      else { const ack = sda[i] === 0; bytes.push(bits);
        ann.push({ t0: toT(t0), t1: toT(i), text: `0x${hx(bits)} +${ack ? "ACK" : "NAK"}`, kind: ack ? "ok" : "bad" }); n = 0; bits = 0; }
    }
  }
  return { ann, bytes };
}
function decSPI(cs, sck, mosi, miso, rate) {
  const ann = [], bytes = [], toT = s => s / rate * 1e9; let bi = 0, mo = 0, mi = 0, n = 0, t0 = 0;
  for (let i = 1; i < cs.length; i++) {
    if (cs[i] === 0 && sck[i - 1] === 0 && sck[i] === 1) {
      if (n === 0) t0 = i;
      mo = (mo << 1) | (mosi[i] & 1); mi = (mi << 1) | (miso[i] & 1); n++;
      if (n === 8) { bytes.push(mo); ann.push({ t0: toT(t0), t1: toT(i), text: `${hx(mo)}/${hx(mi)}`, kind: "ok" }); n = 0; mo = 0; mi = 0; }
    }
  }
  return { ann, bytes };
}

// --- classify a captured lane (the "read the signal" hint) ---
function classify(a, rate) {
  let t = 0, n1 = 0; const edges = [];
  for (let i = 1; i < a.length; i++) { if (a[i] !== a[i - 1]) { t++; edges.push(i); } n1 += a[i]; }
  if (t === 0) return a[0] ? { k: "H", s: T().constH } : { k: "L", s: T().constL };
  const gaps = []; for (let i = 1; i < edges.length; i++) gaps.push(edges[i] - edges[i - 1]);
  const mean = gaps.reduce((x, y) => x + y, 0) / gaps.length;
  const varr = gaps.reduce((x, y) => x + (y - mean) ** 2, 0) / gaps.length;
  const cv = Math.sqrt(varr) / mean;
  if (cv < 0.25 && edges.length >= 6) { const f = rate / (2 * mean); const fs = f >= 1e6 ? (f / 1e6).toFixed(1) + " MHz" : Math.round(f / 1e3) + " kHz"; return { k: "C", s: T().clock(fs) }; }
  return { k: "D", s: T().data(t) };
}

// --- state ---
let exId = "map", ex = EX.map, probes = [], armed = -1, lastCap = null, gnd = { pin: null };
// probes[ch] = { pin: index|null, role: "" }  (8 channels); gnd = separate ground clip
function resetProbes() { probes = Array.from({ length: 8 }, () => ({ pin: null, role: "" })); armed = -1; lastCap = null; gnd = { pin: null }; }

// --- rendering: pins ---
function renderPins() {
  const lab = labels[tgtKey()] || {};
  $("pins").innerHTML = ex.pins.map((p, i) => {
    const ch = probes.findIndex(pr => pr.pin === i);
    const isGnd = gnd.pin === i;
    const col = ch >= 0 ? "#" + COLORS[ch] : "transparent";
    const fn = isGnd ? "⏚" : ch >= 0 ? "D" + ch : "";
    // the GND pad is hinted (so it is findable) but still needs the clip attached
    const padCls = isGnd ? " gnd" : (p.t === "GND" ? " gndhint" : "");
    const tag = lab[i] || "";
    return `<div class="pin" data-pin="${i}"><div class="wire" style="background:${col}"></div>
      <div class="pad${padCls}" title="${p.t === "GND" ? "⏚ ground — attach the clip" : ""}">${i + 1}</div>
      <div class="pn">P${i + 1}</div><div class="fn">${fn}</div>
      <div class="lbl ${tag ? "" : "empty"}" data-lbl="${i}">${tag || T().tag}</div></div>`;
  }).join("");
  $("pins").querySelectorAll(".pin").forEach(el => el.onclick = () => connectPin(+el.dataset.pin));
  $("pins").querySelectorAll("[data-lbl]").forEach(el => el.onclick = ev => { ev.stopPropagation(); cycleLabel(+el.dataset.lbl); });
  const g = $("gndclip");
  g.textContent = gnd.pin != null ? T().gndOn(gnd.pin + 1) : T().gnd;
  g.classList.toggle("armed", armed === "gnd");
  const m = $("marker"), mv = ex.marker.split(" ");
  m.style.left = mv[0]; m.style.top = mv[1]; m.style.width = mv[2]; m.style.height = mv[3];
}
function connectPin(pi) {
  if (armed === "gnd") { probes.forEach(pr => { if (pr.pin === pi) pr.pin = null; }); gnd.pin = pi; armed = -1; renderPins(); renderRack(); return; }
  if (armed < 0) return;
  probes.forEach(pr => { if (pr.pin === pi) pr.pin = null; }); // one probe per pad
  if (gnd.pin === pi) gnd.pin = null;
  probes[armed].pin = pi; armed = -1;
  renderPins(); renderRack();
}

// --- rendering: channel rack ---
function renderRack() {
  $("rack").innerHTML = probes.map((pr, ch) => {
    const cls = lastCap && lastCap.lanes[ch] ? lastCap.lanes[ch].s : "";
    const opts = ex.roles.map(r => `<option value="${r}" ${pr.role === r ? "selected" : ""}>${r || T().unused}</option>`).join("");
    const conn = pr.pin != null ? `→ <b>pad ${pr.pin + 1}</b>` : "—";
    return `<div class="chrow ${armed === ch ? "armed" : ""}" data-ch="${ch}">
      <span class="sw" style="background:#${COLORS[ch]}"></span><span class="cid">D${ch}</span>
      <span class="conn">${conn}</span>
      <button data-arm="${ch}">${armed === ch ? "…" : "connect"}</button>
      <select data-role="${ch}">${opts}</select>
      <span class="cls">${esc(cls)}</span></div>`;
  }).join("");
  $("rack").querySelectorAll("[data-arm]").forEach(b => b.onclick = () => { armed = armed === +b.dataset.arm ? -1 : +b.dataset.arm; renderPins(); renderRack(); });
  $("rack").querySelectorAll("[data-role]").forEach(s => s.onchange = () => { probes[+s.dataset.role].role = s.value; });
  const spb = (+$("srate").value) / ex.bus;
  $("spb").textContent = T().spb(spb);
}

// --- capture ---
function pinTrace(truth, sig) { // map a pad's hidden truth to its live signal for this exercise
  if (truth === "VCC") return constTrace(1);
  if (truth === "GND") return constTrace(0);
  if (sig[truth]) return sig[truth];       // active bus line
  return constTrace(1);                     // idle / NC / inactive line sits high
}
function capture() {
  const rate = +$("srate").value;
  // generate this exercise's live signals
  let sig = {};
  if (exId === "map") { const u = genUart("$GPGGA,PWNSAT*2A\r\n", 9600), g = genI2C(100000); sig = { TX: u.tx, SDA: g.sda, SCL: g.scl }; }
  else if (exId === "uart") { const g = genUart("$GPGGA,PWNSAT*2A\r\n", ex.bus); sig = { TX: g.tx }; ex.src = g.bytes; }
  else if (exId === "i2c") { const g = genI2C(ex.bus); sig = { SDA: g.sda, SCL: g.scl }; ex.src = g.bytes; }
  else { const g = genSPI([0x03, 0x00, 0x00, 0x00, 0, 0, 0], [0, 0, 0, 0, 0x50, 0x57, 0x4e], ex.bus); sig = { SCK: g.sck, MOSI: g.mosi, MISO: g.miso, CS: g.cs, _miso: [0, 0, 0, 0, 0x50, 0x57, 0x4e] }; ex.src = g.bytes; }
  // sample every connected lane
  const lanes = {}; let dur = 1;
  probes.forEach((pr, ch) => {
    if (pr.pin == null) return;
    const tr = pinTrace(ex.pins[pr.pin].t, sig);
    dur = Math.max(dur, tr.dur);
    lanes[ch] = { samp: sample(tr, rate), s: classify(sample(tr, rate), rate).s };
  });
  lastCap = { lanes, rate, dur };
  decode(sig, rate);
  renderRack(); renderScope();
}
function laneByRole(role) { // the sampled array for the channel assigned this role
  const ch = probes.findIndex(pr => pr.role === role && pr.pin != null);
  return ch >= 0 ? lastCap.lanes[ch] && lastCap.lanes[ch].samp : null;
}
function mapFeedback() {
  const lab = labels[tgtKey()] || {}, n = ex.pins.length;
  const tagged = ex.pins.filter((p, i) => lab[i]).length;
  const probed = probes.filter(pr => pr.pin != null).length;
  setConsole([["", T().mapProbed(probed)],
    tagged >= n ? ["ok", T().mapDone] : ["warn", T().mapTag(tagged, n)]]);
}
function decode(sig, rate) {
  let res = null; const con = $("hwconsole");
  const spb = rate / ex.bus;
  const log = [];
  if (exId === "map") return mapFeedback();
  // a dump needs a common ground reference
  if (gnd.pin == null) return setConsole([["warn", T().noGnd]]);
  if (ex.pins[gnd.pin].t !== "GND") return setConsole([["bad", T().gndWrong]]);
  if (exId === "uart") {
    const rx = laneByRole("RX"); if (!rx) return setConsole([["warn", T().needroles]]);
    res = decUART(rx, rate, ex.bus);
    log.push(["", T().decoded + " " + res.bytes.map(asc).join("")]);
  } else if (exId === "i2c") {
    const sda = laneByRole("SDA"), scl = laneByRole("SCL");
    if (!sda || !scl) return setConsole([["warn", T().needroles]]);
    res = decI2C(sda, scl, rate);
    log.push(["", T().decoded + " " + res.bytes.map(b => "0x" + hx(b)).join(" ")]);
  } else {
    const cs = laneByRole("CS"), sck = laneByRole("SCK"), mo = laneByRole("MOSI"), mi = laneByRole("MISO");
    if (!cs || !sck || !mo || !mi) return setConsole([["warn", T().needroles]]);
    res = decSPI(cs, sck, mo, mi, rate);
    log.push(["", T().decoded + " MOSI " + res.bytes.map(hx).join(" ")]);
  }
  lastCap.ann = res.ann;
  const okBytes = JSON.stringify(res.bytes) === JSON.stringify(ex.src);
  if (okBytes) log.push(["ok", T().success]);
  else if (spb < 3.5) log.push(["warn", T().under]);
  else log.push(["bad", T().failmap]);
  setConsole(log);
}
function setConsole(lines) {
  $("hwconsole").innerHTML = lines.map(([c, t]) => `<div class="${c}">${esc(t)}</div>`).join("");
}

// --- rendering: scope (SVG traces + annotations) ---
function renderScope() {
  const scope = $("scope"); if (!lastCap) { scope.innerHTML = ""; return; }
  const chs = probes.map((pr, ch) => ({ ch, pr })).filter(o => o.pr.pin != null);
  const gut = 150, W = Math.max(600, scope.clientWidth - 24), tw = W - gut - 10;
  const annH = 26, rowH = 42, H = annH + chs.length * rowH + 12;
  const xOf = t => gut + (t / lastCap.dur) * tw;
  let svg = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`;
  // annotations strip (on the primary decoded lane)
  (lastCap.ann || []).forEach(a => {
    const x0 = xOf(a.t0), x1 = Math.max(x0 + 14, xOf(a.t1));
    const col = a.kind === "bad" ? "var(--err)" : a.kind === "start" || a.kind === "stop" ? "var(--warn)" : "var(--accent)";
    if (a.kind === "start" || a.kind === "stop")
      svg += `<circle cx="${x0}" cy="${annH / 2}" r="5" fill="${col}"/><text x="${x0 + 8}" y="${annH / 2 + 4}" fill="${col}" font-size="10" font-family="monospace">${esc(a.text)}</text>`;
    else {
      svg += `<rect x="${x0}" y="4" width="${x1 - x0}" height="${annH - 8}" rx="3" fill="${col}" opacity="0.9"/>`;
      svg += `<text x="${(x0 + x1) / 2}" y="${annH / 2 + 4}" fill="#04232a" font-size="9.5" font-family="monospace" text-anchor="middle">${esc(a.text)}</text>`;
    }
  });
  // traces
  chs.forEach((o, r) => {
    const y = annH + r * rowH + 6, hi = y + 6, lo = y + rowH - 16, col = "#" + COLORS[o.ch];
    const role = o.pr.role || T().unused;
    svg += `<text x="6" y="${y + 16}" fill="${col}" font-size="11" font-family="monospace">D${o.ch} · pad ${o.pr.pin + 1}</text>`;
    svg += `<text x="6" y="${y + 29}" fill="var(--dim)" font-size="9.5" font-family="monospace">${esc(role)}</text>`;
    svg += tracePath(lastCap.lanes[o.ch].samp, gut, tw, hi, lo, col);
  });
  svg += `</svg>`;
  scope.innerHTML = svg;
}
function tracePath(a, x0, tw, hi, lo, col) {
  // draw from the sampled array compressed to pixel columns (shows aliasing if undersampled)
  const cols = Math.min(a.length, Math.floor(tw)); let d = "";
  let px = x0, py = a[0] ? hi : lo; d = `M ${px} ${py}`;
  for (let c = 1; c < cols; c++) {
    const idx = Math.floor(c / cols * a.length), x = x0 + c / cols * tw, ny = a[idx] ? hi : lo;
    if (ny !== py) d += ` L ${x.toFixed(1)} ${py} L ${x.toFixed(1)} ${ny}`;
    px = x; py = ny;
  }
  d += ` L ${x0 + tw} ${py}`;
  return `<path d="${d}" fill="none" stroke="${col}" stroke-width="1.6"/>`;
}

// --- exercise switch + init ---
function renderWiki() {
  const c = T().ch[exId];
  $("wiki").innerHTML = `<h2>${esc(c.t)}</h2><p class="goal">${esc(c.goal)}</p>
    <h3>${esc(T().w_bg)}</h3><p>${esc(c.bg)}</p>
    <h3>${esc(T().w_steps)}</h3><ol>${c.steps.map(s => `<li>${esc(s)}</li>`).join("")}</ol>
    <h3>${esc(T().w_why)}</h3><p>${esc(c.why)}</p>`;
}
function loadExercise(id) {
  exId = id; ex = EX[id]; resetProbes();
  $("obj").innerHTML = T().obj[id]; renderWiki();
  // SPI benefits from a faster default
  $("srate").value = id === "spi" ? "4000000" : "4000000";
  renderPins(); renderRack(); $("scope").innerHTML = ""; setConsole([["", T().pinhint]]);
}
function applyLang() {
  document.documentElement.lang = lang;
  $("hwtitle").textContent = T().title; $("targethdr").textContent = T().target; $("probehdr").textContent = T().probe;
  $("srlabel").textContent = T().srate; $("capbtn").textContent = T().cap; $("backbtn").textContent = T().back;
  $("pinhint").textContent = T().pinhint; $("lang").value = lang;
  $("wikitoggle").textContent = T().wikiBtn;
  loadExercise(exId);
}
function applyTheme(th) {
  document.documentElement.setAttribute("data-theme", th);
  try { localStorage.setItem("pwnsat_theme", th); } catch (e) {}
  $("themetoggle").textContent = th === "light" ? "☀" : "◐";
}
$("wikitoggle").onclick = () => $("wiki").classList.toggle("collapsed");
$("gndclip").onclick = () => { armed = armed === "gnd" ? -1 : "gnd"; renderPins(); renderRack(); };
$("exsel").onchange = e => loadExercise(e.target.value);
$("capbtn").onclick = capture;
$("srate").onchange = () => renderRack();
$("lang").onchange = e => { lang = e.target.value; try { localStorage.setItem("pwnsat_lang", lang); } catch (x) {} applyLang(); };
$("themetoggle").onclick = () => applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
window.addEventListener("resize", () => lastCap && renderScope());

// --- self-check: decoders must reproduce their source bytes ---
(function selfCheck() {
  const R = 16e6, ok = [];
  // long string at a modest rate (416 samples/bit) — exercises inter-byte resync
  const u = genUart("$GPGGA,PWNSAT*2A\r\n", 9600); ok.push(JSON.stringify(decUART(sample(u.tx, 4e6), 4e6, 9600).bytes) === JSON.stringify(u.bytes));
  const i = genI2C(100000); ok.push(JSON.stringify(decI2C(sample(i.sda, R), sample(i.scl, R), R).bytes) === JSON.stringify(i.bytes));
  const s = genSPI([0x03, 0xAB], [0, 0x50], 1e6); ok.push(JSON.stringify(decSPI(sample(s.cs, R), sample(s.sck, R), sample(s.mosi, R), sample(s.miso, R), R).bytes) === JSON.stringify(s.bytes));
  console.log("hardware self-check (uart,i2c,spi):", ok, ok.every(Boolean) ? "PASS" : "FAIL");
})();

applyTheme((() => { try { return localStorage.getItem("pwnsat_theme") || "dark"; } catch (e) { return "dark"; } })());
applyLang();
