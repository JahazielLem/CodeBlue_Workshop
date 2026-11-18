# Pwnsat Browser Lab

[English](README.md) · **日本語**

シミュレートされた CCSDS 衛星向けの、ブラウザベースでマルチ受講者対応の
サイバーセキュリティ訓練ラボです。各受講者は独立した衛星インスタンスを持ち、
Web UI（パケットアナライザ・ターミナル・衛星コンソール）から攻撃します。
再現可能な脆弱性演習が7つ（英語／日本語）。Python 3 標準ライブラリのみで動作します。

独立した1つの衛星セッションが、エンドツーエンドの全経路を実証します：

```
terminal command → real CCSDS SPP frame → SatelliteSim dispatch → TM reply
    → packet analyzer (CCSDS dissector + AES decrypt) → satellite console
```

実装済みの演習（Wiki パネルの演習セレクタで切り替え）：

- **V4 — フラッシュウィンドウのフラグ**：ハードコードされたアンロック定数が秘密の
  ブロブを漏洩させる。
- **V3 — 地上局認証バイパス**：期待される応答が `challenge XOR 0xC0DEFACE` のため、
  チャレンジ応答ゲートを偽造できる。
- **V2 — テレコマンド型混同**：ファームウェアは APID で振り分け、TM/TC の型ビットを
  検査しないため、テレメトリとして宣言されたコマンドも実行される。
- **V7 — ペイロード中継の悪用**：`BROADCAST_MSG` がペイロードモード外でも攻撃者の
  内容を中継する（警告のみ）。ベントパイプ中継器の乗っ取り。
- **V6 — AES 鍵辞書攻撃**：固定の AES-128 リンク鍵（`PWNsatLabKey1234`）を、捕捉した
  暗号文とラボのワードリストから復元する。
- **V5 — 保守用デバッグバックドア**：`DEBUG_CONFIG` がリンク暗号化を無効化し（さらに
  地上局モードを認証なしで無効化できる）。
- **V1 — SPP パーサのオーバーリード**：**実際の** `firmware/spp.cpp` を隔離された
  サブプロセスで実行。宣言長の大きい短いパケットが隣接メモリを漏洩させる。

さらに `/hardware.html` の**ハードウェアラボ** — ロジックアナライザのシミュレータで、
基板のラベルなしパッドを探って各信号を特定し、グランドクリップを接続し、サンプル
レートを設定して、**I2C・SPI・UART** を実際の波形生成とデコードでダンプします。

## リポジトリ構成

```
lab/        プラットフォーム（サーバ・シミュレータ・Web UI・テスト）
tools/      pwnsat_protocol.py — ラボが再利用する CCSDS SPP + AES-128 のコア
firmware/   spp.cpp / spp.h — 演習 V1 のためにコンパイルする実パーサ
keys.txt    演習 V6 の AES-128 候補ワードリスト
```

`tools/pwnsat_protocol.py` と `firmware/spp.*` は、元の Pwnsat ワークショップ
（作者 astrobyte、GPL-2.0-or-later — NOTICE を参照）からベンダリングした唯一の
ファイルです。ワークショップの書籍・キャプチャ・ツール一式は意図的に含めていません。

## 実行

依存関係なし — Python 3 標準ライブラリのみ。

```bash
python3 lab/server.py --host 0.0.0.0 --port 8080
```

各受講者のブラウザで `http://<instructor-ip>:8080/` を開きます。各ブラウザは独自の
セッション ID（`localStorage` に保存）を取得し、衛星の状態はセッションごとに保持され、
共有されません。ローカル限定にするには `127.0.0.1` にバインドしてください。意図的に
脆弱なため、**公開インターネットには公開しないでください**。

## 演習を試す

ターミナルで（または Wiki パネルのコマンドをクリックして）実行します。

**V4 — フラッシュウィンドウのフラグ：**

```
debug on
flash-read 0xA5 83 32 0xC35A
```

返ってきた `APID 0x0B` パケットを選択し、**Data Field → Payload** を展開すると、
ディセクタが `FLAG` フィールドを表示します。ファームウェアは1回の読み取りを32バイトに
制限するため、残りはオフセット 115 で再度読みます（`flash-read 0xA5 115 32 0xC35A`）。
セキュアリンクを ON のままにするとダウンリンクは回線上で AES 暗号化されますが、
アナライザは既知のラボ鍵（`PWNsatLabKey1234`）で復号します。誤ったアンロックでは
`FLASH WINDOW LOCKED` が返ります。

**V3 — 地上局認証バイパス：**

```
gs-mode on
ping                      # ブロックされる: GS AUTH REQUIRED
gs-access challenge       # 応答／コンソールで漏洩したチャレンジを読む
xor <challenge> 0xC0DEFACE
gs-access respond <result>
ping                      # PING ACK が返る
```

チャレンジは60秒で失効します（ファームウェア忠実）。速やかに偽造して応答してください。

**V2 — 型混同：**

```
mode 1                    # 基準 NOMINAL
send-tm 0x0D 02           # テレメトリ（Type=0）として宣言した MISSION_MODE コマンド
```

それでもモードは PAYLOAD に変わります。アップリンクパケットを選択すると、Packet Type は
`0 (TM) ⚠ type confusion` と表示されますが、実行されています。ディセクタは方向で解釈するため、
型ビットが偽っていてもアップリンクはコマンドとして表示されます。

**V7 — ペイロード中継の悪用：**

```
mode 1                            # ペイロードモードではない
broadcast 0x1A2B 486920536174     # 任意の周波数で "Hi Sat" を中継
payload-status                    # 転送カウンタ + 記録された周波数
```

衛星はメッセージを TM 0x06 として再送信し（選択 → `Relayed message`）、
`Payload relay used outside payload mode` と記録するだけで、拒否しません。

**V6 — AES 鍵辞書攻撃：**

```
brute-force     # セッション自身が捕捉した暗号化テレメトリを攻撃する
```

暗号化された STATUS パケットが捕捉されるようセキュアリンクを ON のままにして実行します。
攻撃は `keys.txt` の各鍵を試し、`PWNsatLabKey1234` を復元します。

**V5 — デバッグバックドア：**

```
debug on        # STATUS テレメトリが平文になる（Security Flag 0x00）
debug off       # 暗号化が戻る
```

セキュアリンクが ON のとき STATUS パケットは Security Flag 0x01 を持ちますが、`debug on`
の後は 0x00 に落ちます（23バイトから15バイトに縮小）— 鍵は不要です。さらにデバッグは、
認証済みセッションなしでも `gs-mode off` を成功させます。

**V1 — SPP パーサのオーバーリード（実ファームウェアを実行）：**

```
overread 64     # 8バイトのパケット、宣言長は64
```

堅牢化された `spp_parser.py` はこれを拒否します（長さ不一致）。一方、実際の
`spp_unpack_packet` は8バイトのバッファから65バイトをコピーし、仕込まれた秘密
`PWNSAT{spp_overread_leaks_adjacent_memory}` を漏洩させます。**V1 には C++ コンパイラ**
（`clang++` または `g++`）が必要です。サーバは初回使用時に `lab/v1/spp_harness` を
ビルドし、隔離されたサブプロセスで実行します。他の6つの演習にコンパイラは不要です。

## テスト

```bash
python3 lab/test_slice.py      # 17 checks: V4 chain, AES path, isolation, dissector
```

## ファイル

| ファイル | 役割 |
|---|---|
| `satellite_sim.py` | `firmware/worker.cpp` のディスパッチの挙動移植 + CCSDS ディセクタ。SPP/AES コアとして `tools/pwnsat_protocol.py` を再利用 |
| `terminal.py` | 制限付き `pwnsat>` コマンドシェル（互換レイヤー、ホストへのアクセスなし） |
| `server.py` | 標準ライブラリの HTTP + 自前実装の WebSocket。セッションごとに1つの `SatelliteSim` |
| `static/` | SPA：3ペインのパケットアナライザ・ターミナル・衛星コンソール・Wiki・英日 i18n |
| `test_slice.py` | ヘッドレス自己テスト |

## ブランディング・テーマ・教官コンソール

- GSpace パレット（`paleta/GSPACE-colores.json`）：ほぼ黒 `#0A0A0A`、シアンのアクセント
  `#00E5FF`。GSpace ロゴ（`static/gspace-logo.png`）が「PWNSAT LAB」の隣に表示されます。
- ダーク／ライトのテーマ切替（上部バーの ◐）。ブラウザごとに保持され、教官ページと共有されます。
- **教官コンソール** は `/instructor.html`、パスワードで保護。サーバがパスワードを
  （定数時間比較で）検証し、短命のトークンを発行します。各操作にはトークンが必要です。
  アクティブなセッション、セッションごとの健全性・モード・フラグ・カウント、サーバの
  RSS と稼働時間（3秒ごとに自動更新）、セッションごとの **Reset**／**Delete**、および
  **Reset all** を表示します。パスワードは `INSTRUCTOR_PASSWORD` 環境変数で設定します
  （既定値は `changeme` — 変更してください）。信頼できる LAN でのみ実行し、公開
  インターネットでは実行しないでください。

```bash
INSTRUCTOR_PASSWORD='your-pass' python3 lab/server.py --host 0.0.0.0 --port 8080
```

## 測定したキャパシティ（推定ではなく実測）

`python3 lab/loadtest.py` で測定。N 個の独立した WebSocket セッションを開き、各セッションが
**一意の**ミッションモードを設定して読み戻し（混信があれば検出される）、フラッシュのフラグを
復元する一方で、サーバプロセスのピーク RSS と CPU をサンプリングします。ホスト：
Apple M4（10 コア）、macOS 26.6、Python 3.10.21。

セキュアリンク **ON** が現実的な既定です（すべてのテレメトリパケットで純 Python の
AES を実行）。デバッグ／平文の行が下限です。

| 受講者数 | RSS（secure ON） | サーバ CPU（secure ON） | RSS（平文） | CPU（平文） |
|---|---|---|---|---|
| idle | 24.6 MB | — | 24.6 MB | — |
| 10 | 26.2 MB | 0.8 % | 25.5 MB | 0.3 % |
| 20 | 26.5 MB | 1.5 % | 26.1 MB | 0.6 % |
| 30 | 27.0 MB | 2.3 % | 26.8 MB | 0.7 % |
| 50 | 29.3 MB | 3.6 % | 27.9 MB | 1.3 % |
| 100 | 31.1 MB | 7.0 % | 30.8 MB | 2.4 % |

すべての行は直接の実測値です。どの実行でも N 個すべてのセッションが自分のフラグを復元し、
**分離の失敗はゼロ**でした。RSS はセッションあたり約 60 KB、CPU はセッションあたり約
0.07 %（secure）増加します。受講者30人でも30 MB 未満とコア数パーセントに収まり、どんな
ノート PC でも扱えます。実際の限界は CPU やメモリではなく OS のファイルディスクリプタ／
スレッド数で、30 をはるかに超えます。ストレージはごくわずか：セッションはメモリ上のみで、
ラボ全体（コード + 静的アセット + コンパイル済み V1 ハーネス）は約 250 KB です。

## ポートと範囲

- TCP ポートは1つ（既定 8080）。HTTP と WebSocket は同じポートで動作します。
- 分離モデル：セッション ID ごとに1つの `SatelliteSim` オブジェクト。衛星の状態は共有
  されず、ターミナルは自分のシミュレータに SPP パケットを送るだけ（シェルなし、`/dev` なし）。

## 制限事項（正直に）

- カタログ化された7つの脆弱性（V1〜V7）はすべて実装済み。V2〜V7 は `SatelliteSim` の
  挙動移植に対して動作し、V1 は実際にコンパイルした `firmware/spp.cpp` を実行します。
- これらの演習が使う APID（PING, VERSION, STATUS, MISSION_MODE, AES/DEBUG config,
  FLASH_READ, BROADCAST_MSG, PAYLOAD_STATUS, GS_MODE/ACCESS/STATUS）と、定期的な
  STATUS/idle テレメトリを実装しています。演習外の APID（SET_THRUSTER, SET_BEACON_RATE,
  ファームウェアイメージの FLASH ストリーム）はまだ扱っていません。
- `SatelliteSim` は**挙動**移植です：バイトは実際のプロトコルモジュールが生成し（回線
  フォーマットの忠実度は厳密）、ミッションロジックは再現されたもので、元のマシンコード
  ではありません。未改変のファームウェア C を実行するのは V1 のみです。GPS は「使用可能
  かつ範囲内」に抽象化し、V3 を認証偽造に集中させています。完全なジオフェンス／GPS
  スプーフィングの領域は後の演習です。
- V6 の辞書攻撃は、付属の `material/tm_capture_encrypted.pcapng` ではなくセッション自身が
  捕捉した暗号文に対して動作しますが、同じ鍵を復元します。
- サーバは標準ライブラリのスレッド方式（ゼロインストール／オフライン向けに選択）で、
  セッションごとに1スレッドです。100 同時セッションまで負荷試験済み（**測定したキャパ
  シティ**を参照）。受講者10〜30人で約 27 MB とコア数パーセントを使い、負荷時にも分離を
  検証済みです。約 100 を超えると限界は OS のスレッド／fd 数になり、そこでは asyncio
  （FastAPI+websockets）への書き換えでさらにスケールします。
