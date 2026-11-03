# go2rtc fork for CAM720 (JA-A12) over DTLS

Local patch set against upstream [AlexxIT/go2rtc](https://github.com/AlexxIT/go2rtc)
v1.9.15 (`7c05066`). What this does and why is written up in
[../docs/CAM720.md](../docs/CAM720.md). The TL;DR:

- Adds `pkg/cam720/` (client + producer) and `internal/cam720/` (scheme
  registration) so go2rtc understands
  `cam720://<ip>/<uid>?token=<device_pwd>`.
- Simplifies `pkg/tutk/dtls/auth.go`'s PSK derivation to plain SHA256
  (CAM720 does not truncate at the first NULL byte like Wyze does).
- Pins the DTLS cipher to `TLS_PSK_WITH_AES_128_CBC_SHA256` in
  `pkg/tutk/dtls/dtls.go`, which is the only suite CAM720 advertises.
- Fixes `(*DTLSConn).WriteIOCtrl` in `pkg/tutk/dtls/conn_dtls.go` so it
  writes through the DTLS tunnel instead of the raw UDPConn (the raw path
  needs a dialed socket, which the discovery flow does not give it).
- Adds `(*DTLSConn).WriteIOCtrlStd(ctrlType, body)` for the standard
  Session16 IOCTRL framing CAM720 expects.
- Registers `cam720` beside `wyze` in `main.go`.

## Current state

- DTLS session comes up, `AV LOGIN SUCCESS, two-way: true`.
- `WriteIOCtrlStd(0x1FF, …)` reaches the camera (ACKs seen). The camera
  does not push video frames in response — the exact pattern the Jooan
  firmware wants (resolution/quality/support-stream pre-queries, or a
  vendor IOCtrl like 66338 `GetStreamCtrl`, or a parameter inside
  `SMsgAVIoctrlAVStream` beyond `(channel=0, option=0)`) is still open.
- Backchannel audio is scaffolded (`StartIntercom` sends 0x350 then
  `AVServStart`) but CAM720 does not use the Wyze reverse-DTLS pattern,
  so the right port is to swap `AVSendAudioData` for a Session16-style
  frame on the main channel.

## Rebuild

```sh
cd ~/Downloads/cam720-apk/go2rtc-src/AlexxIT-go2rtc-7c05066
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" .
```

## Files

```
pkg_cam720_client.go     -> pkg/cam720/client.go
pkg_cam720_producer.go   -> pkg/cam720/producer.go
internal_cam720_cam720.go -> internal/cam720/cam720.go
pkg_tutk_dtls_auth.go    -> pkg/tutk/dtls/auth.go (modified)
pkg_tutk_dtls_dtls.go    -> pkg/tutk/dtls/dtls.go (modified)
pkg_tutk_dtls_conn_dtls.go -> pkg/tutk/dtls/conn_dtls.go (modified)
main.go                   -> main.go (modified: adds cam720 Init)
```

## cmd/mitm — DTLS man-in-the-middle for CAM720

`cmd/mitm/main.go` (shipped here as `cmd_mitm_main.go`) wraps the local build
as a DTLS proxy for reversing the Jooan phone/desktop app's AV protocol.
Deployment lives in [`deploy/cam720-dtls-mitm.sh`](../deploy/cam720-dtls-mitm.sh)
on the Hub: it brings up a dedicated Wi-Fi (`Athan-capture`), redirects UDP
32761 from that subnet to a local DTLS proxy on `10.77.0.1:33000`, and the
proxy terminates with the PSK derived from `device_pwd` on both sides.

Point the phone at Athan-capture, open the camera in CAM720, and the proxy
logs the plaintext of every TUTK AV packet in both directions
(`journalctl -u dtls-mitm`). That's the trace the next session needs to pin
down the exact IPCAM_START payload CAM720 wants.

## Trace discoveries

In session 2026-11-03 we captured the real CAM720 phone-app ↔ camera traffic
on the Hub's isolated Wi-Fi (`Athan-capture`). Both `live.pcap` captures
(not committed; they live in `~/scratchpad/`) confirmed the real protocol:

- **The transport is `TUTK Session16 scramble + DTLS inside`**. The outer
  envelope is 28 bytes starting with `04 02 1d 0b | body-size | seq |
  07 04 21 00 | sid16`, with the first 16 bytes Kalay-scrambled, and the
  DTLS 1.2 record follows at offset 28. Upstream go2rtc's `msgTxData`
  hardcodes version `0x1a` (Wyze) — patched to `0x1d` for CAM720.
- **The handshake uses `TLS_PSK_WITH_AES_128_CBC_SHA256` with EMS**.
  Identity is `AUTHPWD_admin`, PSK is `SHA256(device_pwd)`. Confirmed in
  the ServerHello extensions (`0x0017`).
- **Live-view AV data is sent as DTLS application records (type 23) at
  epoch 1**, 624-byte records (16-byte IV + 608-byte ciphertext).
- `traces/decrypt_cam.py` and `traces/decrypt_ems.py` are the local Python
  decoders that read a `.pcap`, run every UDP payload back through
  `tutk.ReverseTransCode`, extract DTLS records, derive the master
  secret from the known PSK plus the recorded handshake randoms, and
  attempt to decrypt the AV frames. They currently extract correct
  handshake bytes but the EMS-derived keys do not open the application
  records — the PRF implementation needs a cross-check against pion/dtls
  before plaintext can be read. That's the one remaining blocker.

## Session-decryption cross-check

The PRF implementations in `traces/decrypt_cam.py` and
`traces/decrypt_ems.py` were verified against pion/dtls using the Go tool
`cmd_prf_main.go`. For identical inputs
(client_random, server_random, session_hash, PSK=SHA256(device_pwd)),
Python and pion produce identical master secrets and key material. Yet
decrypting the first client-sent app-data record (the Finished at epoch 1
seq 0) with the derived `cek` yields a padding byte of 191/214/239 — clearly
garbage — regardless of whether EMS or standard master-secret derivation is
used. That means **the handshake extraction is correct and the PRF is
correct, but either**:

- the PSK the camera actually uses for AV sessions is _not_
  `SHA256(device_pwd)` (even though our own go2rtc client's PSK callback
  with that value makes pion/dtls succeed the handshake — pion verifies
  Server Finished, so this would be surprising); or
- the handshake extraction is still missing a message (we parsed CH, SH,
  SHD, CKE; a ServerKeyExchange, if present, would change the session
  hash and the master secret).

`cmd_decrypt_main.go` is a plain Go CBC-SHA256 decoder for feeding one
record and seeing exactly what AES produces, independent of pion.
`cmd_decode_main.go` runs the raw Kalay Transcode on captured UDP
payloads so each packet's TUTK envelope and inner DTLS record can be
inspected.

### PSK verification confirmed; decryption anomaly remains

The camera *does* verify the PSK during handshake: running the local
`camtest` with `CAM_PASS=wrong_token` produces
`handshake error: alert: Alert Fatal: BadRecordMac`, while the real token
produces `AV LOGIN OK two-way: true`. So the authenticated PSK is
`SHA256(device_pwd)`, and the camtest handshake success is real, not a
firmware accept-any-PSK bug.

Yet the application records in the captured phone↔camera session (`live2.pcap`,
not committed) still won't decrypt with the derived `cek`, even after
exhaustive sweep of EMS/non-EMS, both key-expansion seed orders, and every
16-byte slot of the derived key material. The 2 "hits" with pad<16 both
produced plaintext that does not begin with handshake type `0x14`
(Finished) — classic false positives from random pad bytes.

The remaining theories, to pursue next session:

1. The CBC-SHA256 cipher the firmware implements as `0x00ae` is not the
   RFC-standard TLS_PSK_WITH_AES_128_CBC_SHA256 — some vendors reuse the
   codepoint for a slightly different KDF/MAC layout. A side-by-side with
   OpenSSL's `s_client -debug -msg` on a known PSK handshake would reveal
   this immediately.
2. The TUTK-wrapped DTLS might apply an extra scramble pass only on the
   DTLS record body (not the first 16 outer bytes), so our 29-byte offset
   for the IV might be off. We only verified Transcode on the outer 16;
   a fresh look at `ReverseTransCodeBlob` versus `ReverseTransCodePartial`
   semantics would be worth 10 minutes.

### Partial transcode confirmed; cipher mystery remains

Verified today that `ReverseTransCodeBlob` applies partial encryption:
when `decoded[3] & 1 != 0` (which is our case — stage byte `0x0b`), only
the first 16 bytes plus bytes 16–63 get transcoded, and bytes 64+ pass
through untouched. For the client Finished record at packet offset 82 the
IV lives at offset 95 (well past the transcoded zone), so our raw and
decoded IV bytes are identical. Decryption still fails.

Exhaustive search across every 16-byte window of key material from both
EMS and standard master-secret derivations and both key-expansion seed
orders found **zero** combinations whose plaintext starts with the
expected Finished prefix `14 00 00 0c`. That rules out IV/key alignment
bugs. The outstanding hypothesis — that `0x00ae` in this firmware uses
a nonstandard KDF or MAC placement despite its RFC name — needs an
OpenSSL `s_server`-vs-firmware comparison to settle definitively.

### Hypothesis sweep exhausted

Confirmed in a follow-on pass:

- Camera accepts handshakes with EMS **enabled** AND **disabled** —
  running local `camtest` with `ExtendedMasterSecret: DisableExtendedMasterSecret`
  still prints `AV LOGIN OK two-way: true`. Pion either way derives distinct
  session keys; firmware tolerates both silently.
- Both the RFC-standard `TLS_PSK_WITH_AES_128_CBC_SHA256` layout (CMK 32 +
  SMK 32 + CEK 16 + SEK 16) and a plausible SHA-1-MAC fallback layout
  (CMK 20 + SMK 20 + CEK 16 + SEK 16) were tried against the captured
  Finished record. No key-slot offset produces the expected plaintext
  prefix `14 00 00 0c`.

What's left is either:

- An OpenSSL `s_server -psk <device_pwd-SHA256-hex>` against the firmware
  using the same ClientHello, with `-trace` on both sides, to spot the
  exact divergence; or
- Reading the firmware's DTLS implementation. The TUTK libraries that
  Jadx shows are the Android apk's view — the camera-side binary is in
  the vendor's own firmware blob; or
- Reading `cmd/mitm` output live. The DTLS proxy terminates on both
  sides, so once the phone handshakes through it there is no decryption
  to do — pion already has the plaintext. Point a phone at the
  `Athan-capture` SSID, open the CAM720 app, hit Live, and tail
  `journalctl -u dtls-mitm` for the exact IPCAM_START IOCtrl payload.

### Talk-back path requires TUTK multi-channel (open blocker)

Read in w.java (Android `ThreadSendAudio`):

```java
int freeChannel = IOTCAPIs.IOTC_Session_Get_Free_Channel(sid);
TK_sendIOCtrlToChannel(mainCh, 848, SMsgAVIoctrlAVStream.parseContent(freeChannel, 0));
st_AVServStartInConfig cfg = new ...; cfg.iotc_session_id = sid; cfg.iotc_channel_id = freeChannel; cfg.security_mode = 2;
cfg.password_auth = Y; cfg.token_auth = FI8ekqA; cfg.change_password_request = zx; ...
int audioAvIndex = AVAPIs.avServStartEx(cfg, ...);
AVAPIs.avSendAudioData(audioAvIndex, pcm, len(pcm), AVFrame.parseFrameInfo(codec, flags, 0, 0, ts), 16);
```

Confirmed in live tests (`cmd/avdrive`):

- IOCtrl 848 (SPEAKERSTART) is ACKed by the camera with vendor IOCtrl `0x40` (payload `00 01 00 00` initially; after N frames arrive the first byte advances, e.g. `6e 01 00 00` = 0x16E = 366). The camera is *counting* received frames but not routing them to the speaker.
- Blind frame sends via the single DTLS tunnel never play audibly — tried: SPEEX (141) 38-byte frames, G.711 μ-law (137) 160-byte frames, frameInfo as Session16 trailer and as prefix, server-channel = 0 and = 1, 10s and 60s bursts at max amplitude.
- The real app opens a *second* IOTC data channel inside the TUTK session, re-authenticates with password/token callbacks, and sends audio on that new channel's avIndex. Our pion DTLS layer gives us one data channel; TUTK's own session multiplexing inside the DTLS tunnel needs to be ported from `IOTCAPIs.IOTC_Session_Get_Free_Channel` + the native `avServStartEx` flow before `avSendAudioData` has any effect.

### Android app IOCtrl sequence (from Jadx)

Verified by reading `com/jooan/androidmysdk/live/bean/MYCameraBase.java`
and `com/tutk/IOTC/v.java` in the decompiled APK:

- Start video (per channel):
  `TK_sendIOCtrlToChannel(ch, 511, SMsgAVIoctrlAVStream(ch, 0))` — the
  payload is 8 bytes: 4 little-endian channel + 1 option byte + 3 zeros.
  Matches what the fork sends. The guard `!isVideoOnConnect() && f`
  means the app skips the IOCtrl if the camera auto-pushes frames on
  connect.
- Likely pre-queries the app also issues (not strictly required but
  seen in the main init sequence):
  `66338 GetStreamCtrlReq(channel)`, `810` (opaque 8-byte zero), then
  `511`.
- Start speaker (talk-back): `848 IPCAM_SPEAKERSTART`, then
  `AVSendAudioData` on the main AV channel (not Wyze's reverse-DTLS
  pattern).

So the app's start code is confirmed as 511; our 511 payload is byte-identical.
The remaining difference between fork and app must be at the TUTK envelope
layer (framing) or the DTLS cipher — not the IOCtrl number or payload.

### Note on pion state reflection

`(*Conn).ConnectionState()` returns a *clone* produced by
`State.serialize()` + `State.deserialize()`. The serialized form does
**not** carry `preMasterSecret` or `extendedMasterSecret`, so reflecting
those fields on the clone always reads zero. For verifying which
master-secret derivation pion actually ran, add explicit prints inside
`flight5handler.go` or use `cfg.writeKeyLog` — do not trust clone
reflection.

Both are bench work, not reach-further-tonight work. The protocol RE is
otherwise complete: DTLS inside Session16-scramble, version `0x1d`,
IPCAM_START IOCTRL at 511 with `SMsgAVIoctrlAVStream` body (channel 0,
option 0), speaker open at IOCTRL 848 before `AVSendAudioData` on main
channel, every piece documented at the byte level in `docs/CAM720.md`
and this file.
