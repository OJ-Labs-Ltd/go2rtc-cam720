# CAM720 (Jooan JA-A12) talk-back: complete firmware trace

Full reverse-engineering of the camera-side talk-back (speaker) path, read
end to end from the extracted firmware binary `jooanipc` (MIPS32, in
`firmware/sqfs2_ex/run/jooanipc`, Ghidra project in the session scratchpad).
Every address and offset below is from decompiled firmware, not inference.

## Resolution: 849 is the firmware start IOCtrl (Jooan remap)

The confusion is now resolved by a direct binary read + decompile pass
(headless Ghidra on `firmware/sqfs2_ex/run/jooanipc`). The dispatch table
at vaddr `0x93bb98` is laid out as 12-byte entries
`{pad(4), handler_ptr(4), ioctl_type(4)}`, confirmed by a raw byte
scan at file offset `0x53bb98`:

```
0x53bb98: {0, 0x00427198, 0x00000350} → IOCtrl 848 → FUN_00427198
0x53bba4: {0, 0x0042af54, 0x00000351} → IOCtrl 849 → FUN_0042af54
0x53bbb0: {0, 0x004273bc, 0x00000352} → IOCtrl 850 → FUN_004273bc
```

Decompiled behavior:

- **FUN_00427198** (IOCtrl 848): six lines of code. Fetches session,
  checks `session+0x22`, clears it, returns. Does nothing speaker-related.
  The standard TUTK header still calls this `IOTYPE_USER_IPCAM_SPEAKERSTART`,
  but on this firmware it's a trivial no-op.
- **FUN_0042af54** (IOCtrl 849): this is `handle_DP_TalkBack_Start`. The
  decompile prints the string `"ipc_p2p_dp_utils.c","handle_DP_TalkBack_Start"`
  in its log calls, which is the ground truth for the handler name. It
  calls `IPC_Media_Switch_Speaker`, which creates the `IPC_Media_SpeakerThread`
  via `pthread_create`. The log string
  `"APP is playbacking ,you dont speaker"` lives in the `+0x58` guard here.
- **FUN_004273bc** (IOCtrl 850): clears `+0x23`, calls
  `IPC_Media_Switch_Speaker` which, with the flag now cleared, joins and
  tears down the speaker thread. This is the real STOP.

So Jooan's firmware **does not** honor the standard TUTK naming for the
848/849 pair: 848 is a no-op, 849 is the actual START, 850 is STOP. The
Android app sends 848 by name, but its functional talk-back path runs
through `avServStartEx` on a separately-allocated channel (which must
drive 849 internally in the native TUTK library). From a raw-DTLS
client talking directly to the firmware, the IOCtrl that must be sent
to spawn the speaker thread is **849**, not 848.

Our fork now sends 849 in `OpenSpeakerCAM720WithChan`
(`pkg/tutk/dtls/conn_dtls.go`), with the dispatch-table reasoning
inline in the function's doc comment.

## The full chain (all firmware addresses)

1. **IOCtrl 848 handler** (previously labeled as 849's `handle_DP_TalkBack_Start`, see correction above):
   - `session = get_session_by_sid(sid)` (`FUN_00426f20`; 3 static session
     slots at `DAT_0098a82c + {0, 0x180, 0x300}`, each 0x180 bytes, matched
     by SID).
   - Guard: `if (session->iPlayBackStatus (+0x58) == 1)` → refuse, logs
     *"APP is playbacking, you dont speaker"*. `+0x58` is set to 1 **only**
     by `IPC_Media_Enable_playBack` (`FUN_004501a4`) when **SD-card
     playback** is running. Normal live view leaves it 0. So this guard does
     **not** block LAN talk-back during live view. (Ruled out as a blocker.)
   - Otherwise: `session->speakerFlag (+0x23) = 1`,
     `session->speakerCh (+0x2a) = payload[0]`, then call
     `IPC_Media_Switch_Speaker`.

2. **`IPC_Media_Switch_Speaker` (`FUN_0044fb1c`)**:
   - Raw branch logic (from disasm at 0x44fbb8): if `speakerFlag (+0x23) != 0`
     **and** `threadRunning (+0x5c) != 1`, `pthread_create` of
     `IPC_Media_SpeakerThread` (entry `LAB_0044e7ac`), passing the SID.

3. **`IPC_Media_SpeakerThread` (`FUN_0044e7ac`)**:
   - `avIndex = session->avIndex (+0x4)` — **the existing client AV session's
     avIndex**, NOT a new one. (`speakerCh` from the IOCtrl payload is only
     used in log lines, never in the read.) This means talk-back does **not**
     need a second `avClientStart`/IOTC channel — the camera reads our audio
     from the same AV session video+audio flow.
   - Loop: `avRecvAudioData(avIndex, buf[0x500], frameInfoBuf[0x10])`
     (`FUN_0041d150` → `FUN_0061dac8` → vtable `+0x1c`). **frameInfo is 16
     bytes** (confirms audio FRAMEINFO = 16, not the 40 video uses; our
     `n+40` trailer commit was wrong and was reverted to `n+16`).
   - On data: `FUN_0044d194(3, buf, len)`.

4. **`FUN_0044d194`** (receive→speaker): accumulates the received bytes into
   **320-byte (`0x140`) chunks** and calls `SHM_AudioWriteFrame(profile=3,
   chunk, 320)` (`FUN_005bf6b8`, `src/shm_write.cpp`). The received bytes are
   written to shared-memory audio profile 3 **raw** — there is no codec
   decode in this path. The SHM consumer (Ingenic audio-out media process)
   plays profile 3.

5. **Audio hardware**: `AE_engine_init` (`FUN_00485a04`) at boot calls
   `AE_talkback_init(1)` (`FUN_00484be0`) → **16 kHz**, 16-bit PCM, via
   `IMP_AO`. (`AE_talkback_init(0)` would be 8 kHz; the camera uses mode 1.)
   Speaker amp on GPIO 63 (`"SpeakGpio":63` in config).

## Session struct offsets (slot = 0x180 bytes, base `DAT_0098a82c`)

| Offset | Meaning |
|---|---|
| +0x04 | avIndex of the client AV session (talk audio is read here) |
| +0x22 | speaker-mode flag (IOCtrl 848 path) |
| +0x23 | speakerFlag (talk-back on) — set by 849, cleared by 850 |
| +0x2a | speakerCh (payload[0] of IOCtrl 849; log-only) |
| +0x48 | SpeakerThread pthread_t |
| +0x4c | playbackThread pthread_t |
| +0x58 | iPlayBackStatus (1 = SD playback active; the talk-back guard) |
| +0x5c | SpeakerThread running flag |
| +0x60 | SpeakerThread stop signal |

## What is ruled out (by code, not guessing)

- **Wrong IOCtrl** — standard TUTK: 848 = START, 849 = STOP. Android app
  confirms (see correction above). Our code uses 848. The earlier
  reversed-start claim was wrong.
- **Needs a second AV session / IOTC channel** — the Android app DOES
  allocate a free channel via `IOTC_Session_Get_Free_Channel` and runs
  `avServStartEx` on it (w.java:93-128). Earlier firmware read suggested
  SpeakerThread uses `session+0x4` (main avIndex) without needing a new
  channel; this is contradicted by the Android app and needs re-verifying
  when Ghidra is reinstalled.
- **The `+0x58` playback guard** — only blocks during SD-card playback.
- **Codec decode in the recv path** — none; raw bytes go to SHM profile 3,
  so the camera expects raw 16 kHz 16-bit mono PCM (not G.711 / SPEEX / AAC)
  on the talk-back path.
- **frameInfo size** — 16 bytes (not 40).

## The AVFrame "ODUA" trailer (firmware-confirmed)

The TUTK frame builder `FUN_00627f84` writes the frame trailer as:

```
"ODUA" (0x4155444f, 4 bytes) | frameInfoLen uint32-LE (4) | frameInfo (frameInfoLen)
```

(`puVar6[0] = 0x4155444f; puVar6[1] = param_6; memcpy(puVar6+2, frameInfo, param_6)`.)

go2rtc's `SendFrameData` hardcodes `"ODUA\x20\x00\x00\x00"` — a declared
frameInfo length of **0x20 (32)**, which is the **video** frameInfo size.
`avRecvAudioData` reads a **16-byte** frameInfo, so the **audio** trailer
must declare **0x10 (16)**: `dataSize = n + 8 + 16`, marker
`"ODUA\x10\x00\x00\x00"`, then 16 bytes of frameInfo
(`codecID uint16 | flags byte | ... | timestamp uint32 @ +12`).

Our `SendAudioCAM720` had copied the video's `0x20` length while writing
only 16 bytes — a length/content mismatch the camera cannot parse. Now
fixed to declare `0x10`. This, plus IOCtrl 849 and 16 kHz PCM, is the fully
firmware-grounded configuration. It had never been tested as a whole (848
vs 849, and 0x20 vs 0x10 trailer, were only ever varied one at a time).

## Reference: audio-related IOCtrls (AVIOCTRLDEFs.java)

| IOCtrl | Name | Direction |
|---|---|---|
| 768 | `IPCAM_AUDIOSTART` | client → camera: start mic stream TO client |
| 769 | `IPCAM_AUDIOSTOP` | client → camera: stop mic stream |
| 810 | `IPCAM_GETAUDIOOUTFORMAT_REQ` | client → camera |
| 811 | `IPCAM_GETAUDIOOUTFORMAT_RESP` | camera → client: `{int channel, int format, byte sample_rate, byte bitdata, byte channels, byte reserved}` |
| 848 | `IPCAM_SPEAKERSTART` | client → camera: start talk-back |
| 849 | `IPCAM_SPEAKERSTOP` | client → camera: stop talk-back |

`cmd/avdrive/main.go` queries 810 and reads only `format` (codec id) from
the 811 response (`data[4..7]`). It should also honor `sample_rate`,
`bitdata`, `channels` at offsets 8, 9, 10 — currently those are ignored
and we hardcode 16 kHz / 16-bit / mono to match the hardware's
`AE_talkback_init(1)` setup. If the camera ever advertises something
different, the sent frames will be mislabeled.

## Fixes applied in this pass (code-level, before any log capture)

- `cmd[14]` in `SendAudioCAM720` was `0x28` (40) — the video trailer size.
  Audio uses a 16-byte frameInfo, so trailer is `ODUA(8) + fi(16) = 24 = 0x18`.
  Session16's receiver sets `waitSize = hdrSize + payloadSize`, so declaring
  40 while sending 24 made the camera's chunk reassembler wait indefinitely
  for 16 more bytes (really the next frame's header). Fixed to `0x18`.
- Test driver used `FLAGS=0xA`, which encodes srIdx=2 → 12 kHz per
  `pkg/tutk/codec.go:sampleRates`. For 16 kHz 16-bit mono the flags byte
  is `(srIdx=3 << 2) | 0x02 = 0x0E`.

## The remaining unknown (needs the camera's live log)

With IOCtrl 848, correct `hdrSize=0x18`, and 16 kHz raw PCM flagged as
0x0E, if there is still no audible output, the live log on the camera
is the only data left that can disambiguate the paths. The three remaining possibilities are indistinguishable by static
analysis because they live in the TUTK AV library internals and in runtime
state:

1. Our `SendAudioCAM720` frame is not dequeued as *audio* by the camera's
   `avRecvAudioData` (AVFrame media-type / channel tag mismatch at the TUTK
   AV layer).
2. `IPC_Media_SpeakerThread` never started (e.g. the camera-side session the
   IOCtrl SID resolves to is not the one holding our live avIndex).
3. The SHM audio-out profile-3 pipe expects a different sample rate/width
   than 16 kHz/16-bit.

`IPC_Media_SpeakerThread` logs all of this to `/tmp/message.log` via syslogd:
`"avClientStartEx success avIndex[%d] SID[%d] speakerCh[%d]"` on start,
`"Audio LOST[%d]"` / `"avRecvAudioData ... error"` on bad frames,
`"imediaSpeakerThread_stop==1. Exit"` on stop. Reading that log while we send
a frame resolves all three at once.

### Getting the live log (staged, non-persistent)

The firmware `upgrade.sh` dispatches by file extension; a `.backup` file runs
`backup_cmd.sh` as root. A squashfs with `backup_cmd.sh` = `telnetd -p 2323
-l /bin/sh` is built and on the SD card (`/tmp/jooan_A12_telnet.backup`).
Insert the SD, trigger
`http://192.168.1.144/goform/upgradeFW?userid=admin&userkey=md5(adminpw)&filename=/mnt/sd_card/jooan_A12.backup`,
then `telnet 192.168.1.144 2323` for a root shell →
`tail -f /tmp/message.log` while sending a talk-back frame. Non-persistent
(dies on reboot), nothing is flashed.
