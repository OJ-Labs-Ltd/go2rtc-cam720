# CAM720 (Jooan JA-A12) firmware notes

Firmware dumped locally on 2026-11-03 using
[peak3d/jooan-updater](https://github.com/peak3d/jooan-updater)'s
`.backup` dispatch path. Flash image (8 MB) lives at
`firmware/jooan_ja-a12_mtd.bin` (gitignored — contains the device's
baked-in AuthKey). Firmware version: `05.02.31.112`, model JA-A12.

## Dump procedure (reproduce)

```sh
# One-time: build the squashfs payload
git clone https://github.com/peak3d/jooan-updater.git
cd jooan-updater
apt install squashfs-tools xxd  # or brew equivalents
bash ./build-squashfs.sh A12
cp squashfs/jooan_A12.upgrade squashfs/jooan_A12.backup
```

Then copy `squashfs/jooan_A12.backup` to the root of a FAT32 SD card,
insert the SD into the camera, and trigger:

```sh
PWMD5=$(python3 -c "import hashlib,sys; print(hashlib.md5(sys.argv[1].encode()).hexdigest())" "$ADMIN_PASSWORD")
curl "http://192.168.1.144/goform/upgradeFW?userid=admin&userkey=$PWMD5&filename=/mnt/sd_card/jooan_A12.backup"
```

Camera replies `Upgrade Done...`, writes `backup.bin` to the SD root
(reads `/dev/mtd[0-9]` and concatenates). Pull the SD, read `backup.bin`.

## Flash layout

```
0x000000  u-boot + u-boot-env
0x1b8000  squashfs #1  (~3.3 MB, 285 inodes) - rootfs (/bin, /system, /etc)
0x488000  squashfs #2  (~3.6 MB, 198 inodes) - app partition (/run, /VoiceGuide, /lib, /etc)
```

Both filesystems are xz-compressed squashfs 4.0. Extract with
`unsquashfs -d out part.bin`.

## What's inside

Main app binary: `sqfs2_ex/run/jooanipc` (6.08 MB, MIPS32 LSB,
dynamically linked to `/lib/ld-uClibc.so.0`, stripped).

Statically includes the ThroughTek TUTK/IOTC runtime. Observable
exports (from `strings`):

- `AVAPI_BBR_DoSend`, `AVAPI_Send_FEC_RedundPacket`
- `avClientStart_inner`, `avServStart2_inner`, `avServExit`
- `avSendIOCtrl`, `avSendIOCtrlFrame`, `avRecvIOCtrl`, `avRecvIOCtrl_new`
- `IOTC_Session_Channel_ON` / `_OFF`, `IOTC_Session_Lock` / `unLock`
- `IOTC_Session_Write_Data_And_Datatype`, `IOTC_Session_Read_Data_And_Datatype`
- `IOTC_Session_Write_DTLS`
- `IOTC_Device_Login`, `IOTC_Setup_Auto_WakeUp_Internal`

Talk-back:

- `AE_talkback_init` / `AE_talkback_release`
- `AE_audio_talkback_play`
- `TalkBackThr`, `talkback2_Thread`
- `handle_DP_TalkBack_Start`, `handle_DP_Video_Stop`
- Camera opens both `avServStartEx CH0` and `avServStartEx CH1`
  (confirmed via error strings referencing each channel independently)

Audio:

- G.711 (both ONVIF `tt:Encoding=G711` and raw `pcm_alaw` / `pcm_mulaw`
  support in the codec table)
- SPEEX, AAC-LC also present (`AACENC_Encode`, `InitAACEncHandle`)
- Audio processing: `audio_process_aec_*`, `audio_process_agc_*`,
  `audio_process_ns_*`, `audio_process_hpf_*`
- Speaker amp enable: GPIO 63 (`"SpeakGpio":63,"SpeakLevelEx":0`)
- Default talk volume: `AoTalkVolume = 60` (out of 100)

## Baked-in secrets (do not commit)

From the device's root-config JSON (visible in strings of the
app binary):

- `AuthKey` — the 14-char cloud token (= our `device_pwd`, in env file)
- `IaacInfo.SN` — serial-ish identifier used for Iaac licensing
- `SysInfoEnc` — short encrypted blob

The config is readable through the running camera via
`/goform/getOtherSetttings?...singleCMD=GetJsonConf&json_string=...`,
authenticated by `userkey=md5(adminPassword)`.

## Reverse engineering next steps

Static analysis of `jooanipc` under Ghidra is the right next
investment. Headline questions:

1. What exact wire payload does `avServStart2_inner` send on channel 1
   when the client is us? Our fork's `OpenAudioChannelCAM720`
   (Session16 ClientStart on channel 1, 598 bytes, admin + device_pwd)
   is accepted at the DTLS layer but doesn't open the audio path —
   likely a mismatch in `auth_type`, `security_mode`, or the trailer
   layout.
2. Where is the handler that enables GPIO 63 (`SpeakGpio`) at talk-back
   start? If GPIO stays off, even correctly-decoded audio is inaudible.
   Our test frames (G.711 μ-law, G.711 A-law at 8 kHz and 16 kHz,
   SPEEX at 8 kHz, with both n+16 and n+40 trailers) all got
   acknowledged by the camera's vendor-specific IOCtrl `0x40` whose
   counter advanced with frame count — meaning the camera accepts and
   counts frames, just doesn't route them to the speaker.
3. The dispatch table that maps IOCtrl type → `handle_DP_*` handler.
   The ASCII name `handle_DP_TalkBack_Start` is a `strings` hit; find
   the IOCtrl code (likely one of the vendor-specific `MQTT_` or
   `DP_` codes) that triggers it when sent from a logged-in client.
