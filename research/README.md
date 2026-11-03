# CAM720 research notes

Historical reverse-engineering notes and tooling behind the `cam720://`
source, extracted from an earlier home-automation repo. Kept for reference; the
shipping code is in the parent repo (`pkg/cam720`, `pkg/tutk`) and the usage
docs are in [../CAM720.md](../CAM720.md).

- `CAM720.md`, `CAM720_FIRMWARE.md`, `CAM720_TALKBACK.md` — protocol, firmware
  and talk-back analysis.
- `vendor-patches/` — the original patch set and the DTLS capture-decryption
  and MITM tooling used to work the protocol out.

Secrets (device password, admin password) are redacted to placeholders. The
decryption scripts read the device password from the `CAM_PASS` environment
variable.
