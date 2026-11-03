import os
# Full DTLS-over-TUTK-scramble decoder. Extracts the handshake, derives the
# master secret with the known PSK, decrypts application data, and prints the
# plaintext TUTK AV messages the real CAM720 phone app exchanges with the camera.
import struct, sys, subprocess, hashlib, hmac, collections
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PSK = hashlib.sha256(os.environ["CAM_PASS"].encode()).digest()

def pcap(path):
    with open(path, "rb") as f:
        f.read(24)
        while True:
            h = f.read(16)
            if len(h)<16: return
            ts_s, ts_us, incl, _ = struct.unpack("<IIII",h)
            pkt = f.read(incl)
            ip = pkt[14:]
            if (ip[0]>>4)!=4 or ip[9]!=17: continue
            ihl = (ip[0]&15)*4
            src=".".join(map(str,ip[12:16]))
            yield ts_s + ts_us/1e6, src, ip[ihl+8:]

pkts = list(pcap(sys.argv[1]))
# Decode all packets through the Kalay scramble layer
hex_input = "\n".join(p[2].hex() for p in pkts)
out = subprocess.run(["/tmp/decode"], input=hex_input.encode(), capture_output=True).stdout.decode()
blobs = [bytes.fromhex(l.split("rev-blob   : ",1)[1]) for l in out.splitlines() if l.startswith("rev-blob")]
print(f"decoded {len(blobs)}")

# Collect DTLS records (strip TUTK session header, 28 bytes)
records = []
for i, b in enumerate(blobs):
    if len(b) < 41: continue
    off = 28
    while off + 13 <= len(b):
        rec = b[off:]
        L = int.from_bytes(rec[11:13], "big")
        full = rec[:13+L]
        if len(full) < 13+L: break
        records.append((pkts[i][0], pkts[i][1], full))
        off += 13+L

# Pull handshake messages from epoch 0
seen = set(); hs_c = []; hs_s = []
for ts, src, rec in records:
    if rec[0] != 22 or rec[3:5] != b"\x00\x00": continue
    pl = rec[13:]
    o = 0
    while o + 12 <= len(pl):
        L = int.from_bytes(pl[o+1:o+4], "big")
        msg = pl[o:o+12+L]
        if len(msg) < 12+L: break
        k = (src, msg[:12])
        if k not in seen:
            seen.add(k)
            if src == "192.168.1.144": hs_s.append(msg)
            else: hs_c.append(msg)
        o += 12+L

ch = next((m for m in hs_c if m[0] == 1), None)
sh = next((m for m in hs_s if m[0] == 2), None)
shd = next((m for m in hs_s if m[0] == 14), None)
cke = next((m for m in hs_c if m[0] == 16), None)
if not (ch and sh and shd and cke):
    print(f"missing: ch={bool(ch)} sh={bool(sh)} shd={bool(shd)} cke={bool(cke)}")
    sys.exit(1)
client_random = ch[12+2:12+34]
server_random = sh[12+2:12+34]

def prf(secret, label, seed, n):
    out, a = b"", label + seed
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + label + seed, hashlib.sha256).digest()
    return out[:n]

pms = len(PSK).to_bytes(2,"big") + b"\x00"*len(PSK) + len(PSK).to_bytes(2,"big") + PSK
ms = prf(pms, b"master secret", client_random + server_random, 48)
kb = prf(ms, b"key expansion", server_random + client_random, 96)
cmk, smk, cek, sek = kb[:32], kb[32:64], kb[64:80], kb[80:96]
print(f"keys derived: cek={cek.hex()} sek={sek.hex()}")

# Decrypt all app-data records (type 23) with the right key per direction
plaintexts = []
for ts, src, rec in records:
    if rec[0] != 23 or rec[3:5] == b"\x00\x00": continue
    iv = rec[13:29]; ct = rec[29:]
    if len(ct) < 16 or len(ct) % 16: continue
    key = sek if src == "192.168.1.144" else cek
    pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
    if not pt: continue
    pad = pt[-1]
    if pad > 15 or pt[-pad-1:] != bytes([pad])*(pad+1): continue
    body = pt[:-pad-1-32]
    dir_ = "S→C" if src == "192.168.1.144" else "C→S"
    plaintexts.append((ts, dir_, body))
print(f"decrypted {len(plaintexts)} records")

# Dump the C→S plaintexts (phone→camera) in order, these are the IOCtrls the app sends
sent = 0
for ts, d, body in plaintexts:
    if d != "C→S": continue
    sent += 1
    if sent > 60: break
    print(f"{ts:.3f} {d} len={len(body)} {body[:48].hex()}")

print("\n--- unique magic bytes at offset 0 in C→S ---")
cnt = collections.Counter(body[:4].hex() for _, d, body in plaintexts if d == "C→S" and len(body) >= 4)
for k, v in cnt.most_common(10): print(f"  {k}: {v}")
print("\n--- unique magic bytes at offset 0 in S→C (len >= 32) ---")
cnt = collections.Counter(body[:4].hex() for _, d, body in plaintexts if d == "S→C" and len(body) >= 32)
for k, v in cnt.most_common(10): print(f"  {k}: {v}")
