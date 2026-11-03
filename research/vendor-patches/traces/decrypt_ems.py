import os
# Decrypt CAM720 DTLS with Extended Master Secret.
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
hex_input = "\n".join(p[2].hex() for p in pkts)
out = subprocess.run(["/tmp/decode"], input=hex_input.encode(), capture_output=True).stdout.decode()
blobs = [bytes.fromhex(l.split("rev-blob   : ",1)[1]) for l in out.splitlines() if l.startswith("rev-blob")]

# Collect records
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

# Collect ordered handshake messages (dedupe by hs msg_seq per direction)
hs_c = {}; hs_s = {}
for ts, src, rec in records:
    if rec[0] != 22 or rec[3:5] != b"\x00\x00": continue
    pl = rec[13:]
    o = 0
    while o + 12 <= len(pl):
        mt = pl[o]
        L = int.from_bytes(pl[o+1:o+4], "big")
        msg = pl[o:o+12+L]
        if len(msg) < 12+L: break
        mseq = int.from_bytes(msg[4:6], "big")
        d = hs_s if src == "192.168.1.144" else hs_c
        if mseq not in d: d[mseq] = msg
        o += 12+L

print(f"client HS msgs: {sorted(hs_c.keys())}")
print(f"server HS msgs: {sorted(hs_s.keys())}")

ch = hs_c.get(0)  # ClientHello (first flight)
# ServerHello first (seq 0), then ServerHelloDone (seq 1)
sh = hs_s.get(0)
shd = hs_s.get(1)
# ClientKeyExchange is seq 1 in client (seq 0 was ClientHello without cookie, retried with cookie as seq 1? depends)
# Actually we have hs_c with retry sequences. Let's check.
cke = next((m for m in hs_c.values() if m[0] == 16), None)
ch2 = next((m for m in hs_c.values() if m[0] == 1 and m[12+34] == 0 and int.from_bytes(m[4:6], "big") != 0), None)
# Need the ClientHello that was accepted (second one, with cookie)
# For EMS session hash: SHA256 over ClientHello(final), ServerHello, Certificate*, ServerKeyExchange*, CertificateRequest*, ServerHelloDone, ClientCertificate*, ClientKeyExchange
# In TLS/DTLS format (strip DTLS handshake header's msg_seq/frag fields)
def tlsmsg(dtls_msg):
    return dtls_msg[:4] + dtls_msg[12:]
# Which ClientHello? Try both: seq 0 and seq 1
for ch_candidate_seq in sorted(hs_c.keys()):
    ch_candidate = hs_c[ch_candidate_seq]
    if ch_candidate[0] != 1: continue
    transcript = tlsmsg(ch_candidate) + tlsmsg(sh) + tlsmsg(shd) + tlsmsg(cke)
    session_hash = hashlib.sha256(transcript).digest()
    pms = len(PSK).to_bytes(2,"big") + b"\x00"*len(PSK) + len(PSK).to_bytes(2,"big") + PSK
    def prf(secret, label, seed, n):
        o, a = b"", label + seed
        while len(o) < n:
            a = hmac.new(secret, a, hashlib.sha256).digest()
            o += hmac.new(secret, a + label + seed, hashlib.sha256).digest()
        return o[:n]
    ms = prf(pms, b"extended master secret", session_hash, 48)
    client_random = ch_candidate[12+2:12+34]
    server_random = sh[12+2:12+34]
    kb = prf(ms, b"key expansion", server_random + client_random, 96)
    cmk, smk, cek, sek = kb[:32], kb[32:64], kb[64:80], kb[80:96]

    # Try decryption on first app-data record
    first_app = next(((ts, src, r) for ts, src, r in records if r[0] == 23 and r[3:5] != b"\x00\x00"), None)
    if not first_app: continue
    _, src, rec = first_app
    iv = rec[13:29]; ct = rec[29:]
    key = sek if src == "192.168.1.144" else cek
    pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
    pad = pt[-1]
    if pad < 16 and pt[-pad-1:] == bytes([pad])*(pad+1):
        print(f"\n=== CH seq {ch_candidate_seq} WORKS (EMS) ===")
        print(f"client_random={client_random.hex()}")
        print(f"server_random={server_random.hex()}")
        print(f"session_hash={session_hash.hex()}")
        print(f"cek={cek.hex()} sek={sek.hex()}")
        # Dump decrypted traffic
        sent = 0
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
            d = "S→C" if src == "192.168.1.144" else "C→S"
            sent += 1
            if sent <= 20 or sent % 100 == 0:
                print(f"{ts:.3f} {d} len={len(body)} {body[:48].hex()}")
        print(f"\ntotal decrypted: {sent}")
        break
    else:
        print(f"CH seq {ch_candidate_seq} failed (pad={pad})")
