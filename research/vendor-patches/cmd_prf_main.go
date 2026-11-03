// Use pion/dtls's PRF to compute the master secret for the captured handshake
// so we can compare with the Python implementation.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"os"

	"github.com/pion/dtls/v3/pkg/crypto/prf"
)

var sha256Hash prf.HashFunc = func() hash.Hash { return sha256.New() }

func main() {
	// args: client_random server_random session_hash psk
	cr, _ := hex.DecodeString(os.Args[1])
	sr, _ := hex.DecodeString(os.Args[2])
	sh, _ := hex.DecodeString(os.Args[3])
	psk, _ := hex.DecodeString(os.Args[4])
	fmt.Printf("inputs: cr=%d sr=%d sh=%d psk=%d\n", len(cr), len(sr), len(sh), len(psk))

	// PSK pre-master secret: other_secret_len(2) || other_secret || psk_len(2) || psk
	pms := prf.PSKPreMasterSecret(psk)
	fmt.Printf("pms_len=%d first=%x\n", len(pms), pms[:16])

	// EMS master secret
	ms, err := prf.ExtendedMasterSecret(pms, sh, sha256Hash)
	if err != nil { fmt.Println("ems err:", err); return }
	fmt.Printf("ms_ems=%s\n", hex.EncodeToString(ms))

	// Non-EMS master secret
	ms2, err := prf.MasterSecret(pms, cr, sr, sha256Hash)
	if err != nil { fmt.Println("ms err:", err); return }
	fmt.Printf("ms_std=%s\n", hex.EncodeToString(ms2))

	// Compare with Python PRF
}
