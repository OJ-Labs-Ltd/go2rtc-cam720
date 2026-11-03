package dtls

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func CalculateAuthKey(enr, mac string) []byte {
	data := enr + strings.ToUpper(mac)
	hash := sha256.Sum256([]byte(data))
	b64 := base64.StdEncoding.EncodeToString(hash[:6])
	b64 = strings.ReplaceAll(b64, "+", "Z")
	b64 = strings.ReplaceAll(b64, "/", "9")
	b64 = strings.ReplaceAll(b64, "=", "A")
	return []byte(b64)
}

// DerivePSK: PSK = SHA256(input), truncate at first NULL (TUTK3rdSHA256 convention).
// For CAM720: input is the P2P auth key set via /goform/setAPLanP2PAuthkey.
func DerivePSK(input string) []byte {
	hash := sha256.Sum256([]byte(input))
	n := 32
	for i := range 32 {
		if hash[i] == 0x00 { n = i; break }
	}
	psk := make([]byte, 32)
	copy(psk[:n], hash[:n])
	return psk
}
