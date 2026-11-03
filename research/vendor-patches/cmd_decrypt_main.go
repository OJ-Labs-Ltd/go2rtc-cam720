// Decrypt a specific DTLS CBC-SHA256 record given keys/IV/ciphertext.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	key, _ := hex.DecodeString(os.Args[1])
	iv, _ := hex.DecodeString(os.Args[2])
	ct, _ := hex.DecodeString(os.Args[3])
	block, _ := aes.NewCipher(key)
	m := cipher.NewCBCDecrypter(block, iv)
	pt := make([]byte, len(ct))
	m.CryptBlocks(pt, ct)
	fmt.Printf("pt (len=%d): %x\n", len(pt), pt)
	if len(pt) > 0 {
		pad := int(pt[len(pt)-1])
		fmt.Printf("pad: %d\n", pad)
		if pad < 16 {
			body := pt[:len(pt)-pad-1-32]
			fmt.Printf("body: %x\n", body)
		}
	}
}
