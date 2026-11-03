// Reads hex lines on stdin, applies the go2rtc ReverseTransCode to each, prints
// the plaintext bytes. Lets us verify the Kalay scramble layer on captured packets.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/AlexxIT/go2rtc/pkg/tutk"
)

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" { continue }
		b, err := hex.DecodeString(line)
		if err != nil { continue }
		fmt.Printf("in : %s\n", line[:min(80, len(line))])
		fmt.Printf("rev-partial: %x\n", tutk.ReverseTransCodePartial(nil, b[:min(len(b), 16)]))
		fmt.Printf("rev-blob   : %x\n", tutk.ReverseTransCodeBlob(b))
	}
}
func min(a, b int) int { if a < b { return a }; return b }
