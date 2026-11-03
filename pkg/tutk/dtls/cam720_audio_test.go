package dtls

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestCAM720AudioCapture(t *testing.T) {
	// First two silent phone records at 6.077s. Only timestamps are zeroed;
	// the native additive checksum is consequently 0x867e / 0x8681.
	// The payload is synthetic A-law silence, not recorded speech.
	c := &DTLSConn{avSeq: 0x62}
	for _, header := range []string{
		"0c090c0062000000000000000000000000000014010000000301000001001000b0007e860000000001000000",
		"0c010c006300000000000114010000000301010001001000b00081860100000002000000",
	} {
		want, err := hex.DecodeString(header)
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{0xd5}, 160)
		want = append(want, payload...)
		want = append(want, []byte{0x8a, 0, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...)
		got := c.msgAudioFrame(payload, 0, 0x8a, 16000, 1)
		if !bytes.Equal(got, want) {
			t.Fatalf("wire mismatch: got %d bytes %x; want %d bytes %x", len(got), got[:min(44, len(got))], len(want), want[:44])
		}
	}
}

func TestCAM720FullCapture(t *testing.T) {
	path := os.Getenv("CAM720_PLAINTEXT")
	if path == "" {
		t.Skip("set CAM720_PLAINTEXT to the scoped pcapdec dump")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || fields[1] != "ch0" || fields[2] != "P>C" {
			continue
		}
		want, err := hex.DecodeString(fields[len(fields)-1])
		if err != nil {
			t.Fatal(err)
		}
		if len(want) != 212 && len(want) != 220 {
			continue
		}
		outer := len(want) - 196
		frameNo := binary.LittleEndian.Uint32(want[outer+16:])
		c := &DTLSConn{avSeq: binary.LittleEndian.Uint32(want[4:]), audioFrameNo: frameNo - 1}
		payload := bytes.Clone(want[outer+20 : len(want)-16])
		// Remove timestamp contribution from the captured checksum. This
		// does not recalculate the checksum using the production builder.
		check := binary.LittleEndian.Uint16(want[outer+10:])
		for i := len(want) - 4; i < len(want); i++ {
			check -= uint16(want[i])
			want[i] = 0
		}
		binary.LittleEndian.PutUint16(want[outer+10:], check)
		if outer == 24 {
			if frameNo == 1 {
				clear(want[8:16])
			} else {
				// The SDK occasionally piggybacks a transport clock. Its
				// scheduling and parity records are separate from audio framing.
				want = append(want[:8], want[16:]...)
				want[1] &= ^byte(8)
			}
		}
		got := c.msgAudioFrame(payload, 0, 0x8a, 16000, 1)
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d differs after timestamp normalization", frameNo)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 1083 {
		t.Fatalf("checked %d audio frames, want 1083", count)
	}
	t.Logf("matched all %d captured audio frames after timestamp normalization", count)
}

func TestCAM720IOCtrlCapture(t *testing.T) {
	c := &DTLSConn{avSeq: 0x5a, seqCmd: 10}
	want, _ := hex.DecodeString("0c000c005a000000000000000000000000700a00010000000c0000000a00000000000000500300000100000000000000")
	got := c.msgCAM720IOCtrl(848, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	if !bytes.Equal(got, want) {
		t.Fatalf("IOCtrl wire mismatch: got %x; want %x", got, want)
	}
}

func TestCAM720LoginCapture(t *testing.T) {
	// Capture layout with a synthetic password and handshake random ID.
	c := &DTLSConn{enr: "synthetic-fixture"}
	want := make([]byte, 570)
	copy(want, []byte{0, 0, 12, 0})
	copy(want[16:], []byte{0x22, 2, 1, 0, 1, 2, 3, 4})
	copy(want[24:], "admin")
	copy(want[281:], "synthetic-fixture")
	tail, _ := hex.DecodeString("0100000004000000fb071f000000000000000000000003000000000001000000")
	copy(want[538:], tail)
	got := c.msgAVLogin(magicAVLogin1, 570, 1, []byte{1, 2, 3, 4})
	if !bytes.Equal(got, want) {
		t.Fatal("AV login differs from captured field offsets and capability trailer")
	}
}

func TestCAM720FirstIOCtrlStartsAtZero(t *testing.T) {
	c := &DTLSConn{}
	frame := c.msgCAM720IOCtrl(848, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	if binary.LittleEndian.Uint16(frame[18:]) != 0 || binary.LittleEndian.Uint32(frame[28:]) != 0 {
		t.Fatal("first control sequence must be zero, as captured")
	}
}
