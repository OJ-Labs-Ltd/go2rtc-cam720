package cam720

import (
	"bytes"
	"testing"
)

func TestAudioPacketizerCarriesPartialFrames(t *testing.T) {
	var p audioPacketizer
	if got := p.append(bytes.Repeat([]byte{0xd5}, 100), 10000); len(got) != 0 {
		t.Fatal("sent a partial frame")
	}
	chunks := p.append(bytes.Repeat([]byte{0x55}, 220), 20000)
	if len(chunks) != 2 {
		t.Fatalf("got %d frames, want 2", len(chunks))
	}
	want := append(bytes.Repeat([]byte{0xd5}, 100), bytes.Repeat([]byte{0x55}, 60)...)
	if !bytes.Equal(chunks[0].payload, want) || !bytes.Equal(chunks[1].payload, bytes.Repeat([]byte{0x55}, 160)) {
		t.Fatal("packet boundaries lost audio")
	}
	if chunks[0].timestampUS != 10000 || chunks[1].timestampUS != 20000 {
		t.Fatal("timestamps must advance by 10ms per 160 samples")
	}
}
