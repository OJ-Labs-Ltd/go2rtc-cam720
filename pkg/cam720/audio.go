package cam720

type audioChunk struct {
	payload     []byte
	timestampUS uint32
}

type audioPacketizer struct {
	pending     []byte
	timestampUS uint32
}

// append retains partial RTP payloads and returns complete 10ms A-law frames.
func (p *audioPacketizer) append(payload []byte, timestampUS uint32) []audioChunk {
	if len(p.pending) == 0 {
		p.timestampUS = timestampUS
	}
	p.pending = append(p.pending, payload...)
	var chunks []audioChunk
	for len(p.pending) >= 160 {
		chunks = append(chunks, audioChunk{p.pending[:160], p.timestampUS})
		p.pending = p.pending[160:]
		p.timestampUS += 10000
	}
	return chunks
}
