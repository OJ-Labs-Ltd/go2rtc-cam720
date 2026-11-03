package dtls

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/AlexxIT/go2rtc/pkg/tutk"
)

// msgAudioFrame builds the channel-0 AV payload seen in phone_talk.pcap.
// The first record includes the optional eight-byte transport clock; regular
// records are 16-byte outer + 20-byte inner + audio + 16-byte frameInfo.
// The 20-packet FEC group/index identifies audio records. This sender does not
// generate the separate parity records that the SDK also sends.
func (c *DTLSConn) msgAudioFrame(payload []byte, timestampUS uint32, codec byte, sampleRate uint32, channels uint8) []byte {
	return c.msgAudioFrameMS(payload, timestampUS/1000, codec, sampleRate, channels)
}

func (c *DTLSConn) msgAudioFrameMS(payload []byte, timestampMS uint32, codec byte, sampleRate uint32, channels uint8) []byte {
	frame := c.audioFrameNo
	c.audioFrameNo++
	outerSize := 16
	if frame == 0 {
		outerSize += 8
	}
	b := make([]byte, outerSize+20+len(payload)+16)
	b[0], b[1] = 0x0c, 0x01
	binary.LittleEndian.PutUint16(b[2:], protoVersion)
	binary.LittleEndian.PutUint32(b[4:], atomic.AddUint32(&c.avSeq, 1)-1)
	fec := 8
	if frame == 0 {
		b[1] |= 8
		binary.LittleEndian.PutUint32(b[8:], timestampMS)
		fec += 8
	}
	binary.LittleEndian.PutUint16(b[fec:], uint16(frame/20))
	b[fec+2], b[fec+3] = byte(frame%20), 20
	binary.LittleEndian.PutUint32(b[fec+4:], 1)
	inner := b[outerSize:]
	inner[0], inner[1] = tutk.ChannelAudio, tutk.FrameTypeEndSingle
	binary.LittleEndian.PutUint16(inner[2:], uint16(frame))
	binary.LittleEndian.PutUint16(inner[4:], 1)
	binary.LittleEndian.PutUint16(inner[6:], 16)
	binary.LittleEndian.PutUint16(inner[8:], uint16(len(payload)+16))
	binary.LittleEndian.PutUint32(inner[12:], frame)
	binary.LittleEndian.PutUint32(inner[16:], frame+1)
	copy(inner[20:], payload)
	fi := inner[20+len(payload):]
	fi[0] = codec
	fi[2] = tutk.GetSampleRateIndex(sampleRate)<<2 | 2
	if channels == 2 {
		fi[2] |= 1
	}
	binary.LittleEndian.PutUint32(fi[12:], timestampMS)
	var checksum uint16
	for _, v := range inner {
		checksum += uint16(v)
	}
	binary.LittleEndian.PutUint16(inner[10:], checksum)
	return b
}

// msgCAM720IOCtrl is the AV plaintext, without a second IOTC/UDP wrapper.
// The outer IOTC wrapper is added exactly once by WriteDTLS.
func (c *DTLSConn) msgCAM720IOCtrl(ctrlType uint32, body []byte) []byte {
	b := make([]byte, 40+len(body))
	binary.LittleEndian.PutUint16(b, protoVersion)
	binary.LittleEndian.PutUint16(b[2:], protoVersion)
	binary.LittleEndian.PutUint32(b[4:], atomic.AddUint32(&c.avSeq, 1)-1)
	binary.LittleEndian.PutUint16(b[16:], magicIOCtrl)
	binary.LittleEndian.PutUint16(b[18:], c.seqCmd)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint32(b[24:], uint32(4+len(body)))
	binary.LittleEndian.PutUint32(b[28:], uint32(c.seqCmd))
	binary.LittleEndian.PutUint32(b[36:], ctrlType)
	copy(b[40:], body)
	c.seqCmd++
	return b
}
