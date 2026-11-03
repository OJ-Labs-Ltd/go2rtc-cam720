package cam720

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/pcm"
	"github.com/AlexxIT/go2rtc/pkg/tutk"
	"github.com/pion/rtp"
)

// Producer is the backchannel-only (talk) end for a CAM720 camera. The video and
// listen-in paths come from the camera's own RTSP (already in HA via a Generic
// Camera entity). This producer announces a single send-only audio media and
// pushes anything written to it over the Kalay DTLS tunnel.
type Producer struct {
	core.Connection
	client *Client
}

func NewProducer(rawURL string) (*Producer, error) {
	client, err := Dial(rawURL)
	if err != nil {
		return nil, err
	}
	// The camera speaker wants G.711 A-law at 16 kHz. WebRTC browsers only send
	// G.711 at 8 kHz, so we advertise 8 kHz G.711 (A-law and mu-law) here and
	// upsample to 16 kHz A-law in AddTrack. Offering only G.711 keeps the
	// browser off Opus, which it would otherwise prefer.
	client.SetBackchannelCodec(tutk.CodecPCMA, 16000, 1)
	media := &core.Media{
		Kind:      core.KindAudio,
		Direction: core.DirectionSendonly,
		Codecs: []*core.Codec{
			{Name: core.CodecPCMA, ClockRate: 8000, Channels: 1},
			{Name: core.CodecPCMU, ClockRate: 8000, Channels: 1},
		},
	}
	return &Producer{
		Connection: core.Connection{
			ID:         core.NewID(),
			FormatName: "cam720",
			Protocol:   client.Protocol(),
			RemoteAddr: client.RemoteAddr().String(),
			Source:     rawURL,
			Medias:     []*core.Media{media},
			Transport:  client,
		},
		client: client,
	}, nil
}

// Start keeps the DTLS session alive by draining whatever the camera sends.
// We don't surface recv frames; recv comes from the camera's RTSP instead.
func (p *Producer) Start() error {
	for {
		_ = p.client.SetDeadline(time.Now().Add(core.ConnDeadline))
		if _, err := p.client.ReadPacket(); err != nil {
			return err
		}
	}
}

func (p *Producer) Stop() error {
	_ = p.client.StopIntercom()
	return p.client.Close()
}

func (p *Producer) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Connection)
}

func (p *Producer) AddTrack(media *core.Media, codec *core.Codec, track *core.Receiver) error {
	if media.Direction != core.DirectionSendonly {
		return fmt.Errorf("cam720: only sendonly supported, got %s", media.Direction)
	}
	// Transcode whatever the browser sends (8 kHz A-law or mu-law) to the
	// camera's 16 kHz A-law.
	dst := &core.Codec{Name: core.CodecPCMA, ClockRate: 16000, Channels: 1}
	transcode := pcm.Transcode(dst, track.Codec)
	if transcode == nil {
		return fmt.Errorf("cam720: cannot transcode %s to PCMA/16000", track.Codec.Name)
	}
	if err := p.client.StartIntercom(); err != nil {
		return fmt.Errorf("cam720: start intercom: %w", err)
	}
	sender := core.NewSender(media, track.Codec)
	var ts uint32
	sender.Handler = func(pkt *rtp.Packet) {
		out := transcode(pkt.Payload)
		if len(out) == 0 {
			return
		}
		if err := p.client.WriteAudio(tutk.CodecPCMA, out, ts, 16000, 1); err == nil {
			p.Send += len(out)
		}
		ts += uint32(len(out)) * 1000000 / 16000
	}
	sender.HandleRTP(track)
	p.Senders = append(p.Senders, sender)
	return nil
}
