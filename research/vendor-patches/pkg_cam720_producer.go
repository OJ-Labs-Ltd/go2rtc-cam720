package cam720

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/aac"
	"github.com/AlexxIT/go2rtc/pkg/core"
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
	// The camera's talk pipe accepts G.711 A-law at 16 kHz; CAM720's own code
	// (SMsgAVIoctrlSpeakerStart) and the RTP flow we observe for recv both pin
	// it to those values.
	codec := &core.Codec{Name: core.CodecPCMA, ClockRate: 16000, Channels: 1}
	client.SetBackchannelCodec(tutk.CodecPCMA, 16000, 1)
	media := &core.Media{
		Kind:      core.KindAudio,
		Direction: core.DirectionSendonly,
		Codecs:    []*core.Codec{codec},
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
	if err := p.client.StartIntercom(); err != nil {
		return fmt.Errorf("cam720: start intercom: %w", err)
	}
	tutkCodec, rate, ch := p.client.GetBackchannelCodec()
	sender := core.NewSender(media, track.Codec)
	var ts uint32
	frameDurUS := tutk.GetSamplesPerFrame(tutkCodec) * 1000000 / rate
	sender.Handler = func(pkt *rtp.Packet) {
		if err := p.client.WriteAudio(tutkCodec, pkt.Payload, ts, rate, ch); err == nil {
			p.Send += len(pkt.Payload)
		}
		ts += frameDurUS
	}
	// Accept AAC from the browser too; convert to ADTS so the camera's decoder sees proper frames.
	switch track.Codec.Name {
	case core.CodecAAC:
		if track.Codec.IsRTP() {
			sender.Handler = aac.RTPToADTS(codec, sender.Handler)
		} else {
			sender.Handler = aac.EncodeToADTS(codec, sender.Handler)
		}
	}
	sender.HandleRTP(track)
	p.Senders = append(p.Senders, sender)
	return nil
}
