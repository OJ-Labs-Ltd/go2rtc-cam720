// Package cam720 drives a Jooan CAM720 (JA-A12) camera over its ThroughTek
// Kalay DTLS P2P channel. We only need the LAN flow, so the Kalay cloud
// broker is skipped entirely: Dial takes the camera's own IP, UID and the
// device_pwd token.
package cam720

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/tutk"
	"github.com/AlexxIT/go2rtc/pkg/tutk/dtls"
)

// Standard TUTK IOCTRL command codes (from AVIOCTRLDEFs.java).
const (
	iotypeIpcamStart        uint32 = 0x01FF
	iotypeIpcamAudioStart   uint32 = 0x0300
	iotypeIpcamSpeakerStart uint32 = 0x0350
)

type Client struct {
	conn *dtls.DTLSConn

	host    string
	uid     string
	token   string
	verbose bool

	closed  bool
	closeMu sync.Mutex

	// Backchannel codec, cached from the audio frames the camera sends.
	audioCodecID    byte
	audioSampleRate uint32
	audioChannels   uint8
}

// Dial parses `cam720://TOKEN@HOST/UID?verbose=1` or the equivalent query
// form `cam720://HOST/?uid=UID&token=TOKEN` and brings up the DTLS AV
// session.
func Dial(rawURL string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("cam720: invalid URL: %w", err)
	}

	q := u.Query()
	token := q.Get("token")
	if token == "" {
		if u.User != nil {
			token = u.User.Username()
		}
	}
	uid := q.Get("uid")
	if uid == "" {
		uid = u.Path
		for len(uid) > 0 && uid[0] == '/' {
			uid = uid[1:]
		}
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "32761"
	}
	if host == "" || uid == "" || token == "" {
		return nil, fmt.Errorf("cam720: host, uid and token are all required")
	}

	c := &Client{host: host, uid: uid, token: token, verbose: q.Get("verbose") == "1"}

	portInt := 32761
	if port != "" {
		if n, err := net.LookupPort("udp", port); err == nil {
			portInt = n
		}
	}
	conn, err := dtls.DialDTLS(host, portInt, uid, "", token, c.verbose)
	if err != nil {
		return nil, fmt.Errorf("cam720: dtls dial: %w", err)
	}
	c.conn = conn

	if err := conn.AVClientStart(8 * time.Second); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("cam720: av login: %w", err)
	}
	// Backchannel-only producer: video / listen-in come from the camera's own
	// RTSP. We don't ask the camera to push AV frames; just hold the DTLS
	// session so we can open the speaker channel on demand.
	return c, nil
}

// ioctrl sends a TUTK user IOCTRL command in the standard Session16 wire
// format (what CAM720 firmware expects). Body = SMsgAVIoctrlAVStream.
func (c *Client) ioctrl(ctrlType uint32, channel uint32) error {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body, channel)
	// bytes 4..7 reserved (zero)
	return c.conn.WriteIOCtrlStd(ctrlType, body)
}

func (c *Client) SupportsAudio() bool    { return true }
func (c *Client) SupportsIntercom() bool { return c.conn != nil && c.conn.HasTwoWayStreaming() }

func (c *Client) ReadPacket() (*tutk.Packet, error) {
	return c.conn.AVRecvFrameData()
}

func (c *Client) SetBackchannelCodec(codecID byte, sampleRate uint32, channels uint8) {
	c.audioCodecID = codecID
	c.audioSampleRate = sampleRate
	c.audioChannels = channels
}

func (c *Client) GetBackchannelCodec() (byte, uint32, uint8) {
	return c.audioCodecID, c.audioSampleRate, c.audioChannels
}

func (c *Client) StartIntercom() error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	if c.conn.IsBackchannelReady() {
		return nil
	}
	// Tell the camera to open its speaker channel, then bring up the DTLS backchannel.
	if err := c.ioctrl(iotypeIpcamSpeakerStart, 0); err != nil {
		return fmt.Errorf("open speaker: %w", err)
	}
	return c.conn.AVServStart()
}

func (c *Client) StopIntercom() error {
	if c.conn == nil || !c.conn.IsBackchannelReady() {
		return nil
	}
	return c.conn.AVServStop()
}

func (c *Client) WriteAudio(codec byte, payload []byte, ts uint32, rate uint32, ch uint8) error {
	if !c.conn.IsBackchannelReady() {
		return fmt.Errorf("backchannel not ready")
	}
	return c.conn.AVSendAudioData(codec, payload, ts, rate, ch)
}

func (c *Client) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return nil
	}
	return c.conn.SetDeadline(t)
}

func (c *Client) Protocol() string { return "cam720/dtls" }

func (c *Client) RemoteAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

func (c *Client) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
