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

	audioMu      sync.Mutex
	audioStarted bool
	audioFrames  audioPacketizer

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
	// The speaker stays silent unless the session matches the iOS app's:
	// a second AV login on IOTC channel 1, then IPCAM_START and 810 on channel 0.
	if err := conn.AVClientStartCh1(5 * time.Second); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("cam720: ch1 av login: %w", err)
	}
	for _, ctrl := range []uint32{iotypeIpcamStart, 810} {
		if err := conn.WriteIOCtrlStd(ctrl, make([]byte, 8)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("cam720: ioctrl %d: %w", ctrl, err)
		}
	}
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
	c.audioMu.Lock()
	defer c.audioMu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	if c.audioStarted {
		return nil
	}
	// The iPhone sends 848 {1,0}, but all talk audio uses the main avIndex.
	if err := c.conn.OpenSpeakerCAM720(); err != nil {
		return err
	}
	c.audioFrames = audioPacketizer{}
	c.audioStarted = true
	return nil
}

func (c *Client) StopIntercom() error {
	c.audioMu.Lock()
	defer c.audioMu.Unlock()
	if c.conn == nil || !c.audioStarted {
		return nil
	}
	err := c.conn.CloseSpeakerCAM720()
	c.audioStarted = false
	c.audioFrames = audioPacketizer{}
	return err
}

func (c *Client) WriteAudio(codec byte, payload []byte, ts uint32, rate uint32, ch uint8) error {
	c.audioMu.Lock()
	defer c.audioMu.Unlock()
	if !c.audioStarted {
		return fmt.Errorf("backchannel not ready")
	}
	if codec != tutk.CodecPCMA || rate != 16000 || ch != 1 {
		return fmt.Errorf("cam720: talk-back requires G.711 A-law, 16000 Hz, mono")
	}
	for _, chunk := range c.audioFrames.append(payload, ts) {
		if err := c.conn.AVSendAudioDataCh0(codec, chunk.payload, chunk.timestampUS, rate, ch); err != nil {
			return err
		}
	}
	return nil
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
