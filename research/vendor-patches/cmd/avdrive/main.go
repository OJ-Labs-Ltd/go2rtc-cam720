// Drives DTLS + SpeakerStart + a real SPEEX narrowband tone, so we can
// verify at the camera whether the audio pipeline actually plays. If any
// 2nd arg is "quiet", payload is zeros. SPEEX frame size for narrowband
// mode 5 is 38 bytes. We send one frame every 20ms, 50 total = 1 second.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/tutk/dtls"
)

func main() {
	host, uid := os.Args[1], os.Args[2]
	port := 32761
	if p := os.Getenv("DRIVE_PORT"); p != "" {
		port, _ = strconv.Atoi(p)
	}
	psk := os.Getenv("CAM_PASS")
	speexFile := os.Getenv("SPEEX_FILE") // path to raw speex frames
	fmt.Printf("dialing %s:%d uid=%s speex=%s\n", host, port, uid, speexFile)
	c, err := dtls.DialDTLS(host, port, uid, "", psk, true)
	if err != nil { fmt.Println("dial:", err); return }
	defer c.Close()
	if err = c.AVClientStart(5 * time.Second); err != nil { fmt.Println("av:", err); return }
	fmt.Println("AV LOGIN OK two-way:", c.HasTwoWayStreaming())

	fmt.Println(">> 810 GetAudioOutFormat")
	if err := c.WriteIOCtrlStd(810, make([]byte, 8)); err != nil { fmt.Println("w810:", err); return }
	time.Sleep(500 * time.Millisecond)

	// Drain IOCtrl responses, note camera-advertised codec from 811 if seen
	advertisedCodec := uint16(141)
	advertisedFlags := byte(0x02)
	for i := 0; i < 6; i++ {
		if ct, data, err := c.RecvIOCtrlRaw(500 * time.Millisecond); err == nil {
			fmt.Printf("<< IOCtrl 0x%x(%d) %d bytes %s\n", ct, ct, len(data), hex.EncodeToString(data))
			if ct == 811 && len(data) >= 8 {
				c := binary.LittleEndian.Uint32(data[4:])
				advertisedCodec = uint16(c)
				fmt.Printf(">>> camera advertises codec = %d (0x%x)\n", c, c)
			}
		}
	}

	serverCh, _ := strconv.Atoi(os.Getenv("SERVER_CHAN"))
	if m := os.Getenv("FRAMEINFO"); m != "" {
		c.SendAudioCAM720Mode(m)
		fmt.Printf("### frameInfo mode = %s\n", m)
	}
	if os.Getenv("OPEN_CH1") == "1" {
		fmt.Println(">> OpenAudioChannelCAM720(admin, device_pwd)")
		if err := c.OpenAudioChannelCAM720("admin", os.Getenv("CAM_PASS")); err != nil {
			fmt.Println("open ch1:", err); return
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Printf(">> 848 OpenSpeakerCAM720WithChan(%d)\n", serverCh)
	if err := c.OpenSpeakerCAM720WithChan(uint32(serverCh)); err != nil { fmt.Println("w848:", err); return }
	time.Sleep(1500 * time.Millisecond)

	for i := 0; i < 3; i++ {
		if ct, data, err := c.RecvIOCtrlRaw(500 * time.Millisecond); err == nil {
			fmt.Printf("<< IOCtrl 0x%x(%d) %d bytes %s\n", ct, ct, len(data), hex.EncodeToString(data))
		}
	}
	_ = advertisedFlags

	var frames [][]byte
	frameSize, _ := strconv.Atoi(os.Getenv("FRAME_SIZE"))
	if frameSize == 0 {
		frameSize = 38 // speex narrowband default
	}
	if speexFile != "" {
		data, err := ioutil.ReadFile(speexFile)
		if err != nil { fmt.Println("read:", err); return }
		for i := 0; i+frameSize <= len(data); i += frameSize {
			frames = append(frames, data[i:i+frameSize])
		}
		fmt.Printf("loaded %d frames of %d bytes\n", len(frames), frameSize)
	} else {
		pcm := make([]byte, 160)
		for i := range pcm { pcm[i] = 0xFF }
		for i := 0; i < 10; i++ { frames = append(frames, pcm) }
	}

	codec := advertisedCodec
	if cs := os.Getenv("CODEC"); cs != "" {
		if v, _ := strconv.Atoi(cs); v > 0 { codec = uint16(v) }
	}
	flags := byte(0x02)
	if fs := os.Getenv("FLAGS"); fs != "" {
		if v, _ := strconv.ParseInt(fs, 0, 16); v != 0 { flags = byte(v) }
	}
	if speexFile == "" {
		codec = 0x8A
	}
	fmt.Printf("### using codec=%d flags=0x%x for frames\n", codec, flags)

	for i, f := range frames {
		if err := c.SendAudioCAM720(codec, flags, f); err != nil {
			fmt.Println("audio err:", err)
			break
		}
		if i < 5 || i%10 == 0 {
			fmt.Printf(">> audio frame %d sent (%d bytes codec=%d flags=0x%x)\n", i+1, len(f), codec, flags)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Settle & observe
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ct, data, err := c.RecvIOCtrlRaw(200 * time.Millisecond); err == nil {
			fmt.Printf("<< IOCtrl 0x%x %d bytes %s\n", ct, len(data), hex.EncodeToString(data))
		}
	}
	_ = binary.LittleEndian
}
