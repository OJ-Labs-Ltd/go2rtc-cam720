// avdrive sends the verified iPhone talk-back profile: channel 0, IOCtrl 848,
// 160-byte G.711 A-law frames at 16 kHz (10 ms), then IOCtrl 849.
// CAM_PASS is read only from the environment. AUDIO_FILE may name raw A-law
// audio; otherwise the driver generates a one-second 440 Hz test tone.
package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/pcm"
	"github.com/AlexxIT/go2rtc/pkg/tutk"
	"github.com/AlexxIT/go2rtc/pkg/tutk/dtls"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "avdrive:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: CAM_PASS=<environment value> avdrive cameraIP cameraUID")
	}
	password := os.Getenv("CAM_PASS")
	if password == "" {
		return fmt.Errorf("CAM_PASS must be set")
	}
	port := 32761
	if value := os.Getenv("DRIVE_PORT"); value != "" {
		var err error
		port, err = strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid DRIVE_PORT")
		}
	}
	var data []byte
	if path := os.Getenv("AUDIO_FILE"); path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	} else {
		data = make([]byte, 16000)
		for i := range data {
			value := int16(3000 * math.Sin(2*math.Pi*440*float64(i)/16000))
			if os.Getenv("QUIET") == "1" {
				value = 0
			}
			data[i] = pcm.PCMtoPCMA(value)
		}
	}
	if len(data) == 0 || len(data)%160 != 0 {
		return fmt.Errorf("AUDIO_FILE must contain a positive multiple of 160 raw A-law bytes")
	}
	c, err := dtls.DialDTLS(args[0], port, args[1], "", password, false)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err = c.AVClientStart(5 * time.Second); err != nil {
		return fmt.Errorf("AV login: %w", err)
	}
	if err = c.OpenSpeakerCAM720(); err != nil {
		return fmt.Errorf("speaker start: %w", err)
	}
	defer c.CloseSpeakerCAM720()
	// The phone allows about 500 ms between speaker-start and the first frame.
	time.Sleep(500 * time.Millisecond)
	start := time.Now()
	fmt.Printf("channel=0 codec=0x8a rate=16000 mono frames=%d interval=10ms\n", len(data)/160)
	for offset := 0; offset < len(data); offset += 160 {
		index := offset / 160
		if delay := time.Until(start.Add(time.Duration(index) * 10 * time.Millisecond)); delay > 0 {
			time.Sleep(delay)
		}
		if err = c.AVSendAudioDataCh0(tutk.CodecPCMA, data[offset:offset+160], uint32(index)*10000, 16000, 1); err != nil {
			return fmt.Errorf("frame %d: %w", index, err)
		}
	}
	time.Sleep(10 * time.Millisecond)
	return nil
}
