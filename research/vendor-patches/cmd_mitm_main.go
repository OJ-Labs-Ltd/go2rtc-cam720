// MITM DTLS proxy for CAM720. Terminates DTLS on both sides using the known PSK
// (SHA256 of device_pwd), then logs decrypted TUTK AV frames traveling in both
// directions. The point is to reverse the exact IOCtrl/data sequence the real
// CAM720 phone app uses, so we can replicate it in go2rtc.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

// Known camera endpoint and PSK input. Target host comes from argv[1], PSK
// input (device_pwd) from CAM_PASS.
func main() {
	targetHost := os.Args[1]
	psk := sha256.Sum256([]byte(os.Getenv("CAM_PASS")))

	// Listen for incoming DTLS on 0.0.0.0:33000. Phones routed through our iptables
	// DNAT land here instead of talking to the camera directly.
	addr := &net.UDPAddr{Port: 33000}
	cfg := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			fmt.Printf("[PH] PSK hint=%q\n", hint)
			return psk[:], nil
		},
		PSKIdentityHint:         []byte("AUTHPWD_admin"),
		InsecureSkipVerify:      true,
		InsecureSkipVerifyHello: true,
		CipherSuites:            []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CBC_SHA256},
		ExtendedMasterSecret:    dtls.DisableExtendedMasterSecret,
	}

	l, err := dtls.Listen("udp", addr, cfg)
	if err != nil { fmt.Println("listen:", err); return }
	fmt.Printf("mitm listening on udp 33000, forwarding to %s:32761\n", targetHost)

	for {
		phoneConn, err := l.Accept()
		if err != nil { fmt.Println("accept:", err); continue }
		fmt.Printf("[+] phone connected from %s\n", phoneConn.RemoteAddr())
		go handle(phoneConn, targetHost, psk[:])
	}
}

func handle(phone net.Conn, targetHost string, psk []byte) {
	defer phone.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Open DTLS to the real camera as client.
	target := &net.UDPAddr{IP: net.ParseIP(targetHost), Port: 32761}
	udp, err := net.DialUDP("udp", nil, target)
	if err != nil { fmt.Println("dial cam:", err); return }
	cfg := &dtls.Config{
		PSK:                     func([]byte) ([]byte, error) { return psk, nil },
		PSKIdentityHint:         []byte("AUTHPWD_admin"),
		InsecureSkipVerify:      true,
		InsecureSkipVerifyHello: true,
		CipherSuites:            []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CBC_SHA256},
		ExtendedMasterSecret:    dtls.DisableExtendedMasterSecret,
	}
	cam, err := dtls.Client(udp, nil, cfg)
	if err != nil { fmt.Println("dial dtls cam:", err); return }
	defer cam.Close()
	fmt.Println("[-] connected to camera")

	// Pump both directions and log plaintext.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pump(ctx, phone, cam, "PH→CAM") }()
	go func() { defer wg.Done(); pump(ctx, cam, phone, "CAM→PH") }()
	wg.Wait()
}

func pump(ctx context.Context, src, dst net.Conn, tag string) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		src.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := src.Read(buf)
		if err != nil { fmt.Printf("[%s] read err: %v\n", tag, err); return }
		if n > 0 {
			fmt.Printf("[%s] len=%d %s\n", tag, n, hex.EncodeToString(buf[:n])[:min(200, n*2)])
			dst.Write(buf[:n])
		}
	}
}

func min(a, b int) int { if a < b { return a }; return b }
