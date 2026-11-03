package cam720

import (
	"github.com/AlexxIT/go2rtc/internal/app"
	"github.com/AlexxIT/go2rtc/internal/streams"
	"github.com/AlexxIT/go2rtc/pkg/cam720"
	"github.com/AlexxIT/go2rtc/pkg/core"
)

func Init() {
	log := app.GetLogger("cam720")
	streams.HandleFunc("cam720", func(rawURL string) (core.Producer, error) {
		log.Debug().Msgf("cam720: dial %s", rawURL)
		return cam720.NewProducer(rawURL)
	})
}
