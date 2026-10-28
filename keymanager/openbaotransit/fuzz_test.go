package openbaotransit

import (
	"testing"

	"github.com/laenenai/keyring/internal/domain"
)

func FuzzReadableCiphertext(f *testing.F) {
	f.Add([]byte("vault:v1:Zm9v"))
	f.Add([]byte("bao:v1:Zm9v"))
	f.Add([]byte("vault:v1:"))
	f.Add([]byte{0xff, 0x00})
	f.Fuzz(func(_ *testing.T, ciphertext []byte) {
		_, _ = readableCiphertext(domain.WrappedDEK{
			KEKID:      "k",
			KEKVersion: domain.FirstKEKVersion,
			KeyID:      "key",
			Ciphertext: ciphertext,
		})
	})
}
