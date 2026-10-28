package domain_test

import (
	"testing"

	"github.com/laenenai/keyring/internal/domain"
)

func FuzzWrappedDEKUnmarshalBinary(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add([]byte{1, 0, 0, 0, 1, 'k', 0, 0, 0, 1, 0, 0, 0, 1, 'x', 0, 0, 0, 1, 'f', 0, 0, 0, 1, 'c'})
	f.Add([]byte{0xff, 1, 2, 3})
	f.Fuzz(func(_ *testing.T, data []byte) {
		var w domain.WrappedDEK
		_ = w.UnmarshalBinary(data)
	})
}
