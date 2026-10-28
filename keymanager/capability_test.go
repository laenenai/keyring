package keymanager_test

import (
	"testing"

	"github.com/laenenai/keyring/keymanager"
	"github.com/laenenai/keyring/keymanager/local"
	"github.com/laenenai/keyring/keymanager/openbaotransit"
)

func TestRewrapWithoutPlaintextIsAdapterSpecific(t *testing.T) {
	t.Parallel()

	var _ keymanager.RewrapWithoutPlaintext = (*openbaotransit.KeyManager)(nil)
	var _ keymanager.KEKVersionLister = (*openbaotransit.KeyManager)(nil)
	var _ keymanager.KEKVersionLister = (*local.KeyManager)(nil)
	if _, ok := any((*local.KeyManager)(nil)).(keymanager.RewrapWithoutPlaintext); ok {
		t.Fatal("local.KeyManager must not claim a plaintext-free rewrap capability")
	}
}
