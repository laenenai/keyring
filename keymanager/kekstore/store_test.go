package kekstore_test

import (
	"testing"

	"github.com/laenenai/keyring/keymanager/kekstore"
	"github.com/laenenai/keyring/keyringtest"
)

func TestMemKEKStoreConformance(t *testing.T) {
	keyringtest.RunKEKStoreSuite(t, func(t *testing.T) kekstore.KEKStore {
		return kekstore.NewMemKEKStore()
	})
}
