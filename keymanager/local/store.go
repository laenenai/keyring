package local

import "github.com/laenenai/keyring/keymanager/kekstore"

// KEKStore is the neutral persistence port defined in keymanager/kekstore.
// It remains here as an alias so existing imports of the local adapter keep
// compiling; new code should import keymanager/kekstore directly.
type KEKStore = kekstore.KEKStore

// MemKEKStore is the in-memory test store from keymanager/kekstore. See its
// documentation before using it for data that must outlive the process.
type MemKEKStore = kekstore.MemKEKStore

// ErrKEKVersionExists is the neutral store's optimistic-concurrency signal.
var ErrKEKVersionExists = kekstore.ErrKEKVersionExists

// NewMemKEKStore returns an empty in-memory store. It is retained as a local
// convenience; new code can call kekstore.NewMemKEKStore directly.
func NewMemKEKStore() *MemKEKStore { return kekstore.NewMemKEKStore() }
