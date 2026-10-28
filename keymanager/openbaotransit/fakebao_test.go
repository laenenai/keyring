package openbaotransit_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/laenenai/keyring"
	"github.com/laenenai/keyring/keymanager/openbaotransit"
)

// fakeTransit is a minimal in-memory transit server for failure-injection
// tests. It is deliberately not a general OpenBao emulator: it implements the
// handful of endpoints and error shapes these tests need, so a test can put
// the adapter into states a healthy real server will not produce (for example
// a tombstone and live key material at the same time).
type fakeTransit struct {
	mu sync.Mutex

	// keys maps a transit key name (for example "kek-tenant") to its latest
	// version. A missing entry is a 404/key-not-found.
	keys map[string]uint32
	// destroyed is keyed by the logical KEK id, not the transit key name.
	destroyed map[string]bool
	// destroyOnEncrypt simulates DestroyKEK completing between the tombstone
	// check and the encrypt call, with transit upserting the deleted key.
	destroyOnEncrypt map[string]bool
	// plaintext is returned by decrypt/datakey responses.
	plaintext []byte
}

func newFakeTransit() *fakeTransit {
	return &fakeTransit{
		keys:             make(map[string]uint32),
		destroyed:        make(map[string]bool),
		destroyOnEncrypt: make(map[string]bool),
		plaintext:        make([]byte, keyring.DEKSize),
	}
}

func (f *fakeTransit) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeTransit) keyManager(t *testing.T, srv *httptest.Server) keyring.KeyManager {
	t.Helper()
	km, err := openbaotransit.Open(t.Context(), openbaotransit.Config{
		Address: srv.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("openbaotransit.Open: %v", err)
	}
	return km
}

func (f *fakeTransit) markDestroyed(id string, keepKey bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed[id] = true
	if keepKey {
		f.keys[openbaotransit.KeyNamePrefix+id] = 1
		return
	}
	delete(f.keys, openbaotransit.KeyNamePrefix+id)
}

func (f *fakeTransit) markDestroyOnEncrypt(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyOnEncrypt[id] = true
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/transit/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		http.NotFound(w, r)
		return
	}

	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "keys":
		f.handleReadKey(w, parts[1])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[0] == "keys":
		f.handleCreateKey(w, parts[1])
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "keys" && parts[2] == "rotate":
		f.handleRotate(w, parts[1])
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "keys" && parts[2] == "config":
		writeJSON(w, http.StatusNoContent, nil)
	case r.Method == http.MethodDelete && len(parts) == 2 && parts[0] == "keys":
		f.handleDeleteKey(w, parts[1])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[0] == "encrypt":
		f.handleEncrypt(w, parts[1])
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "datakey" && parts[1] == "plaintext":
		f.handleGenerate(w, parts[2])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[0] == "decrypt":
		f.handleDecrypt(w, parts[1])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[0] == "rewrap":
		f.handleRewrap(w, parts[1])
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeTransit) handleReadKey(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if id, ok := strings.CutPrefix(name, openbaotransit.TombstoneNamePrefix); ok {
		if f.destroyed[id] {
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"latest_version": 1}})
			return
		}
		writeKeyNotFound(w)
		return
	}
	version, ok := f.keys[name]
	if !ok {
		writeKeyNotFound(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"latest_version": version}})
}

func (f *fakeTransit) handleCreateKey(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if id, ok := strings.CutPrefix(name, openbaotransit.TombstoneNamePrefix); ok {
		f.destroyed[id] = true
		writeJSON(w, http.StatusNoContent, nil)
		return
	}
	if _, exists := f.keys[name]; !exists {
		f.keys[name] = 1
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (f *fakeTransit) handleRotate(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	version, ok := f.keys[name]
	if !ok {
		writeKeyNotFound(w)
		return
	}
	version++
	f.keys[name] = version
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"latest_version": version}})
}

func (f *fakeTransit) handleDeleteKey(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, name)
	writeJSON(w, http.StatusNoContent, nil)
}

func (f *fakeTransit) handleEncrypt(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id := strings.TrimPrefix(name, openbaotransit.KeyNamePrefix)
	if f.destroyOnEncrypt[id] {
		// Destroy completed after the caller's tombstone check; transit's
		// upsert recreates the key while wrapping.
		f.destroyed[id] = true
		f.keys[name] = 1
	}
	version, ok := f.keys[name]
	if !ok {
		f.keys[name] = 1
		version = 1
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"ciphertext":  fmt.Sprintf("vault:v%d:AAAA", version),
		"key_version": version,
	}})
}

func (f *fakeTransit) handleGenerate(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id := strings.TrimPrefix(name, openbaotransit.KeyNamePrefix)
	if f.destroyOnEncrypt[id] {
		f.destroyed[id] = true
		f.keys[name] = 1
	}
	version, ok := f.keys[name]
	if !ok {
		f.keys[name] = 1
		version = 1
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"ciphertext":  fmt.Sprintf("vault:v%d:AAAA", version),
		"key_version": version,
		"plaintext":   f.plaintext,
	}})
}

func (f *fakeTransit) handleDecrypt(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.keys[name]; !ok {
		writeKeyNotFound(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"plaintext": f.plaintext}})
}

func (f *fakeTransit) handleRewrap(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	version, ok := f.keys[name]
	if !ok {
		writeKeyNotFound(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"ciphertext":  fmt.Sprintf("vault:v%d:BBBB", version),
		"key_version": version,
	}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func writeKeyNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"key not found"}})
}
