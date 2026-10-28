package openbaotransit_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laenenai/keyring"
	"github.com/laenenai/keyring/keymanager/openbaotransit"
)

func newFaultManager(t *testing.T, server *httptest.Server, retry openbaotransit.RetryPolicy) *openbaotransit.KeyManager {
	t.Helper()
	km, err := openbaotransit.Open(context.Background(), openbaotransit.Config{
		Address: server.URL,
		Token:   "test-token",
		Retry:   retry,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return km
}

func faultDEK(t *testing.T) keyring.DEK {
	t.Helper()
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	return dek
}

func TestRetriesTransientServerErrors(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/destroyed-kek-kek-1":
			http.Error(w, `{"errors":["key not found"]}`, http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/encrypt/kek-kek-1":
			if attempts.Add(1) < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"errors":["transaction commit failed"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v1:Zm9v","key_version":1}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	km := newFaultManager(t, server, openbaotransit.RetryPolicy{
		MaxAttempts:    3,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
	})
	if _, err := km.WrapDEK(context.Background(), "kek-1", "key-1", faultDEK(t)); err != nil {
		t.Fatalf("WrapDEK after transient errors: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("encrypt attempts = %d, want 3", got)
	}
}

func TestDoesNotRetryPermanentClientErrors(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/destroyed-kek-kek-1":
			http.Error(w, `{"errors":["key not found"]}`, http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/encrypt/kek-kek-1":
			attempts.Add(1)
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	km := newFaultManager(t, server, openbaotransit.RetryPolicy{
		MaxAttempts:    3,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
	})
	_, err := km.WrapDEK(context.Background(), "kek-1", "key-1", faultDEK(t))
	if !errors.Is(err, keyring.ErrPermissionDenied) {
		t.Fatalf("WrapDEK error = %v, want ErrPermissionDenied", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("encrypt attempts = %d, want 1", got)
	}
}

func TestRateLimitIsRetriedAndTyped(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/destroyed-kek-kek-1":
			http.Error(w, `{"errors":["key not found"]}`, http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/encrypt/kek-kek-1":
			if attempts.Add(1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"errors":["rate limited"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v1:Zm9v","key_version":1}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	km := newFaultManager(t, server, openbaotransit.RetryPolicy{
		MaxAttempts:    2,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
	})
	if _, err := km.WrapDEK(context.Background(), "kek-1", "key-1", faultDEK(t)); err != nil {
		t.Fatalf("WrapDEK after 429: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("encrypt attempts = %d, want 2", got)
	}
}

func TestRotateIsNotAutomaticallyRetried(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/transit/keys/kek-kek-1/rotate" {
			attempts.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errors":["transaction commit failed"]}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	km := newFaultManager(t, server, openbaotransit.RetryPolicy{
		MaxAttempts:    3,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
	})
	_, err := km.RotateKEK(context.Background(), "kek-1")
	if !errors.Is(err, keyring.ErrTransient) {
		t.Fatalf("RotateKEK error = %v, want ErrTransient", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("rotate attempts = %d, want 1 (ambiguous mutation is not retried)", got)
	}
}

func TestTransientErrorReportsRetryAfter(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, `{"errors":["unavailable"]}`)
	}))
	t.Cleanup(server.Close)

	km := newFaultManager(t, server, openbaotransit.RetryPolicy{
		MaxAttempts:    1,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
	})
	_, err := km.RotateKEK(context.Background(), "kek-1")
	if !errors.Is(err, keyring.ErrTransient) {
		t.Fatalf("RotateKEK error = %v, want ErrTransient", err)
	}
	var retryAfter interface{ RetryAfter() time.Duration }
	if !errors.As(err, &retryAfter) {
		t.Fatalf("error %T does not expose RetryAfter", err)
	}
	if got := retryAfter.RetryAfter(); got != 2*time.Second {
		t.Fatalf("RetryAfter = %s, want 2s", got)
	}
}

func TestOversizedResponseIsRejected(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
	}))
	t.Cleanup(server.Close)

	km := newFaultManager(t, server, openbaotransit.RetryPolicy{MaxAttempts: 1})
	_, err := km.RotateKEK(context.Background(), "kek-1")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("RotateKEK(oversized response) = %v, want an exceeds error", err)
	}
}

func TestMalformedSuccessBodyIsNotRetried(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{"))
	}))
	t.Cleanup(server.Close)

	km := newFaultManager(t, server, openbaotransit.RetryPolicy{MaxAttempts: 3})
	if _, err := km.RotateKEK(context.Background(), "kek-1"); err == nil {
		t.Fatal("RotateKEK(malformed body) returned nil error")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1 (malformed 2xx is not retried)", got)
	}
}

func TestTokenHeaderIsSent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "test-token" {
			t.Errorf("X-Vault-Token = %q, want test-token", got)
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			http.Error(w, `{"errors":["key not found"]}`, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"latest_version":2}}`))
	}))
	t.Cleanup(server.Close)

	km := newFaultManager(t, server, openbaotransit.RetryPolicy{MaxAttempts: 1})
	if _, err := km.RotateKEK(context.Background(), "kek-1"); err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
}
