package openbaotransit_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/laenenai/keyring"
	"github.com/laenenai/keyring/keymanager/openbaotransit"
	"github.com/laenenai/keyring/keyringtest"
)

// TestOpenBaoTransitConformance is the authoritative test for this adapter,
// and the test that says the port's shape was right: the shared suite,
// unchanged, against the real openbao/openbao:2.2.1. Every subtest gets its
// own transit mount, so the state each one sees is its own.
//
// It is also the only test here that proves anything about the properties
// this adapter exists for. An in-memory fake would prove the contract and
// nothing about the enforcement: that a destroyed key is destroyed by the
// server rather than by this process declining to use it, that transit's own
// version numbering lines up with domain.KEKVersion, that a derived key
// really does bind a record to its key id. CONVENTIONS.md requires the real
// image for exactly this reason.
func TestOpenBaoTransitConformance(t *testing.T) {
	t.Parallel()

	keyringtest.RunKeyManagerSuite(t, func(t *testing.T) keyring.KeyManager {
		km, err := openbaotransit.Open(context.Background(), transitMount(t))
		if err != nil {
			t.Fatalf("openbaotransit.Open: %v", err)
		}
		return km
	})
}

// TestTombstonedKEKCannotBeUsed puts the adapter into the state DestroyKEK
// can leave after a crash (tombstone present, key material still present) and
// asserts every operation fails closed. Without this, a partial destroy leaves
// a KEK that reports destruction on writes while reads still return DEKs.
func TestTombstonedKEKCannotBeUsed(t *testing.T) {
	t.Parallel()

	fake := newFakeTransit()
	srv := fake.server(t)
	km := fake.keyManager(t, srv)

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	fake.plaintext = bytes.Clone(dek.Bytes())

	record := keyring.WrappedDEK{
		KEKID:      "victim",
		KEKVersion: 1,
		KeyID:      "key-1",
		Ciphertext: []byte("vault:v1:AAAA"),
	}
	fake.markDestroyed("victim", true)

	calls := map[string]func() error{
		"UnwrapDEK": func() error {
			got, err := km.UnwrapDEK(context.Background(), record)
			if !got.IsZero() {
				return fmt.Errorf("UnwrapDEK returned key material: %w", err)
			}
			return err
		},
		"RewrapDEK": func() error {
			got, err := km.RewrapDEK(context.Background(), record)
			if len(got.Ciphertext) != 0 {
				return fmt.Errorf("RewrapDEK returned a record: %w", err)
			}
			return err
		},
		"RotateKEK": func() error {
			_, err := km.RotateKEK(context.Background(), "victim")
			return err
		},
		"WrapDEK": func() error {
			_, err := km.WrapDEK(context.Background(), "victim", "key-1", dek)
			return err
		},
		"GenerateDEK": func() error {
			_, _, err := km.GenerateDEK(context.Background(), "victim", "key-1")
			return err
		},
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, keyring.ErrKEKDestroyed) {
			t.Errorf("%s with a tombstone present error = %v, want ErrKEKDestroyed", name, err)
		}
	}
}

// TestWrapRaceWithDestroyFailsClosed simulates DestroyKEK completing between
// the tombstone check and the encrypt/datakey call. The adapter must re-check
// the tombstone after the call and fail rather than return a record under a
// resurrected key.
func TestWrapRaceWithDestroyFailsClosed(t *testing.T) {
	t.Parallel()

	fake := newFakeTransit()
	srv := fake.server(t)
	km := fake.keyManager(t, srv)
	fake.markDestroyOnEncrypt("victim")

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	if _, err := km.WrapDEK(context.Background(), "victim", "key-1", dek); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Errorf("WrapDEK racing DestroyKEK error = %v, want ErrKEKDestroyed", err)
	}
	if _, _, err := km.GenerateDEK(context.Background(), "victim", "key-1"); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Errorf("GenerateDEK racing DestroyKEK error = %v, want ErrKEKDestroyed", err)
	}
}

// TestRewrapNeverPutsTheDEKOnTheWire is the one assertion the generic suite
// cannot make, and the reason RewrapDEK is a port method rather than sugar
// for unwrap-then-wrap: on the rewrap path the DEK must not appear in any
// request this adapter sends or any response it receives. The suite can see
// that RewrapDEK returns no DEK; only a test holding the wire can see that
// none crossed it.
//
// It asserts three things about the recorded exchange, in increasing
// strength: no request or response body contains the key material in any
// encoding a leak would plausibly take; no response carries a "plaintext"
// field at all; and nothing on the path calls transit's decrypt endpoint —
// which is what makes "a rotation sweep's token needs rewrap and not decrypt"
// a fact about this code rather than an intention.
func TestRewrapNeverPutsTheDEKOnTheWire(t *testing.T) {
	t.Parallel()

	cfg := transitMount(t)
	recorder := &recordingTransport{}
	cfg.HTTPClient = &http.Client{Transport: recorder}

	ctx := context.Background()
	km, err := openbaotransit.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("openbaotransit.Open: %v", err)
	}

	kekID, keyID := keyring.KEKID("rewrap-wire-kek"), keyring.KeyID("rewrap-wire-key")

	// Generated rather than caller-minted, so the material has already been
	// on the wire once — in the datakey response — and a leak on the rewrap
	// path cannot be excused as "it was never there to begin with".
	dek, record, err := km.GenerateDEK(ctx, kekID, keyID)
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	material := bytes.Clone(dek.Bytes())

	if _, err := km.RotateKEK(ctx, kekID); err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}

	// Everything up to here is setup, and the datakey response legitimately
	// carried the DEK. From this point the recording is the rewrap path and
	// nothing else.
	recorder.reset()
	rewrapped, err := km.RewrapDEK(ctx, record)
	if err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}
	exchanges := recorder.recorded()

	if len(exchanges) == 0 {
		t.Fatal("RewrapDEK made no requests, so there is no wire traffic to inspect")
	}
	for _, exchange := range exchanges {
		if strings.Contains(exchange.path, "/decrypt/") {
			t.Errorf("the rewrap path called %s: RewrapDEK must not be unwrap-then-wrap", exchange.path)
		}
		assertNoMaterial(t, "request body of "+exchange.path, exchange.request, material)
		assertNoMaterial(t, "response body of "+exchange.path, exchange.response, material)
		if bytes.Contains(exchange.response, []byte(`"plaintext"`)) {
			t.Errorf("the response to %s carries a plaintext field; transit's rewrap must not return one", exchange.path)
		}
	}

	// And the re-wrap did its job, which is what makes the absence above
	// meaningful rather than the result of nothing having happened.
	if rewrapped.KEKVersion <= record.KEKVersion {
		t.Fatalf("RewrapDEK recorded %s, want newer than %s", rewrapped.KEKVersion, record.KEKVersion)
	}
	got, err := km.UnwrapDEK(ctx, rewrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK of the rewrapped record: %v", err)
	}
	t.Cleanup(got.Destroy)
	if !bytes.Equal(got.Bytes(), material) {
		t.Fatal("the rewrapped record unwrapped to different key material")
	}
}

// TestDestroyKEKDeletesTheKeyServerSide is the adapter-specific half of
// crypto-shredding, matching what local_test.go asserts about its store: the
// suite proves a destroyed KEK's DEKs no longer unwrap, and this proves the
// reason is that the material is gone from OpenBao rather than that this
// process is declining to ask for it. A fresh key manager — a restarted
// deployment — must still see the destruction.
func TestDestroyKEKDeletesTheKeyServerSide(t *testing.T) {
	t.Parallel()

	cfg := transitMount(t)
	ctx := context.Background()
	km, err := openbaotransit.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("openbaotransit.Open: %v", err)
	}

	kekID, keyID := keyring.KEKID("doomed"), keyring.KeyID("key-1")
	dek, record, err := km.GenerateDEK(ctx, kekID, keyID)
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	if err := km.DestroyKEK(ctx, kekID); err != nil {
		t.Fatalf("DestroyKEK: %v", err)
	}

	// The key is gone from the server, not merely refused by this manager.
	if status, body := readKey(t, cfg, openbaotransit.KeyNamePrefix+string(kekID)); status != http.StatusNotFound {
		t.Errorf("reading the destroyed key returned HTTP %d (%s), want 404: the material was not deleted", status, body)
	}
	// And the destruction record is there, which is what keeps "destroyed"
	// from looking like "never existed" once the key itself is gone.
	if status, body := readKey(t, cfg, openbaotransit.TombstoneNamePrefix+string(kekID)); status != http.StatusOK {
		t.Errorf("reading the destruction record returned HTTP %d (%s), want 200", status, body)
	}

	restarted, err := openbaotransit.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("openbaotransit.Open (restart): %v", err)
	}
	if _, err := restarted.UnwrapDEK(ctx, record); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Errorf("UnwrapDEK after a restart error = %v, want ErrKEKDestroyed (erasure must survive a restart)", err)
	}
	if _, err := restarted.WrapDEK(ctx, kekID, keyID, dek); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Errorf("WrapDEK after a restart error = %v, want ErrKEKDestroyed (a shredded KEK is never resurrected)", err)
	}
	if _, _, err := restarted.GenerateDEK(ctx, kekID, keyID); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Errorf("GenerateDEK after a restart error = %v, want ErrKEKDestroyed", err)
	}
}

// TestKEKsAreDerivedKeys pins the mechanism that binds a record to its key
// id. It is adapter-specific because it is a statement about transit's key
// configuration rather than about the port: the suite asserts that a record
// moved to another key id fails to unwrap, and this says the reason is
// derivation rather than something this adapter could later stop doing while
// still passing the suite.
func TestKEKsAreDerivedKeys(t *testing.T) {
	t.Parallel()

	cfg := transitMount(t)
	ctx := context.Background()
	km, err := openbaotransit.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("openbaotransit.Open: %v", err)
	}

	dek, _, err := km.GenerateDEK(ctx, "derived", "key-1")
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	status, body := readKey(t, cfg, openbaotransit.KeyNamePrefix+"derived")
	if status != http.StatusOK {
		t.Fatalf("reading the key returned HTTP %d (%s)", status, body)
	}
	compact := strings.ReplaceAll(body, " ", "")
	for _, want := range []string{`"derived":true`, `"type":"aes256-gcm96"`} {
		if !strings.Contains(compact, want) {
			t.Errorf("the key's configuration does not contain %s: %s", want, body)
		}
	}
}

// TestOpenRejectsUnusableConfig runs in -short: a deployment that
// misconfigures this adapter must fail at startup, with a sentinel it can
// recognize.
func TestOpenRejectsUnusableConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  openbaotransit.Config
	}{
		{"no_address", openbaotransit.Config{Token: "t"}},
		{"blank_address", openbaotransit.Config{Address: "   ", Token: "t"}},
		{"relative_address", openbaotransit.Config{Address: "openbao.internal:8200", Token: "t"}},
		{"unsupported_scheme", openbaotransit.Config{Address: "unix:///run/openbao.sock", Token: "t"}},
		{"no_host", openbaotransit.Config{Address: "https://", Token: "t"}},
		{"no_token", openbaotransit.Config{Address: "https://openbao.invalid:8200"}},
		{
			"relative_mount_path",
			openbaotransit.Config{Address: "https://openbao.invalid:8200", Token: "t", MountPath: "transit/../sys"},
		},
		{
			"empty_mount_segment",
			openbaotransit.Config{Address: "https://openbao.invalid:8200", Token: "t", MountPath: "a//b"},
		},
		{
			"userinfo_in_address",
			openbaotransit.Config{Address: "https://user:pass@openbao.invalid:8200", Token: "t"}, //nolint:gosec // test fixture for userinfo rejection
		},
		{
			"path_in_address",
			openbaotransit.Config{Address: "https://openbao.invalid:8200/v1", Token: "t"},
		},
		{
			"query_in_address",
			openbaotransit.Config{Address: "https://openbao.invalid:8200?x=1", Token: "t"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km, err := openbaotransit.Open(context.Background(), tc.cfg)
			if !errors.Is(err, keyring.ErrInvalidConfig) {
				t.Fatalf("Open(%s) error = %v, want ErrInvalidConfig", tc.name, err)
			}
			if km != nil {
				t.Fatal("Open returned a key manager alongside its error")
			}
		})
	}
}

// TestOpenRejectsPlainHTTPToNonLoopback: a token and DEK plaintext must not
// travel over cleartext to a remote host. Loopback HTTP is allowed because it
// is the normal local-dev/test case and does not cross a network boundary.
func TestOpenRejectsPlainHTTPToNonLoopback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		address string
		allow   bool
		wantErr bool
	}{
		{"non_loopback_http", "http://192.0.2.1:8200", false, true},
		{"non_loopback_http_allowed", "http://192.0.2.1:8200", true, false},
		{"loopback_http", "http://127.0.0.1:8200", false, false},
		{"loopback_http_v6", "http://[::1]:8200", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			km, err := openbaotransit.Open(context.Background(), openbaotransit.Config{
				Address:           tc.address,
				Token:             "t",
				AllowInsecureHTTP: tc.allow,
			})
			if tc.wantErr {
				if !errors.Is(err, keyring.ErrInvalidConfig) {
					t.Fatalf("Open(%s) error = %v, want ErrInvalidConfig", tc.name, err)
				}
				if km != nil {
					t.Fatal("Open returned a key manager alongside its error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Open(%s): %v", tc.name, err)
			}
		})
	}
}

// TestRedirectIsNotFollowed: a redirect must not receive the X-Vault-Token
// header (and, for WrapDEK, the plaintext DEK in the replayed body). The
// adapter must refuse redirects rather than trusting the endpoint to stay on
// the same origin.
func TestRedirectIsNotFollowed(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"ciphertext":"vault:v1:AAAA","plaintext":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","key_version":1}}`)
	}))
	defer collector.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/keys/destroyed-kek-") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"errors":["key not found"]}`)
			return
		}
		http.Redirect(w, r, collector.URL+r.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // deliberately testing redirect refusal
	}))
	defer source.Close()

	km, err := openbaotransit.Open(context.Background(), openbaotransit.Config{
		Address: source.URL,
		Token:   "s.super-secret-token",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	if _, _, err := km.GenerateDEK(context.Background(), "victim", "key-1"); err == nil {
		t.Fatal("GenerateDEK followed a redirect; want a refused redirect error")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("redirect target received %d request(s); the token/body must not be forwarded", got)
	}
}

// TestConfigRedactsTheToken: the token is the one secret this adapter's
// configuration holds, and a configuration struct is the thing most likely to
// be logged wholesale at startup.
func TestConfigRedactsTheToken(t *testing.T) {
	t.Parallel()

	const token = "s.a-very-secret-openbao-token"
	cfg := openbaotransit.Config{Address: "https://openbao.invalid:8200", Token: token, MountPath: "transit"}

	for _, rendering := range []string{cfg.String(), cfg.LogValue().String()} {
		if strings.Contains(rendering, token) {
			t.Errorf("a Config rendering leaked the token: %s", rendering)
		}
		if !strings.Contains(rendering, keyring.Redacted) {
			t.Errorf("a Config rendering does not say it redacted anything: %s", rendering)
		}
	}

	// String and LogValue were what this test checked, and they were not
	// enough: %#v, %d and %c reflected the struct and printed the token, and
	// json.Marshal reached Token through its exported field. The named
	// subtest covers every rendering rather than the two a reader thinks of.
	keyringtest.NoSecretLeaksInAnyRendering(t, cfg, []byte(token))
}

// TestConfigDoesNotLeakTheTokenThroughXMLOrGob: XML and gob do not consult
// MarshalJSON/String/LogValue, so a Config with an exported Token field must
// implement their interfaces too.
func TestConfigDoesNotLeakTheTokenThroughXMLOrGob(t *testing.T) {
	t.Parallel()

	const token = "s.a-very-secret-openbao-token"
	cfg := openbaotransit.Config{Address: "https://openbao.invalid:8200", Token: token, MountPath: "transit"}

	x, err := xml.Marshal(cfg)
	if err != nil {
		t.Fatalf("xml.Marshal: %v", err)
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(cfg); err != nil {
		t.Fatalf("gob.Encode: %v", err)
	}

	for name, rendering := range map[string]string{
		"xml": string(x),
		"gob": buf.String(),
	} {
		if strings.Contains(rendering, token) {
			t.Errorf("%s leaked the OpenBao token: %q", name, rendering)
		}
		if !strings.Contains(rendering, keyring.Redacted) {
			t.Errorf("%s does not contain a redaction marker: %q", name, rendering)
		}
	}
}

// TestKeyManagerRedactsTheTokenInEveryRendering covers the value Open hands
// back, not just the config it was given: a *KeyManager retains the token as
// the X-Vault-Token header value, and it is in scope wherever the error
// handling around Open is.
func TestKeyManagerRedactsTheTokenInEveryRendering(t *testing.T) {
	t.Parallel()

	const token = "s.another-very-secret-openbao-token"
	km, err := openbaotransit.Open(context.Background(), openbaotransit.Config{
		Address:   "https://openbao.invalid:8200",
		Token:     token,
		MountPath: "transit",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	keyringtest.NoSecretLeaksInAnyRendering(t, km, []byte(token))

	// The pointer is the common case, but a caller can dereference or copy a
	// manager. The four redaction interfaces must be in the value method set
	// too, or fmt reflects the unexported token.
	for name, rendering := range map[string]string{
		"value %v":  fmt.Sprintf("%v", *km),
		"value %+v": fmt.Sprintf("%+v", *km),
		"value %#v": fmt.Sprintf("%#v", *km),
	} {
		if strings.Contains(rendering, token) {
			t.Errorf("%s leaked the OpenBao token: %s", name, rendering)
		}
		if !strings.Contains(rendering, keyring.Redacted) {
			t.Errorf("%s does not contain a redaction marker: %s", name, rendering)
		}
	}
}

// TestRecordVersionMismatchIsRejectedWithoutTheServer runs in -short, and
// that is the point: a record whose claimed KEK version disagrees with the
// version its transit ciphertext names must be refused here, before anything
// is sent. If the check were left to the server, the server would decrypt
// under the version the bytes name and the record's claim would be
// decorative. The address points at a port nothing listens on, so a request
// would surface as a connection error rather than as ErrUnwrapFailed.
func TestRecordVersionMismatchIsRejectedWithoutTheServer(t *testing.T) {
	t.Parallel()

	km := unreachableKeyManager(t)
	cases := []struct {
		name   string
		record keyring.WrappedDEK
	}{
		{
			"version_disagrees_with_the_ciphertext",
			keyring.WrappedDEK{KEKID: "k", KEKVersion: 2, KeyID: "key", Ciphertext: []byte("vault:v1:Zm9v")},
		},
		{
			"not_a_transit_ciphertext",
			keyring.WrappedDEK{KEKID: "k", KEKVersion: 1, KeyID: "key", Ciphertext: []byte("just-some-bytes")},
		},
		{
			"no_version_field",
			keyring.WrappedDEK{KEKID: "k", KEKVersion: 1, KeyID: "key", Ciphertext: []byte("vault:Zm9v")},
		},
		{
			"non_ascii_ciphertext",
			keyring.WrappedDEK{KEKID: "k", KEKVersion: 1, KeyID: "key", Ciphertext: []byte{0xF6, 'a', 'u', 'l', 't'}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			if got, err := km.UnwrapDEK(ctx, tc.record); !errors.Is(err, keyring.ErrUnwrapFailed) {
				t.Errorf("UnwrapDEK(%s) error = %v, want ErrUnwrapFailed", tc.name, err)
			} else if !got.IsZero() {
				t.Error("UnwrapDEK returned key material alongside its error")
			}
			if _, err := km.RewrapDEK(ctx, tc.record); !errors.Is(err, keyring.ErrUnwrapFailed) {
				t.Errorf("RewrapDEK(%s) error = %v, want ErrUnwrapFailed", tc.name, err)
			}
		})
	}
}

// TestCancelledContextNeedsNoServer runs in -short: every method must honor a
// cancelled context, and must do so without a round trip.
func TestCancelledContextNeedsNoServer(t *testing.T) {
	t.Parallel()

	km := unreachableKeyManager(t)
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	record := keyring.WrappedDEK{KEKID: "k", KEKVersion: 1, KeyID: "key", Ciphertext: []byte("vault:v1:Zm9v")}
	calls := map[string]func() error{
		"WrapDEK":     func() error { _, err := km.WrapDEK(ctx, "k", "key", dek); return err },
		"GenerateDEK": func() error { _, _, err := km.GenerateDEK(ctx, "k", "key"); return err },
		"UnwrapDEK":   func() error { _, err := km.UnwrapDEK(ctx, record); return err },
		"RewrapDEK":   func() error { _, err := km.RewrapDEK(ctx, record); return err },
		"RotateKEK":   func() error { _, err := km.RotateKEK(ctx, "k"); return err },
		"DestroyKEK":  func() error { return km.DestroyKEK(ctx, "k") },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Errorf("%s with a cancelled context: error = %v, want context.Canceled", name, err)
		}
	}
}

// unreachableKeyManager returns a key manager pointed at a port nothing
// listens on, for the assertions that must hold before any request is made.
func unreachableKeyManager(t *testing.T) keyring.KeyManager {
	t.Helper()
	km, err := openbaotransit.Open(context.Background(), openbaotransit.Config{
		Address: "http://127.0.0.1:1",
		Token:   "unused",
	})
	if err != nil {
		t.Fatalf("openbaotransit.Open: %v", err)
	}
	return km
}

// readKey reads one transit key's configuration straight from the server,
// bypassing the adapter, and returns the status and body. It is how a test
// asserts what is actually stored rather than what the adapter says is.
func readKey(t *testing.T, cfg openbaotransit.Config, name string) (int, string) {
	t.Helper()

	target := strings.TrimSuffix(cfg.Address, "/") + "/v1/" + cfg.MountPath + "/keys/" + name
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("build a key-read request: %v", err)
	}
	req.Header.Set("X-Vault-Token", cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("read the key %s: %v", name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read the response for key %s: %v", name, err)
	}
	return resp.StatusCode, string(body)
}

// exchange is one request/response pair recorded off the wire.
type exchange struct {
	path     string
	request  []byte
	response []byte
}

// recordingTransport captures every request and response body an http.Client
// sends through it, so a test can assert on what actually crossed the wire
// rather than on what the adapter returned.
type recordingTransport struct {
	mu        sync.Mutex
	exchanges []exchange
}

// RoundTrip implements http.RoundTripper.
func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var requestBody []byte
	if req.Body != nil {
		var err error
		requestBody, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(requestBody))
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	responseBody, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	resp.Body = io.NopCloser(bytes.NewReader(responseBody))

	r.mu.Lock()
	r.exchanges = append(r.exchanges, exchange{
		path:     req.URL.Path,
		request:  requestBody,
		response: responseBody,
	})
	r.mu.Unlock()
	return resp, nil
}

// reset forgets everything recorded so far.
func (r *recordingTransport) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exchanges = nil
}

// recorded returns the exchanges captured since the last reset.
func (r *recordingTransport) recorded() []exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]exchange(nil), r.exchanges...)
}

// assertNoMaterial fails if text contains material in any encoding a leak
// would plausibly take. It mirrors the suite's own canary, which is not
// exported, because the thing under test here is bytes on a wire rather than
// an error string.
func assertNoMaterial(t *testing.T, label string, text, material []byte) {
	t.Helper()
	if len(material) == 0 {
		t.Fatal("assertNoMaterial called with no material, which would assert nothing")
	}
	encodings := map[string]string{
		"raw bytes":      string(material),
		"lower hex":      hex.EncodeToString(material),
		"upper hex":      strings.ToUpper(hex.EncodeToString(material)),
		"base64 std":     base64.StdEncoding.EncodeToString(material),
		"base64 raw std": base64.RawStdEncoding.EncodeToString(material),
		"base64 url":     base64.URLEncoding.EncodeToString(material),
		"base64 raw url": base64.RawURLEncoding.EncodeToString(material),
	}
	for name, encoded := range encodings {
		if bytes.Contains(text, []byte(encoded)) {
			t.Errorf("%s leaked key material as %s", label, name)
		}
	}
}

func TestWrongAdapterFormatIsRejectedWithoutTheServer(t *testing.T) {
	t.Parallel()

	km := unreachableKeyManager(t)
	record := keyring.WrappedDEK{
		KEKID:      "k",
		KEKVersion: keyring.FirstKEKVersion,
		KeyID:      "key",
		Format:     keyring.WrappedDEKFormatLocal,
		Ciphertext: []byte("vault:v1:Zm9v"),
	}
	if _, err := km.UnwrapDEK(context.Background(), record); !errors.Is(err, keyring.ErrInvalidWrappedDEK) {
		t.Fatalf("UnwrapDEK(wrong format) = %v, want ErrInvalidWrappedDEK", err)
	}
	if _, err := km.RewrapDEK(context.Background(), record); !errors.Is(err, keyring.ErrInvalidWrappedDEK) {
		t.Fatalf("RewrapDEK(wrong format) = %v, want ErrInvalidWrappedDEK", err)
	}
}

func TestCloseRejectsFurtherUseAndIsIdempotent(t *testing.T) {
	t.Parallel()

	km := unreachableKeyManager(t)
	closer, ok := km.(interface{ Close() error })
	if !ok {
		t.Fatal("openbaotransit.KeyManager does not implement Close")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := km.RotateKEK(context.Background(), "kek-closed"); !errors.Is(err, keyring.ErrClosed) {
		t.Fatalf("RotateKEK after Close = %v, want ErrClosed", err)
	}
}
