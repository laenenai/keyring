package openbaotransit_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/laenen-ai/keyring"
	"github.com/laenen-ai/keyring/keymanager/openbaotransit"
	"github.com/laenen-ai/keyring/keyringtest"
)

// Environment variables that point this adapter's conformance run at a real
// OpenBao, following CONVENTIONS.md's TEST_DATABASE_URL pattern: when they
// are set, no container is started and the suite runs against that server.
const (
	addressEnv = "TEST_OPENBAO_ADDR"
	// authEnv names the variable holding the OpenBao token. It is named
	// for what it is for rather than for the secret it points at, so that
	// a credential-scanning linter is not asked to tell a variable name
	// from a credential.
	authEnv = "TEST_OPENBAO_TOKEN"
)

// TestOpenBaoTransitConformance is wired to the shared suite now so that
// implementing the transport is a matter of turning a skip into a green run
// rather than of writing a test suite.
//
// It skips under -short because it needs a network-reachable OpenBao, which
// is a run-time skip and never a build tag (CONVENTIONS.md). Outside -short
// it skips too, for as long as Open reports that the transport is not
// implemented; the increment that adds the transport also adds the
// testcontainers harness against openbao/openbao:2.2.1 that makes this run
// without an operator setting anything.
func TestOpenBaoTransitConformance(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("openbao-transit needs a network-reachable OpenBao; skipped in -short")
	}

	keyringtest.RunKeyManagerSuite(t, func(t *testing.T) keyring.KeyManager {
		km, err := openbaotransit.Open(context.Background(), openbaotransit.Config{
			Address: os.Getenv(addressEnv),
			Token:   os.Getenv(authEnv),
		})
		if errors.Is(err, keyring.ErrNotImplemented) {
			t.Skipf("openbao-transit transport is not implemented in this increment; "+
				"the suite is wired and will run once it is (set %s and %s then)", addressEnv, authEnv)
		}
		if err != nil {
			t.Fatalf("openbaotransit.Open: %v", err)
		}
		return km
	})
}

// TestOpenReportsNotImplemented runs in -short: the stub's contract is that
// a deployment wiring this adapter fails at startup with a sentinel it can
// recognize, rather than starting and failing at its first wrap.
func TestOpenReportsNotImplemented(t *testing.T) {
	t.Parallel()

	km, err := openbaotransit.Open(context.Background(), openbaotransit.Config{
		Address: "https://openbao.invalid:8200",
		Token:   "not-a-real-token",
	})
	if !errors.Is(err, keyring.ErrNotImplemented) {
		t.Fatalf("Open error = %v, want ErrNotImplemented", err)
	}
	if km != nil {
		t.Fatal("Open returned a key manager alongside its error")
	}
}
