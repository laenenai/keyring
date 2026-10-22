package externalkms_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/laenen-ai/keyring"
	"github.com/laenen-ai/keyring/keymanager/externalkms"
	"github.com/laenen-ai/keyring/keyringtest"
)

// Environment variables that point this adapter's conformance run at a real
// external KMS. There is no container for a cloud KMS, so unlike the
// openbao-transit adapter this one will always need an operator to supply a
// key: a provider's own emulator is not the thing whose behavior this
// adapter exists to be correct about.
const (
	providerEnv = "TEST_EXTERNAL_KMS_PROVIDER"
	keyURIEnv   = "TEST_EXTERNAL_KMS_KEY_URI"
)

// TestExternalKMSConformance is wired to the shared suite now so that
// implementing a provider is a matter of turning a skip into a green run.
// It skips under -short because it needs a network-reachable key manager,
// which is a run-time skip and never a build tag (CONVENTIONS.md).
func TestExternalKMSConformance(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("external-kms needs a network-reachable key manager; skipped in -short")
	}

	keyringtest.RunKeyManagerSuite(t, func(t *testing.T) keyring.KeyManager {
		km, err := externalkms.Open(context.Background(), externalkms.Config{
			Provider: os.Getenv(providerEnv),
			KeyURI:   os.Getenv(keyURIEnv),
		})
		if errors.Is(err, keyring.ErrNotImplemented) {
			t.Skipf("external-kms transport is not implemented in this increment; "+
				"the suite is wired and will run once it is (set %s and %s then)", providerEnv, keyURIEnv)
		}
		if err != nil {
			t.Fatalf("externalkms.Open: %v", err)
		}
		return km
	})
}

// TestOpenReportsNotImplemented runs in -short: the stub's contract is that
// a deployment wiring this adapter fails at startup with a sentinel it can
// recognize, rather than starting and failing at its first wrap.
func TestOpenReportsNotImplemented(t *testing.T) {
	t.Parallel()

	km, err := externalkms.Open(context.Background(), externalkms.Config{
		Provider: "aws-kms",
		KeyURI:   "arn:aws:kms:eu-west-1:000000000000:key/00000000-0000-0000-0000-000000000000",
	})
	if !errors.Is(err, keyring.ErrNotImplemented) {
		t.Fatalf("Open error = %v, want ErrNotImplemented", err)
	}
	if km != nil {
		t.Fatal("Open returned a key manager alongside its error")
	}
}
