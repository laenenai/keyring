package openbaotransit_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/laenenai/keyring/keymanager/openbaotransit"
)

// This file is the OpenBao half of the harness CONVENTIONS.md describes for
// Postgres, in the same shape as cas/internal/testdb: a real server in a
// container, one per test binary run; a uniquely named, isolated instance for
// each test, created fresh and torn down afterwards, so tests run in parallel
// with no shared state and nothing to truncate between them; an environment
// override that uses an already-running server instead of starting a
// container; and a run-time skip under testing.Short(), never a build tag.
//
// The isolated instance here is a transit *mount* rather than a database. A
// mount is the unit of isolation OpenBao has that matches what a database is
// for Postgres: keys in one mount are invisible to another, a mount is
// created and destroyed by one API call, and destroying it destroys every key
// in it — which also means a test that destroys KEKs leaves nothing behind.
//
// It lives in a _test.go file in this package rather than in an internal
// package because this is its only consumer. Promoting it is the right move
// when there is a second one (and CONVENTIONS.md says where it would go);
// doing so in advance would add a package to the module's surface for nobody.

// Environment variables that point these tests at a real OpenBao, following
// CONVENTIONS.md's TEST_DATABASE_URL pattern: when they are set, no container
// is started and the tests run against that server, in their own mounts.
const (
	addressEnv = "TEST_OPENBAO_ADDR"
	// authEnv names the variable holding the OpenBao token. It is named for
	// what it is for rather than for the secret it points at, so that a
	// credential-scanning linter is not asked to tell a variable name from a
	// credential.
	authEnv = "TEST_OPENBAO_TOKEN"
)

// baoImage is the image CONVENTIONS.md pins for this module's transit
// adapter, and the one cas's dev stack already runs. It is pinned by digest
// so a retargeted tag cannot change what CI executed.
const baoImage = "openbao/openbao@sha256:62f582f85e405ef00d48f678c19863d096a2bc0c05e0e5a9bbccd676a1c7316c"

// devRootToken is the root token of the dev-mode server this harness starts.
// It is a test fixture for an ephemeral container that exists for the length
// of one test binary run, not a credential: a deployment's token comes from
// Config.Token, and a developer's from the environment override above.
//
// G101 is expected and is the finding working correctly — a literal named
// "token" is exactly what it should flag — so it is silenced here, where the
// value is the one place in this module that is deliberately not a secret,
// rather than by giving the constant a name that hides what it is.
const devRootToken = "keyring-test-root-token" //nolint:gosec

// containerStartupTimeout bounds the wait for the server to report healthy.
// It is generous because the first run on a machine may be pulling the image.
const containerStartupTimeout = 3 * time.Minute

// baoServer is a reachable OpenBao: either the container this harness started
// or the one an operator pointed it at.
type baoServer struct {
	address string
	token   string
}

var (
	serverOnce sync.Once
	server     baoServer
	serverErr  error
)

// transitMount returns a Config addressing a transit mount created for this
// test alone, and registers the unmount with t.Cleanup. Every call gets its
// own mount, so the conformance suite's per-subtest factory produces genuinely
// isolated state and subtests can run in parallel.
//
// It skips the test under testing.Short() before doing any container or
// network work, which is why `mise test` is a real no-container inner loop
// and `mise test-all` is the full suite. -short wins even when the
// environment override is set: a reachable server is not a reason to run,
// because the convention is "no external services in the inner loop", period.
func transitMount(t *testing.T) openbaotransit.Config {
	t.Helper()

	if testing.Short() {
		t.Skip("openbaotransit: skipping container-backed test in -short mode; run `mise run test-all` for the full suite")
	}

	srv := sharedServer(t)
	mount := "keyring-test-" + randomHex(t)

	ctx := context.Background()
	if err := srv.mount(ctx, mount); err != nil {
		t.Fatalf("openbaotransit: create the transit mount %s: %v", mount, err)
	}
	t.Cleanup(func() {
		// Best-effort, and logged rather than failed: a cleanup failure must
		// not mask the test's own result. Against the container it does not
		// matter at all — the container goes away — and against a long-lived
		// server it leaves one mount named after a test run.
		if err := srv.unmount(context.Background(), mount); err != nil {
			t.Logf("openbaotransit: cleanup: unmount %s: %v", mount, err)
		}
	})

	return openbaotransit.Config{Address: srv.address, Token: srv.token, MountPath: mount}
}

// sharedServer returns the OpenBao every test in this binary run uses: the
// server named by the environment when it is set, and otherwise a container
// started once per run (not once per test) and shared.
func sharedServer(t *testing.T) baoServer {
	t.Helper()

	serverOnce.Do(func() {
		if address := os.Getenv(addressEnv); address != "" {
			token := os.Getenv(authEnv)
			if token == "" {
				serverErr = fmt.Errorf("%s is set but %s is not", addressEnv, authEnv)
				return
			}
			server = baoServer{address: address, token: token}
			return
		}
		server, serverErr = startContainer(context.Background())
	})
	if serverErr != nil {
		t.Fatalf("openbaotransit: start an OpenBao to test against: %v", serverErr)
	}
	return server
}

// startContainer runs OpenBao in dev mode and returns its address. Dev mode
// is the right choice for a test server and only for a test server: it is
// unsealed, in-memory and has a known root token, so a test needs no unseal
// ceremony, and nothing it holds outlives the run.
func startContainer(ctx context.Context) (baoServer, error) {
	container, err := testcontainers.Run(ctx, baoImage,
		testcontainers.WithExposedPorts("8200/tcp"),
		testcontainers.WithCmd("server", "-dev"),
		testcontainers.WithEnv(map[string]string{
			"BAO_DEV_ROOT_TOKEN_ID":  devRootToken,
			"BAO_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
		}),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/v1/sys/health").
				WithPort("8200/tcp").
				WithStartupTimeout(containerStartupTimeout),
		),
	)
	if err != nil {
		return baoServer{}, fmt.Errorf("run %s: %w", baoImage, err)
	}

	address, err := container.PortEndpoint(ctx, "8200/tcp", "http")
	if err != nil {
		return baoServer{}, fmt.Errorf("container endpoint: %w", err)
	}
	// The container is shared across the whole binary run, so there is no
	// test whose Cleanup could own it; testcontainers' reaper removes it when
	// the run ends. This is the same arrangement cas/internal/testdb has.
	return baoServer{address: address, token: devRootToken}, nil
}

// mount enables a transit engine at path.
func (s baoServer) mount(ctx context.Context, path string) error {
	return s.do(ctx, http.MethodPost, "sys/mounts/"+path, map[string]string{"type": "transit"})
}

// unmount disables the engine at path, destroying every key in it.
func (s baoServer) unmount(ctx context.Context, path string) error {
	return s.do(ctx, http.MethodDelete, "sys/mounts/"+path, nil)
}

// do performs one administrative request with the standard library, which is
// all this harness needs and keeps the adapter's own no-SDK rule true of its
// tests as well.
func (s baoServer) do(ctx context.Context, method, path string, body any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode a %s request: %w", method, err)
		}
		reader = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.address, "/")+"/v1/"+path, reader)
	if err != nil {
		return fmt.Errorf("build a %s request: %w", method, err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

// randomHex returns 16 hex characters of cryptographically random text, so
// two mounts never collide — including two runs against the same long-lived
// server.
func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random bytes for a mount name: %v", err)
	}
	return hex.EncodeToString(b)
}
