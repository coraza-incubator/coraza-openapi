// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
// Package coraza_e2e loads the rules produced by `coraza-openapi generate`
// into a real Coraza WAF instance wired as HTTP middleware, and asserts that
// a curated set of requests gets the status codes the rules intend to
// produce. This is the final correctness gate for the generator.
package coraza_e2e

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	coraza "github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

// Any UUID-shaped value, used to exercise the path regex generated from the
// spec's `petId: {format: uuid}` declaration.
const validUUID = "11111111-2222-3333-4444-555555555555"

// corazaPreamble pulls in Coraza's recommended engine config and the
// stock crs-setup.conf (both shipped inside the coraza-coreruleset Go
// module). The example setup file keeps the anomaly-score knobs commented
// out by design (operators uncomment what they want) — we activate the
// standard CRS defaults ourselves so crs-plugin rules have something to
// contribute to. SecRuleEngine defaults to DetectionOnly in the
// recommended config; flip it On for the matrix.
const corazaPreamble = `
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecRuleEngine On
SecAction \
    "id:800000,phase:1,pass,nolog,t:none,\
    setvar:'tx.blocking_paranoia_level=1',\
    setvar:'tx.detection_paranoia_level=1',\
    setvar:'tx.critical_anomaly_score=5',\
    setvar:'tx.error_anomaly_score=4',\
    setvar:'tx.warning_anomaly_score=3',\
    setvar:'tx.notice_anomaly_score=2',\
    setvar:'tx.inbound_anomaly_score_threshold=5',\
    setvar:'tx.outbound_anomaly_score_threshold=4',\
    setvar:'tx.inbound_anomaly_score_pl1=0'"
`

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

// buildOnce makes sure the core + CLI are compiled. Called from TestMain so
// we don't pay the cost once per sub-test.
func buildOnce() error {
	root, err := filepath.Abs("../..")
	if err != nil {
		return err
	}
	for _, target := range []string{"build:core", "build:cli"} {
		c := exec.Command("npm", "run", target)
		c.Dir = root
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return err
		}
	}
	return nil
}

func TestMain(m *testing.M) {
	if err := buildOnce(); err != nil {
		fmt.Fprintln(os.Stderr, "build failed:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// generate runs the CLI with the given extra flags against the bundled
// Petstore spec and returns the rule text.
func generatePetstoreRules(t *testing.T, extraFlags ...string) string {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "openapi.conf")
	args := []string{
		filepath.Join(root, "packages/cli/dist/bin.js"),
		"generate",
		filepath.Join(root, "packages/core/src/samples/petstore.yaml"),
		// httptest.NewServer listens on 127.0.0.1:<random>; extend the allowed
		// hosts so the hostname rule passes for both that and the spec host.
		"--host", "petstore.example.com,127.0.0.1",
		"-o", out,
	}
	args = append(args, extraFlags...)
	gen := exec.Command("node", args...)
	gen.Stderr = os.Stderr
	if err := gen.Run(); err != nil {
		t.Fatalf("generate %v: %v", extraFlags, err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated rules: %v", err)
	}
	return string(b)
}

// newServer wires Coraza as an http.Handler middleware in front of an
// always-200 backend so that any non-200 we observe is the WAF's verdict.
func newServer(t *testing.T, rules string) *httptest.Server {
	t.Helper()
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(corazaPreamble + "\n" + rules),
	)
	if err != nil {
		t.Fatalf("coraza.NewWAF: %v\n--- rules ---\n%s", err, rules)
	}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	return httptest.NewServer(txhttp.WrapHandler(waf, backend))
}

type tc struct {
	name    string
	method  string
	path    string
	host    string            // optional override; defaults to petstore.example.com
	headers map[string]string // sent as-is
	body    string
	ctype   string
	want    int
}

// TestPetstoreStandaloneBlock is the baseline "standalone-block" config —
// every violation denies with its natural status code.
func TestPetstoreStandaloneBlock(t *testing.T) {
	rules := generatePetstoreRules(t)
	srv := newServer(t, rules)
	defer srv.Close()

	cases := []tc{
		{
			name:    "declared op passes (listPets)",
			method:  "GET",
			path:    "/pets?status=available",
			headers: map[string]string{"X-API-Key": "topsecret"},
			want:    http.StatusOK,
		},
		{
			name:    "wrong Host is rejected (403)",
			method:  "GET",
			path:    "/pets?status=available",
			host:    "evil.com",
			headers: map[string]string{"X-API-Key": "topsecret"},
			want:    http.StatusForbidden,
		},
		{
			name:    "missing required query param (400)",
			method:  "GET",
			path:    "/pets",
			headers: map[string]string{"X-API-Key": "topsecret"},
			want:    http.StatusBadRequest,
		},
		{
			name:    "invalid enum value on status (400)",
			method:  "GET",
			path:    "/pets?status=wrong",
			headers: map[string]string{"X-API-Key": "topsecret"},
			want:    http.StatusBadRequest,
		},
		{
			name:   "missing credentials on a protected op (401)",
			method: "GET",
			path:   "/pets?status=available",
			want:   http.StatusUnauthorized,
		},
		{
			name:    "undeclared URI falls through to the catch-all (404)",
			method:  "GET",
			path:    "/this-is-not-in-the-spec",
			headers: map[string]string{"X-API-Key": "topsecret"},
			want:    http.StatusNotFound,
		},
		{
			name:    "path with wrong uuid shape -> 404",
			method:  "GET",
			path:    "/pets/not-a-uuid",
			headers: map[string]string{"X-API-Key": "topsecret"},
			want:    http.StatusNotFound,
		},
		{
			name:    "path with good uuid -> 200",
			method:  "GET",
			path:    "/pets/" + validUUID,
			headers: map[string]string{"X-API-Key": "topsecret"},
			want:    http.StatusOK,
		},
		{
			name:    "unsupported content-type on createPet (415)",
			method:  "POST",
			path:    "/pets",
			headers: map[string]string{"Authorization": "Bearer x"},
			body:    `name=hi`,
			ctype:   "text/plain",
			want:    http.StatusUnsupportedMediaType,
		},
		{
			name:    "public /health bypasses auth",
			method:  "GET",
			path:    "/health",
			headers: map[string]string{},
			want:    http.StatusOK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest(c.method, srv.URL+c.path, bytes.NewBufferString(c.body))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			for k, v := range c.headers {
				req.Header.Set(k, v)
			}
			if c.ctype != "" {
				req.Header.Set("Content-Type", c.ctype)
			}
			// Default: let httptest's native host (127.0.0.1) flow through;
			// test cases that want to assert wrong-host behavior set this.
			if c.host != "" {
				req.Host = c.host
			}

			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.want {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("%s %s: want %d, got %d\nbody: %s",
					c.method, c.path, c.want, resp.StatusCode, string(body))
			}
		})
	}
}

// doRequest is a compact helper for the matrix tests below.
func doRequest(t *testing.T, srv *httptest.Server, method, path string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// TestPetstoreStandaloneDetect: `--mode standalone-detect`. No request should
// ever be denied; everything passes through with status 200, even violations.
func TestPetstoreStandaloneDetect(t *testing.T) {
	rules := generatePetstoreRules(t, "--mode", "standalone-detect")
	if strings.Contains(rules, "deny,status:") {
		t.Fatalf("detect-mode output must not contain 'deny,status:'")
	}
	srv := newServer(t, rules)
	defer srv.Close()

	creds := map[string]string{"X-API-Key": "k"}
	cases := []struct {
		name, method, path string
		headers            map[string]string
	}{
		{"valid", "GET", "/pets?status=available", creds},
		{"missing-param (would-block)", "GET", "/pets", creds},
		{"bad-enum (would-block)", "GET", "/pets?status=wrong", creds},
		{"undeclared (would-block)", "GET", "/unknown", creds},
		{"no-creds (would-block)", "GET", "/pets?status=available", map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := doRequest(t, srv, c.method, c.path, c.headers)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s %s: detect-mode should pass, got %d", c.method, c.path, resp.StatusCode)
			}
		})
	}
}

// TestPetstoreCRSPlugin: `--mode crs-plugin`. Rules must not deny on their own
// and must contribute to `tx.inbound_anomaly_score_pl1`. We verify that by
// adding a small "scoreboard" rule that denies when the score is non-zero.
func TestPetstoreCRSPlugin(t *testing.T) {
	rules := generatePetstoreRules(t, "--mode", "crs-plugin")
	if strings.Contains(rules, "deny,status:") {
		t.Fatalf("crs-plugin output must not contain 'deny,status:'")
	}
	if !strings.Contains(rules, "tx.inbound_anomaly_score_pl1") {
		t.Fatalf("crs-plugin output should contribute to anomaly score")
	}
	// Append a phase:2 "did anything trigger the score?" rule so we can
	// observe the WAF decision — stand-in for CRS 949xxx.
	// CRS already initializes the anomaly-score TX variables via the
	// @crs-setup.conf.example include in the preamble. Add a stand-in for
	// CRS's 949110 inbound blocking rule so we can observe the decision.
	scoreboard := `
SecRule TX:inbound_anomaly_score_pl1 "@gt 0" \
    "id:9999,phase:2,deny,status:403,msg:'crs-plugin triggered',logdata:'score=%{tx.inbound_anomaly_score_pl1}'"
`
	srv := newServer(t, rules+scoreboard)
	defer srv.Close()

	cases := []struct {
		name   string
		method string
		path   string
		hdr    map[string]string
		want   int
	}{
		{"valid request -> pass", "GET", "/pets?status=available", map[string]string{"X-API-Key": "k"}, 200},
		{"missing param -> scored, blocked by scoreboard", "GET", "/pets", map[string]string{"X-API-Key": "k"}, 403},
		{"undeclared URL -> scored, blocked by scoreboard", "GET", "/unknown", map[string]string{"X-API-Key": "k"}, 403},
		{"no creds -> scored, blocked by scoreboard", "GET", "/pets?status=available", map[string]string{}, 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := doRequest(t, srv, c.method, c.path, c.hdr)
			defer resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("%s %s: want %d got %d", c.method, c.path, c.want, resp.StatusCode)
			}
		})
	}
}

// TestUndeclaredAlertOnly: `--mode standalone-block` but the undeclared
// endpoint action is "alert" — so unknown URLs pass but are tagged.
func TestUndeclaredAlertOnly(t *testing.T) {
	// The CLI doesn't have a single flag for this yet; write a config file.
	root := repoRoot(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "coraza-openapi.config.json")
	if err := os.WriteFile(cfg, []byte(`{
		"routing": { "undeclaredEndpointAction": "alert", "allowedHosts": ["petstore.example.com", "127.0.0.1"] }
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "openapi.conf")
	gen := exec.Command("node",
		filepath.Join(root, "packages/cli/dist/bin.js"),
		"generate",
		filepath.Join(root, "packages/core/src/samples/petstore.yaml"),
		"--config", cfg, "-o", out,
	)
	gen.Stderr = os.Stderr
	if err := gen.Run(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, _ := os.ReadFile(out)
	rules := string(b)
	if !strings.Contains(rules, "alert only — not blocked") {
		t.Fatalf("alert mode should keep the catch-all rule with alert-only messaging")
	}
	srv := newServer(t, rules)
	defer srv.Close()
	resp := doRequest(t, srv, "GET", "/totally-undeclared", map[string]string{"X-API-Key": "k"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("undeclared URL with alert-only policy should still pass, got %d", resp.StatusCode)
	}
}

// TestUndeclaredAllow: the catch-all isn't even emitted — undeclared URLs
// are indistinguishable from allowed ones at the WAF layer.
func TestUndeclaredAllow(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "coraza-openapi.config.json")
	if err := os.WriteFile(cfg, []byte(`{
		"routing": { "undeclaredEndpointAction": "allow", "allowedHosts": ["petstore.example.com", "127.0.0.1"] }
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "openapi.conf")
	gen := exec.Command("node",
		filepath.Join(root, "packages/cli/dist/bin.js"),
		"generate",
		filepath.Join(root, "packages/core/src/samples/petstore.yaml"),
		"--config", cfg, "-o", out,
	)
	gen.Stderr = os.Stderr
	if err := gen.Run(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, _ := os.ReadFile(out)
	rules := string(b)
	if strings.Contains(rules, "Path not defined in OpenAPI spec") ||
		strings.Contains(rules, "alert only — not blocked") {
		t.Fatalf("allow mode should emit no catch-all")
	}
	srv := newServer(t, rules)
	defer srv.Close()
	resp := doRequest(t, srv, "GET", "/totally-undeclared", map[string]string{"X-API-Key": "k"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("undeclared URL under 'allow' should pass, got %d", resp.StatusCode)
	}
}

// TestDebugMode: `--debug` annotates pass rules with msg; correctness of the
// deny matrix is unchanged.
func TestDebugMode(t *testing.T) {
	rules := generatePetstoreRules(t, "--debug")
	if !strings.Contains(rules, "debug: matched") {
		t.Fatalf("--debug should annotate pass rules with msg")
	}
	srv := newServer(t, rules)
	defer srv.Close()
	// Sanity: same request shape as standalone-block should still 200.
	resp := doRequest(t, srv, "GET", "/pets?status=available",
		map[string]string{"X-API-Key": "k"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d", resp.StatusCode)
	}
}

// TestBlockDeprecated: `--block-deprecated` turns deleteP et's deprecated flag
// into a hard 410.
func TestBlockDeprecated(t *testing.T) {
	rules := generatePetstoreRules(t, "--block-deprecated")
	if !strings.Contains(rules, "status:410") {
		t.Fatalf("block-deprecated should emit status:410 rule")
	}
	srv := newServer(t, rules)
	defer srv.Close()
	// DELETE /pets/{uuid} is the only deprecated op in the bundled spec.
	resp := doRequest(t, srv, "DELETE", "/pets/"+validUUID,
		map[string]string{"X-API-Key": "k"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Errorf("deprecated DELETE should 410, got %d", resp.StatusCode)
	}
	// Non-deprecated op on the same path still works.
	resp2 := doRequest(t, srv, "GET", "/pets/"+validUUID,
		map[string]string{"X-API-Key": "k"})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("non-deprecated GET should pass, got %d", resp2.StatusCode)
	}
}

// TestAuthDisabled: `--no-enforce-auth` drops all auth rules; requests with no
// credentials get through to the declared ops.
func TestAuthDisabled(t *testing.T) {
	rules := generatePetstoreRules(t, "--no-enforce-auth")
	if strings.Contains(rules, "Missing credentials for") {
		t.Fatalf("--no-enforce-auth should remove auth rules")
	}
	srv := newServer(t, rules)
	defer srv.Close()
	resp := doRequest(t, srv, "GET", "/pets?status=available", map[string]string{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d, want 200 (auth disabled)", resp.StatusCode)
	}
}