// Regression tests for the review fixes. Run from this directory:
//
//	go test -race main.go main_test.go
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *Logger { return newLogger("error", io.Discard) }

// 1. X-Forwarded-For split over several header lines.
func TestRealIPUsesAllForwardedForLines(t *testing.T) {
	trusted := parseCIDRs([]string{"127.0.0.0/8"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Add("X-Forwarded-For", "6.6.6.6")     // written by the client
	r.Header.Add("X-Forwarded-For", "203.0.113.7") // appended by the proxy
	if got := realIPFrom(r, trusted); got.String() != "203.0.113.7" {
		t.Fatalf("real IP = %v, want 203.0.113.7", got)
	}

	ctx := context.WithValue(r.Context(), ctxRealIP, net.ParseIP("203.0.113.7"))
	orig := r.WithContext(ctx)
	out := orig.Clone(ctx)
	setForwardedHeaders(out, orig)
	if got, want := out.Header.Get("X-Forwarded-For"), "6.6.6.6, 203.0.113.7, 127.0.0.1"; got != want {
		t.Fatalf("forwarded chain = %q, want %q", got, want)
	}
	if got := out.Header.Get("X-Real-IP"); got != "203.0.113.7" {
		t.Fatalf("X-Real-IP = %q", got)
	}
}

// 3. Scheme/host/port claims from untrusted peers.
func TestUntrustedForwardingHeadersStripped(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "Forwarded", "X-Real-IP"} {
		r.Header.Set(h, "spoofed")
	}
	stripUntrustedForwardingHeaders(r)
	for h := range r.Header {
		if strings.HasPrefix(h, "X-Forwarded") || h == "Forwarded" || h == "X-Real-Ip" {
			t.Errorf("%s survived", h)
		}
	}
}

// 2. Path-based auth on FastCGI sites and PATH_INFO.
func TestFastCGIAuthCoversPathInfo(t *testing.T) {
	hash := "pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0$" + strings.Repeat("A", 43)
	rs := &runtimeSite{
		cfg: &SiteConfig{
			Type:    "fastcgi",
			FastCGI: FastCGIConfig{SplitPath: ".php"},
			Auth:    AuthConfig{Enabled: true, Realm: "x", Users: map[string]string{"admin": hash}, Paths: []string{"/admin"}},
		},
		authPaths: []string{"/admin"},
	}
	h := rs.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	for _, p := range []string{"/admin", "/admin/users", "/index.php/admin", "/index.php/ADMIN/users", "/a.php/index.php/admin"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", p, w.Code)
		}
	}
	for _, p := range []string{"/", "/index.php", "/index.php/blog", "/blog.php/x"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", p, w.Code)
		}
	}
}

// 4. Truncated or empty hashes must not authenticate anyone.
func TestVerifyPasswordFailsClosed(t *testing.T) {
	good := hashPassword("secret")
	if !verifyPassword("secret", good) || verifyPassword("wrong", good) {
		t.Fatal("regular hash does not verify correctly")
	}
	for _, bad := range []string{
		"pbkdf2-sha256$1$$",
		"pbkdf2-sha256$210000$c2FsdHNhbHQ$",
		good[:strings.LastIndex(good, "$")+1],
		"pbkdf2-sha256$210000$$" + good[strings.LastIndex(good, "$")+1:],
	} {
		if verifyPassword("anything", bad) || verifyPassword("", bad) {
			t.Errorf("hash %q accepted a password", bad)
		}
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	doc := `{"sites":[{"name":"s","type":"static","root":"` + filepath.ToSlash(dir) + `","domains":["a.test"],
		"auth":{"enabled":true,"users":{"admin":"pbkdf2-sha256$1$$"}}}]}`
	if _, err := parseConfig([]byte(doc), cfgPath); err == nil {
		t.Fatal("config with an empty password hash was accepted")
	}
}

// 5. Repeated basic-auth checks are served from the cache.
func TestBasicAuthCacheSkipsRepeatedPBKDF2(t *testing.T) {
	hash := hashPassword("secret")
	c := basicAuthVerifier()
	start := time.Now()
	if !c.verify(context.Background(), "u", "secret", hash) {
		t.Fatal("first check failed")
	}
	first := time.Since(start)
	start = time.Now()
	for i := 0; i < 20; i++ {
		if !c.verify(context.Background(), "u", "secret", hash) {
			t.Fatal("cached check failed")
		}
	}
	if twenty := time.Since(start); twenty > first {
		t.Fatalf("20 cached checks took %s, one uncached %s", twenty, first)
	}
	if c.verify(context.Background(), "u", "wrong", hash) {
		t.Fatal("wrong password accepted")
	}
}

// 6. prune-releases only touches release trees webhost manages.
func TestPruneReleasesSkipsUnmanagedTrees(t *testing.T) {
	base := t.TempDir()
	mk := func(dir string, n int) {
		for i := 1; i <= n; i++ {
			if err := os.MkdirAll(filepath.Join(dir, "r"+string(rune('0'+i))), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Managed site: current -> releases/r7.
	managed := filepath.Join(base, "managed")
	mk(filepath.Join(managed, "releases"), 7)
	if err := os.Symlink(filepath.Join(managed, "releases", "r7"), filepath.Join(managed, "current")); err != nil {
		t.Fatal(err)
	}
	// Plain directory root with somebody else's "releases" next to it.
	plain := filepath.Join(base, "plain")
	mk(filepath.Join(plain, "releases"), 7)
	_ = os.MkdirAll(filepath.Join(plain, "public"), 0o755)
	// The working directory's parent: a proxy site (no root) used to prune it.
	wd := filepath.Join(base, "work", "cwd")
	mk(filepath.Join(base, "work", "releases"), 7)
	_ = os.MkdirAll(wd, 0o755)
	old, _ := os.Getwd()
	defer func() { _ = os.Chdir(old) }()
	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}

	srv := &Server{log: testLogger(), cfg: &Config{Sites: []*SiteConfig{
		{Name: "m", Type: "static", Root: filepath.Join(managed, "current"), Deploy: DeployConfig{Enabled: true, KeepReleases: 5}},
		{Name: "p", Type: "static", Root: filepath.Join(plain, "public"), Deploy: DeployConfig{Enabled: true, KeepReleases: 5}},
		{Name: "x", Type: "proxy", Deploy: DeployConfig{Enabled: true, KeepReleases: 5}},
	}}}
	sc := newScheduler(srv)
	if err := sc.builtinTask("prune-releases")(context.Background()); err != nil {
		t.Fatal(err)
	}
	count := func(dir string) int {
		ents, _ := os.ReadDir(dir)
		return len(ents)
	}
	if n := count(filepath.Join(managed, "releases")); n != 5 {
		t.Errorf("managed releases: %d left, want 5", n)
	}
	if n := count(filepath.Join(plain, "releases")); n != 7 {
		t.Errorf("foreign releases next to a plain root: %d left, want 7", n)
	}
	if n := count(filepath.Join(base, "work", "releases")); n != 7 {
		t.Errorf("releases next to the working directory: %d left, want 7", n)
	}
}

// 7. Restore with -sites: symlinks survive, stale files go, the switch is atomic.
func TestRestoreSitesReplacesContent(t *testing.T) {
	base := t.TempDir()
	site := filepath.Join(base, "sites", "s")
	rel1 := filepath.Join(site, "releases", "20260101-000000")
	_ = os.MkdirAll(filepath.Join(rel1, "assets"), 0o755)
	_ = os.WriteFile(filepath.Join(rel1, "index.html"), []byte("v1"), 0o644)
	_ = os.Symlink("index.html", filepath.Join(rel1, "latest.html"))
	_ = os.Symlink("../../../etc/passwd", filepath.Join(rel1, "escape"))
	root := filepath.Join(site, "current")
	if err := os.Symlink(rel1, root); err != nil {
		t.Fatal(err)
	}

	// Archive the site the way makeBackup does.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tarAddTree(tw, "sites/s", rel1); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()
	archive := filepath.Join(base, "backup-x.tar.gz")
	_ = os.WriteFile(archive, buf.Bytes(), 0o600)

	// After the backup: content changes in the live release.
	_ = os.WriteFile(filepath.Join(rel1, "stale.html"), []byte("new"), 0o644)
	_ = os.WriteFile(filepath.Join(rel1, "index.html"), []byte("v2"), 0o644)

	srv := &Server{log: testLogger(), cfgPath: filepath.Join(base, "config.json"), cfg: &Config{
		DataDir: base,
		Sites:   []*SiteConfig{{Name: "s", Type: "static", Root: root}},
	}}
	report, err := srv.restoreBackup(archive, true)
	if err != nil {
		t.Fatalf("restore: %v (%v)", err, report)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "index.html")); string(b) != "v1" {
		t.Errorf("index.html = %q, want v1", b)
	}
	if fileExists(filepath.Join(root, "stale.html")) {
		t.Error("file created after the backup survived the restore")
	}
	if target, err := os.Readlink(filepath.Join(root, "latest.html")); err != nil || target != "index.html" {
		t.Errorf("latest.html is no longer a symlink to index.html (%q, %v)", target, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "escape")); err == nil {
		t.Error("symlink pointing outside the site was restored")
	}
	if cur, _ := os.Readlink(root); cur == rel1 || !strings.Contains(filepath.Base(cur), "restore") {
		t.Errorf("current -> %s, want a new restore release", cur)
	}
	if b, _ := os.ReadFile(filepath.Join(rel1, "stale.html")); string(b) != "new" {
		t.Error("the previous release was modified in place")
	}
}

// 8. in-flight accounting survives ReverseProxy's abort panic.
type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic(http.ErrAbortHandler)
}

func TestProxyInflightDecrementedOnAbort(t *testing.T) {
	up := &upstream{proxy: &httputil.ReverseProxy{
		Rewrite:   func(pr *httputil.ProxyRequest) { pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "127.0.0.1:1" },
		Transport: panicTransport{},
	}}
	func() {
		defer func() { _ = recover() }()
		proxyThrough(up, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	if up.inflight != 0 {
		t.Fatalf("inflight = %d after an aborted request, want 0", up.inflight)
	}
}

// 9. Forced rotation is safe next to concurrent writes (run with -race).
func TestRotateConcurrentWithWrites(t *testing.T) {
	w, err := newRotatingWriter(filepath.Join(t.TempDir(), "x.log"), 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = w.Write([]byte("line\n"))
			}
		}()
	}
	for i := 0; i < 20; i++ {
		w.Rotate()
	}
	wg.Wait()
}

// 10. A job added by reload runs without waiting for the old nearest job.
func TestSchedulerPicksUpReloadedJobs(t *testing.T) {
	srv := &Server{log: testLogger()}
	sc := newScheduler(srv)
	sc.load(&Config{Cron: []CronJobConfig{{Name: "hourly", Spec: "@every 1h", Task: "log-rotate"}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sc.run(ctx)
	time.Sleep(100 * time.Millisecond)
	sc.load(&Config{Cron: []CronJobConfig{
		{Name: "hourly", Spec: "@every 1h", Task: "log-rotate"},
		{Name: "fast", Spec: "@every 1s", Task: "log-rotate"},
	}})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, j := range sc.jobsSnapshot() {
			if j["name"] == "fast" && j["runs"].(int64) > 0 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("job added by reload did not run within 5s")
}

// 11. timeout_sec holds even when the command leaves a child on its stdout.
func TestCronCommandTimeoutWithChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	sc := newScheduler(&Server{log: testLogger()})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	err := sc.runCommand(ctx, CronJobConfig{Name: "t", Command: "sh", Args: []string{"-c", "sleep 30 & sleep 30"}})
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("command with timeout 1s returned after %s", took)
	}
	if err == nil {
		t.Fatal("timed-out command reported success")
	}
}

// 12. A restarted process starts only after the old one has exited.
func TestSupervisorRestartWaitsForExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh and SIGINT")
	}
	log := filepath.Join(t.TempDir(), "events")
	script := `trap 'sleep 1; echo stop >> "$1"; exit 0' INT; echo start >> "$1"; while :; do sleep 0.1; done`
	sup := newSupervisor(&Server{log: testLogger()})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); sup.stopAll() }()
	sup.start(ctx, &Config{Processes: []ProcessConfig{{Name: "w", Command: "sh", Args: []string{"-c", script, "sh", log}, Restart: "always"}}})
	waitFor := func(want string) {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if b, _ := os.ReadFile(log); strings.TrimSpace(string(b)) == want {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		b, _ := os.ReadFile(log)
		t.Fatalf("events %q, want %q", strings.TrimSpace(string(b)), want)
	}
	waitFor("start")
	if err := sup.restart(ctx, "w"); err != nil {
		t.Fatal(err)
	}
	waitFor("start\nstop\nstart")
}

// 13. Saving config.json must not copy "defaults" into every site.
func TestConfigWritesKeepDefaultsInherited(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{"-dir", dir}); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	sitesHaveOwnDefaults := func() bool {
		var raw struct {
			Sites []map[string]json.RawMessage `json:"sites"`
		}
		b, _ := os.ReadFile(cfgPath)
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		for _, s := range raw.Sites {
			for _, k := range []string{"security", "compress", "cache", "rate_limit"} {
				if _, ok := s[k]; ok {
					return true
				}
			}
		}
		return false
	}
	if sitesHaveOwnDefaults() {
		t.Fatal("init wrote per-site copies of the defaults")
	}
	before, _ := os.ReadFile(cfgPath)
	if err := setSiteDisabled(cfgPath, "spa", false); err != nil {
		t.Fatal(err)
	}
	if sitesHaveOwnDefaults() {
		t.Fatal("enable/disable wrote per-site copies of the defaults")
	}
	after, _ := os.ReadFile(cfgPath)
	if !bytes.Contains(after, []byte(`"name": "spa"`)) || len(after) < len(before)-64 {
		t.Fatal("config lost content")
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range cfg.Sites {
		if s.Name == "spa" && s.Disabled {
			t.Fatal("spa still disabled")
		}
	}
	if err := setSiteDisabled(cfgPath, "nope", true); err == nil {
		t.Fatal("unknown site was not reported")
	}
}

// ---------------------------------------------------------------------------
// Helpers for the 1.2.3 tests.

// newTestServer builds a Server from a config.json holding extra (JSON
// members such as "sites") in a temporary data directory.
func newTestServer(t *testing.T, extra string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	doc := `{"admin":{"enabled":true,"token":"test-token"},"log":{"level":"error"},` + extra + `}`
	if err := os.WriteFile(cfgPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if st := s.getState(); st != nil && st.cancel != nil {
			st.cancel()
		}
		s.cancel()
		for _, c := range s.closers {
			_ = c.Close()
		}
	})
	return s, dir
}

// jsonPath quotes a file path for a JSON document.
func jsonPath(p string) string {
	b, _ := json.Marshal(filepath.ToSlash(p))
	return string(b)
}

// writeFiles creates files (name -> content) under dir.
func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// selfSignedCert returns a self-signed certificate for hosts and its PEM files.
func selfSignedCert(t *testing.T, hosts ...string) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c, certPEM, keyPEM
}

// serveHTTP sends r through the server's root handler.
func serveHTTP(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// ---------------------------------------------------------------------------

// 14. HTTP→HTTPS redirect: not for plain-HTTP sites, not when a trusted proxy
// already terminated TLS, and IPv6 hosts keep their brackets.
func TestHTTPSRedirectRules(t *testing.T) {
	plain := &SiteConfig{Name: "plain", Domains: []string{"plain.test"}}
	secure := &SiteConfig{Name: "secure", Domains: []string{"secure.test"}, TLS: TLSConfig{Enabled: true}}
	st := &runtimeState{
		exact: map[string]*runtimeSite{
			"plain.test":  {cfg: plain},
			"secure.test": {cfg: secure},
		},
		trusted: parseCIDRs([]string{"127.0.0.0/8"}),
	}
	st.fallback = st.exact["secure.test"]
	s := &Server{state: st, cfg: &Config{Sites: []*SiteConfig{plain, secure}}}
	for _, c := range []struct {
		host, remote, xfp string
		want              bool
	}{
		{"plain.test", "203.0.113.1:1000", "", false},
		{"secure.test", "203.0.113.1:1000", "", true},
		{"secure.test", "203.0.113.1:1000", "https", true}, // claim from an untrusted peer
		{"secure.test", "127.0.0.1:1000", "https", false},  // a trusted proxy terminated TLS
		{"secure.test", "127.0.0.1:1000", "", true},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://"+c.host+"/x?y=1", nil)
		r.RemoteAddr = c.remote
		if c.xfp != "" {
			r.Header.Set("X-Forwarded-Proto", c.xfp)
		}
		if got := s.shouldRedirectToHTTPS(r); got != c.want {
			t.Errorf("%s from %s (X-Forwarded-Proto %q): redirect=%v, want %v", c.host, c.remote, c.xfp, got, c.want)
		}
	}
	for _, c := range []struct{ host, listen, want string }{
		{"[::1]:8080", ":443", "https://[::1]/x?y=1"},
		{"[2001:db8::1]", ":8443", "https://[2001:db8::1]:8443/x?y=1"},
		{"example.com:8080", ":8443", "https://example.com:8443/x?y=1"},
		{"example.com", ":443", "https://example.com/x?y=1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/x?y=1", nil)
		r.Host = c.host
		if got := httpsRedirectURL(r, c.listen); got != c.want {
			t.Errorf("Host %s, listen %s: %s, want %s", c.host, c.listen, got, c.want)
		}
	}
}

// 14b. The same rules through the HTTP listener's handler.
func TestHTTPSRedirectViaEntryHandler(t *testing.T) {
	root := t.TempDir()
	s, _ := newTestServer(t, `"sites":[
		{"name":"plain","type":"static","root":`+jsonPath(root)+`,"domains":["plain.test"]},
		{"name":"secure","type":"static","root":`+jsonPath(root)+`,"domains":["secure.test"],"tls":{"enabled":true},"default":true}]`)
	h := s.httpEntryHandler()
	for _, c := range []struct {
		host, remote, xfp string
		redirect          bool
	}{
		{"plain.test", "203.0.113.1:1000", "", false},
		{"secure.test", "127.0.0.1:1000", "https", false},
		{"secure.test", "203.0.113.1:1000", "https", true},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://"+c.host+"/x", nil)
		r.RemoteAddr = c.remote
		if c.xfp != "" {
			r.Header.Set("X-Forwarded-Proto", c.xfp)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Code == http.StatusMovedPermanently; got != c.redirect {
			t.Errorf("%s from %s: redirect=%v, want %v", c.host, c.remote, got, c.redirect)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "http://[::1]:8080/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if loc := w.Header().Get("Location"); w.Code != http.StatusMovedPermanently || !strings.HasPrefix(loc, "https://[::1]") {
		t.Errorf("IPv6: status %d, Location %q", w.Code, loc)
	}
}

// 15. tls.min_version applies to its own site, not to the whole listener.
func TestTLSMinVersionPerSite(t *testing.T) {
	certs, err := newCertManager(t.TempDir(), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	modern := &SiteConfig{Name: "modern", Domains: []string{"modern.test"}, TLS: TLSConfig{Enabled: true, MinVersion: "1.3"}}
	legacy := &SiteConfig{Name: "legacy", Domains: []string{"legacy.test"}, TLS: TLSConfig{Enabled: true, MinVersion: "1.2"}}
	s := &Server{certs: certs, cfg: &Config{Sites: []*SiteConfig{modern, legacy}}, state: &runtimeState{
		exact: map[string]*runtimeSite{"modern.test": {cfg: modern}, "legacy.test": {cfg: legacy}},
	}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", s.tlsConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	dial := func(name string) error {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: name, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	if err := dial("legacy.test"); err != nil {
		t.Fatalf("TLS 1.2 client refused by a site with min_version 1.2: %v", err)
	}
	if err := dial("modern.test"); err == nil {
		t.Fatal("TLS 1.2 client accepted by a site with min_version 1.3")
	}
}

// 16. The most specific wildcard wins, whatever the order in the config.
func TestWildcardMostSpecificWins(t *testing.T) {
	base := t.TempDir()
	writeFiles(t, base, map[string]string{"wide/index.html": "wide", "narrow/index.html": "narrow"})
	s, _ := newTestServer(t, `"sites":[
		{"name":"wide","type":"static","root":`+jsonPath(filepath.Join(base, "wide"))+`,"domains":["*.example.test"]},
		{"name":"narrow","type":"static","root":`+jsonPath(filepath.Join(base, "narrow"))+`,"domains":["*.a.example.test"]}]`)
	for host, want := range map[string]string{"x.a.example.test": "narrow", "x.example.test": "wide"} {
		w := serveHTTP(s, httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil))
		if got := strings.TrimSpace(w.Body.String()); got != want {
			t.Errorf("%s served by %q, want %q", host, got, want)
		}
	}
}

// 17. No certificates are minted for names of sites without tls.enabled.
func TestNoCertificateForPlainHTTPSite(t *testing.T) {
	root := t.TempDir()
	s, _ := newTestServer(t, `"sites":[
		{"name":"plain","type":"static","root":`+jsonPath(root)+`,"domains":["plain.test"]},
		{"name":"secure","type":"static","root":`+jsonPath(root)+`,"domains":["secure.test"],"tls":{"enabled":true}}]`)
	if _, ok := s.certs.allowHost("plain.test"); ok {
		t.Error("certificate allowed for a site with tls.enabled=false")
	}
	if _, ok := s.certs.allowHost("secure.test"); !ok {
		t.Error("certificate refused for a site with tls.enabled=true")
	}
}

// 18. Behind a trusted proxy the upstream and PHP see the client's scheme,
// host and address; from untrusted peers the claims are ignored.
func TestProxyKeepsTrustedForwardedProto(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
	}))
	defer up.Close()
	s, _ := newTestServer(t, `"sites":[{"name":"app","type":"proxy","domains":["app.test"],"upstreams":["`+up.URL+`"]}]`)
	send := func(remote string) http.Header {
		r := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "www.public.test")
		if w := serveHTTP(s, r); w.Code != http.StatusOK {
			t.Fatalf("status %d", w.Code)
		}
		mu.Lock()
		defer mu.Unlock()
		return got
	}
	h := send("127.0.0.1:4000") // loopback is trusted by default
	if h.Get("X-Forwarded-Proto") != "https" || h.Get("X-Forwarded-Host") != "www.public.test" {
		t.Errorf("trusted proxy: upstream got proto %q host %q, want https / www.public.test",
			h.Get("X-Forwarded-Proto"), h.Get("X-Forwarded-Host"))
	}
	h = send("203.0.113.9:4000")
	if h.Get("X-Forwarded-Proto") != "http" || h.Get("X-Forwarded-Host") != "app.test" {
		t.Errorf("untrusted peer: upstream got proto %q host %q, want http / app.test",
			h.Get("X-Forwarded-Proto"), h.Get("X-Forwarded-Host"))
	}
}

// fakePHP is a FastCGI responder that records what PHP would see.
type fakePHP struct {
	mu     sync.Mutex
	remote string
	https  bool
	env    map[string]string
	calls  int
}

func startFakePHP(t *testing.T) (*fakePHP, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakePHP{}
	go func() {
		_ = fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.remote, f.https, f.env = r.RemoteAddr, r.TLS != nil, fcgi.ProcessEnv(r)
			f.calls++
			f.mu.Unlock()
			_, _ = io.WriteString(w, "from-php")
		}))
	}()
	return f, ln.Addr().String()
}

func TestFastCGISeesClientBehindTrustedProxy(t *testing.T) {
	php, addr := startFakePHP(t)
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"index.php": "<?php"})
	s, _ := newTestServer(t, `"sites":[{"name":"php","type":"fastcgi","root":`+jsonPath(root)+`,"domains":["php.test"],
		"fastcgi":{"address":"`+addr+`","timeout_sec":5}}]`)

	r := httptest.NewRequest(http.MethodGet, "http://php.test/index.php", nil)
	r.RemoteAddr = "127.0.0.1:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Port", "443")
	if w := serveHTTP(s, r); w.Code != http.StatusOK || w.Body.String() != "from-php" {
		t.Fatalf("status %d body %q", w.Code, w.Body)
	}
	php.mu.Lock()
	if host, _, _ := net.SplitHostPort(php.remote); host != "203.0.113.7" {
		t.Errorf("REMOTE_ADDR = %q, want the client 203.0.113.7", php.remote)
	}
	if !php.https || php.env["REQUEST_SCHEME"] != "https" || php.env["SERVER_PORT"] != "443" {
		t.Errorf("behind a TLS-terminating proxy: HTTPS=%v REQUEST_SCHEME=%q SERVER_PORT=%q",
			php.https, php.env["REQUEST_SCHEME"], php.env["SERVER_PORT"])
	}
	php.mu.Unlock()

	r = httptest.NewRequest(http.MethodGet, "http://php.test/index.php", nil)
	r.RemoteAddr = "198.51.100.2:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("X-Forwarded-Proto", "https")
	serveHTTP(s, r)
	php.mu.Lock()
	defer php.mu.Unlock()
	if host, _, _ := net.SplitHostPort(php.remote); host != "198.51.100.2" || php.https {
		t.Errorf("untrusted claims honored: REMOTE_ADDR %q, HTTPS %v", php.remote, php.https)
	}
}

// 18b. HSTS is sent when a trusted proxy terminated TLS for the client.
func TestHSTSBehindTrustedProxy(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"index.html": "hi"})
	s, _ := newTestServer(t, `"sites":[{"name":"s","type":"static","root":`+jsonPath(root)+`,"domains":["s.test"]}]`)
	for remote, want := range map[string]bool{"127.0.0.1:4000": true, "203.0.113.9:4000": false} {
		r := httptest.NewRequest(http.MethodGet, "http://s.test/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-Proto", "https")
		w := serveHTTP(s, r)
		if got := w.Header().Get("Strict-Transport-Security") != ""; got != want {
			t.Errorf("peer %s: HSTS sent=%v, want %v", remote, got, want)
		}
	}
}

// 19. strip_prefix works on path segments and keeps encoded characters.
func TestProxyStripPrefixBoundaryAndEncoding(t *testing.T) {
	var mu sync.Mutex
	var uri string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		uri = r.RequestURI
		mu.Unlock()
	}))
	defer up.Close()
	s, _ := newTestServer(t, `"sites":[
		{"name":"api","type":"proxy","domains":["api.test"],"upstreams":["`+up.URL+`"],"proxy":{"strip_prefix":"/api"}},
		{"name":"base","type":"proxy","domains":["base.test"],"upstreams":["`+up.URL+`/base/"],"proxy":{"strip_prefix":"/api/"}}]`)
	for _, c := range []struct{ host, path, want string }{
		{"api.test", "/api/users?x=1", "/users?x=1"},
		{"api.test", "/api", "/"},
		{"api.test", "/apiary", "/apiary"},
		{"api.test", "/api/files/a%2Fb", "/files/a%2Fb"},
		{"base.test", "/api/x", "/base/x"},
		{"base.test", "/api/a%2Fb", "/base/a%2Fb"},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://"+c.host+c.path, nil)
		r.RemoteAddr = "203.0.113.5:1000"
		serveHTTP(s, r)
		mu.Lock()
		if uri != c.want {
			t.Errorf("%s%s reached the upstream as %q, want %q", c.host, c.path, uri, c.want)
		}
		mu.Unlock()
	}
	// The helper on its own: RawPath stays consistent with Path.
	u, _ := url.Parse("http://h/api/a%2Fb%20c")
	rewriteProxyPath(u, "/api", &url.URL{Path: "/"})
	if u.Path != "/a/b c" || u.EscapedPath() != "/a%2Fb%20c" {
		t.Errorf("path %q escaped %q", u.Path, u.EscapedPath())
	}
}

// 20. Health checks use the proxy's TLS settings (insecure_skip_verify).
func TestHealthCheckUsesProxyTLSSettings(t *testing.T) {
	var hits int32
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer up.Close()
	site := &SiteConfig{Name: "s", Type: "proxy", Upstreams: []string{up.URL},
		ProxyConfig: ProxyConfig{InsecureSkipVerify: true, DialTimeoutSec: 5},
		HealthCheck: HealthConfig{Enabled: true, Path: "/health", IntervalSec: 1, TimeoutSec: 2, FailAfter: 1, RiseAfter: 1}}
	p, err := newUpstreamPool(site, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.startHealthChecks(ctx, newMetrics(), testLogger())
	deadline := time.Now().Add(6 * time.Second)
	for atomic.LoadInt32(&hits) < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) < 2 {
		t.Fatal("health checks never reached an upstream with a self-signed certificate")
	}
	if !p.ups[0].isHealthy() {
		t.Fatal("upstream marked unhealthy")
	}
}

// 21. Outbound HTTPS (ACME, proxy upstreams) trusts roots imported with
// "webhost roots -import" next to the system store, and honors HTTPS_PROXY.
func TestOutboundTrustsImportedRoots(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	rootsFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(rootsFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPath, _ := extraRootsPath.Load().(string)
	reset := func(p string) {
		extraRootsPath.Store(p)
		rootPoolOnce = sync.Once{}
		rootPoolVal, rootPoolFrom, rootPoolErr = nil, "", nil
	}
	reset(rootsFile)
	defer reset(oldPath)

	client, err := newOutboundClient(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := client.Transport.(*http.Transport); !ok || tr.Proxy == nil {
		t.Error("outbound client ignores HTTPS_PROXY")
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("outbound client does not trust the imported root: %v", err)
	}
	resp.Body.Close()

	p, err := newUpstreamPool(&SiteConfig{Name: "s", Upstreams: []string{srv.URL}, ProxyConfig: ProxyConfig{DialTimeoutSec: 5}}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	resp, err = (&http.Client{Transport: p.transport, Timeout: 10 * time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatalf("proxy transport does not trust the imported root: %v", err)
	}
	resp.Body.Close()
}

// 22. A new ACME directory gets a new account; the old one is kept aside.
func TestACMEDirectoryChangeMovesOldAccount(t *testing.T) {
	cm, err := newCertManager(t.TempDir(), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	acme := filepath.Join(cm.dir, "acme")
	staging := "https://acme-staging-v02.api.letsencrypt.org/directory"
	if err := cm.switchACMEDirectory(staging); err != nil {
		t.Fatal(err)
	}
	writeFiles(t, acme, map[string]string{
		"account.key": "KEY", "account.kid": "https://staging.test/acct/1",
		"shop.test.crt": "CRT", "shop.test.key": "PRIV",
	})
	if err := cm.switchACMEDirectory(staging); err != nil {
		t.Fatal(err)
	}
	if !fileExists(filepath.Join(acme, "account.kid")) {
		t.Fatal("account moved although the directory did not change")
	}
	if err := cm.switchACMEDirectory(acmeLetsEncryptProd); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"account.kid", "shop.test.crt", "shop.test.key"} {
		if fileExists(filepath.Join(acme, n)) {
			t.Errorf("%s from the staging directory is still in use", n)
		}
	}
	if !fileExists(filepath.Join(acme, "account.key")) {
		t.Error("account.key was moved")
	}
	if m, _ := filepath.Glob(filepath.Join(acme, "previous-*", "account.kid")); len(m) != 1 {
		t.Errorf("old account not kept aside: %v", m)
	}
}

// 23. Messages can be queued through the admin API.
func TestMailSendQueuesMessage(t *testing.T) {
	root := t.TempDir()
	s, _ := newTestServer(t, `"mail":{"enabled":true,"from":"site@example.test","relay":"127.0.0.1:1","max_retries":5},
		"sites":[{"name":"s","type":"static","root":`+jsonPath(root)+`,"domains":["s.test"]}]`)
	h := s.adminHandler()
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/mail/send", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := post(`{"to":["user@example.test"],"subject":"Hi","text":"Hello"}`); w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	// The immediate delivery attempt (refused by 127.0.0.1:1) keeps it queued.
	deadline := time.Now().Add(10 * time.Second)
	for {
		q := s.mail.queueSnapshot(10)
		if len(q) != 1 {
			t.Fatalf("queue has %d messages, want 1", len(q))
		}
		if q[0]["attempts"].(int) >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if w := post(`{"to":[],"subject":"x","text":"y"}`); w.Code != http.StatusBadRequest {
		t.Errorf("message without recipients: status %d, want 400", w.Code)
	}
}

// fakeSMTP accepts SMTP sessions and passes each message body to the channel.
// With brokenTLS the server answers STARTTLS with garbage.
func fakeSMTP(t *testing.T, cert tls.Certificate, brokenTLS bool) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	msgs := make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSMTP(c, cert, brokenTLS, msgs)
		}
	}()
	return ln.Addr().String(), msgs
}

func serveFakeSMTP(conn net.Conn, cert tls.Certificate, brokenTLS bool, msgs chan<- string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	c, rd, tlsOn := conn, bufio.NewReader(conn), false
	say := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	say("220 fake ESMTP")
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			if tlsOn {
				say("250 fake")
			} else {
				say("250-fake")
				say("250 STARTTLS")
			}
		case cmd == "STARTTLS":
			say("220 go ahead")
			if brokenTLS {
				_, _ = io.WriteString(c, "this is not TLS at all\r\n")
				return
			}
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			c, rd, tlsOn = tc, bufio.NewReader(tc), true
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			say("250 ok")
		case cmd == "DATA":
			say("354 go on")
			var b strings.Builder
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			if tlsOn {
				msgs <- "tls:" + b.String()
			} else {
				msgs <- "plain:" + b.String()
			}
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

// 24. Direct MX delivery uses opportunistic TLS: an MX with a certificate
// that does not verify, or with broken TLS, still gets the message.
func TestMXDeliveryOpportunisticTLS(t *testing.T) {
	cert, _, _ := selfSignedCert(t, "mx.example.test")
	m := &mailer{lg: testLogger(), cfg: MailConfig{StartTLS: "auto", TimeoutSec: 5, HELO: "webhost.test"}}
	recv := func(ch <-chan string) string {
		select {
		case s := <-ch:
			return s
		case <-time.After(5 * time.Second):
			return ""
		}
	}

	addr, msgs := fakeSMTP(t, cert, false)
	if err := m.sendMX(context.Background(), addr, "a@site.test", []string{"b@example.test"}, []byte("Subject: x\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("MX with a self-signed certificate: %v", err)
	}
	if got := recv(msgs); !strings.HasPrefix(got, "tls:") {
		t.Errorf("message not delivered over TLS: %q", got)
	}
	// A relay (with a password) still requires a valid certificate.
	if err := m.sendVia(context.Background(), addr, "a@site.test", []string{"b@example.test"}, []byte("x\r\n"), "", "", false, false); err == nil {
		t.Error("relay accepted a certificate that does not verify")
	}

	addr, msgs = fakeSMTP(t, cert, true)
	if err := m.sendMX(context.Background(), addr, "a@site.test", []string{"b@example.test"}, []byte("Subject: x\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("MX with broken TLS: %v", err)
	}
	if got := recv(msgs); !strings.HasPrefix(got, "plain:") {
		t.Errorf("message not delivered after the TLS failure: %q", got)
	}
}

// 25. fastcgi.static_extensions: other files are never handed out raw.
func TestFastCGIStaticExtensions(t *testing.T) {
	php, addr := startFakePHP(t)
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"index.php": "<?php", "style.css": "body{}", "dump.sql": "SECRET"})
	s, _ := newTestServer(t, `"sites":[{"name":"php","type":"fastcgi","root":`+jsonPath(root)+`,"domains":["php.test"],
		"fastcgi":{"address":"`+addr+`","timeout_sec":5,"static_extensions":["css",".JS"]}}]`)
	get := func(p string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://php.test"+p, nil)
		r.RemoteAddr = "203.0.113.5:1000"
		return serveHTTP(s, r)
	}
	if w := get("/style.css"); w.Code != http.StatusOK || w.Body.String() != "body{}" {
		t.Errorf("/style.css: status %d body %q", w.Code, w.Body)
	}
	w := get("/dump.sql")
	if strings.Contains(w.Body.String(), "SECRET") {
		t.Fatal("/dump.sql was served as a file despite static_extensions")
	}
	php.mu.Lock()
	defer php.mu.Unlock()
	if w.Body.String() != "from-php" || !strings.HasSuffix(php.env["SCRIPT_FILENAME"], "index.php") {
		t.Errorf("/dump.sql: body %q, script %q — want the front controller", w.Body, php.env["SCRIPT_FILENAME"])
	}
}

// 26. WebSocket upgrades are proxied whatever proxy.websocket says: configs
// written by init up to 1.2.2 carry "websocket": false in every site, so the
// key must not switch WebSocket off. New configs no longer write it.
func TestProxyWebSocketAlwaysProxied(t *testing.T) {
	var upgrades int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			atomic.AddInt32(&upgrades, 1)
		}
	}))
	defer up.Close()
	s, _ := newTestServer(t, `"sites":[
		{"name":"plain","type":"proxy","domains":["plain.test"],"upstreams":["`+up.URL+`"]},
		{"name":"old","type":"proxy","domains":["old.test"],"upstreams":["`+up.URL+`"],"proxy":{"websocket":false}}]`)
	for _, host := range []string{"plain.test", "old.test"} {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/socket", nil)
		r.RemoteAddr = "203.0.113.5:1000"
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		serveHTTP(s, r)
	}
	if n := atomic.LoadInt32(&upgrades); n != 2 {
		t.Errorf("%d of 2 WebSocket upgrades reached the upstream", n)
	}
	b, err := json.Marshal(ProxyConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "websocket") {
		t.Errorf("an empty proxy block still writes the websocket key: %s", b)
	}
}

// 27. Reload replaces configured certificates instead of adding to them.
func TestReloadDropsRemovedManualCertificates(t *testing.T) {
	_, certPEM, keyPEM := selfSignedCert(t, "shop.test")
	files := t.TempDir()
	writeFiles(t, files, map[string]string{"shop.crt": string(certPEM), "shop.key": string(keyPEM)})
	root := t.TempDir()
	site := func(tlsJSON string) string {
		return `"sites":[{"name":"shop","type":"static","root":` + jsonPath(root) + `,"domains":["shop.test"],"tls":` + tlsJSON + `}]`
	}
	s, dir := newTestServer(t, site(`{"enabled":true,"cert_file":`+jsonPath(filepath.Join(files, "shop.crt"))+
		`,"key_file":`+jsonPath(filepath.Join(files, "shop.key"))+`}`))
	if s.certs.lookup("shop.test") == nil {
		t.Fatal("configured certificate not loaded")
	}
	doc := `{"admin":{"enabled":true,"token":"test-token"},"log":{"level":"error"},` + site(`{"enabled":true}`) + `}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.certs.lookup("shop.test") != nil {
		t.Fatal("certificate removed from the config is still served after reload")
	}
}

// 28. service -install refuses a missing or broken config.
func TestServiceInstallNeedsConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := checkServiceConfig(cfgPath, "webhost"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing config: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkServiceConfig(cfgPath, "webhost"); err == nil {
		t.Fatal("broken config accepted")
	}
	ok := filepath.Join(dir, "ok")
	if err := cmdInit([]string{"-dir", ok}); err != nil {
		t.Fatal(err)
	}
	if err := checkServiceConfig(filepath.Join(ok, "config.json"), "webhost"); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// 29. The Go toolchain is only used when its SHA-256 matches go.dev's.
func TestGoToolchainDownloadIsVerified(t *testing.T) {
	archive := []byte("pretend this is a Go archive")
	sum := sha256.Sum256(archive)
	good := hex.EncodeToString(sum[:])
	var mu sync.Mutex
	index := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		idx := index
		mu.Unlock()
		switch {
		case r.URL.Path == "/index":
			if idx == "" {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = io.WriteString(w, idx)
		case r.URL.Path == "/VERSION":
			_, _ = io.WriteString(w, "go1.99.1\ntime 2026-01-01T00:00:00Z\n")
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			_, _ = io.WriteString(w, good)
		default:
			_, _ = w.Write(archive)
		}
	}))
	defer srv.Close()
	oldIndex, oldVersion, oldBase := goReleaseIndexURL, goVersionURL, goDownloadBaseURL
	defer func() { goReleaseIndexURL, goVersionURL, goDownloadBaseURL = oldIndex, oldVersion, oldBase }()
	goReleaseIndexURL, goVersionURL, goDownloadBaseURL = srv.URL+"/index", srv.URL+"/VERSION", srv.URL+"/dl/"

	mu.Lock()
	index = `[{"version":"go1.99.1","stable":true,"files":[
		{"filename":"go1.99.1.src.tar.gz","os":"","arch":"","sha256":"` + good + `","kind":"source"},
		{"filename":"go1.99.1.linux-armv6l.tar.gz","os":"linux","arch":"armv6l","sha256":"` + good + `","kind":"archive"},
		{"filename":"go1.99.1.linux-amd64.tar.gz","os":"linux","arch":"amd64","sha256":"` + good + `","kind":"archive"}]}]`
	mu.Unlock()
	a, err := goArchiveFor(srv.Client(), "linux", "arm")
	if err != nil || a.Filename != "go1.99.1.linux-armv6l.tar.gz" || a.SHA256 != good {
		t.Fatalf("release list: %+v, %v", a, err)
	}
	dst := filepath.Join(t.TempDir(), "go.tar.gz")
	if err := downloadVerified(srv.Client(), goDownloadBaseURL+a.Filename, dst, a.SHA256, 1<<20); err != nil {
		t.Fatalf("matching checksum rejected: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "go.tar.gz")
	if err := downloadVerified(srv.Client(), goDownloadBaseURL+a.Filename, bad, strings.Repeat("0", 64), 1<<20); err == nil {
		t.Fatal("archive with a wrong checksum accepted")
	}
	if fileExists(bad) {
		t.Fatal("rejected archive left on disk")
	}

	mu.Lock()
	index = ""
	mu.Unlock()
	a, err = goArchiveFor(srv.Client(), "linux", "amd64")
	if err != nil || a.Version != "go1.99.1" || a.Filename != "go1.99.1.linux-amd64.tar.gz" || a.SHA256 != good {
		t.Fatalf("fallback to VERSION + .sha256: %+v, %v", a, err)
	}
}

// 30. The startup banner writes no terminal escape codes into logs.
func TestBannerWithoutEscapesWhenNotTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	(&Server{cfg: &Config{DataDir: "/data"}, cfgPath: "/data/config.json"}).printBanner()
	os.Stdout = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	if bytes.ContainsRune(out, 0x1b) {
		t.Fatalf("escape codes written to a pipe: %q", out)
	}
	if !bytes.Contains(out, []byte(version+" — server started")) {
		t.Fatalf("banner: %q", out)
	}
}
