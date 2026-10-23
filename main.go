//usr/bin/env go run "$0" "$@"; exit $?

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 supersfera

// webhost is a universal production web server for hosting websites, ready out of the box.
//
// ONE file, zero external dependencies (stdlib only), without go.mod.
//
// Three ways to start it:
//
//  1. Straight from source, if Go is installed (nothing else is needed):
//     chmod +x main.go
//     ./main.go   # init on first start, then run
//
//     The first line of the file is a polyglot: a comment for Go and a command
//     for the shell. On ./main.go the kernel returns ENOEXEC (no "#!"), the shell
//     falls back to /bin/sh, and POSIX resolves "//usr/bin/env" to
//     "/usr/bin/env", which runs "go run" on this same file.
//
//  2. Build a binary for the current machine:
//     go build -o webhost main.go && ./webhost
//
//  3. Build binaries for all platforms, even without Go on the system.
//     The build subcommand downloads the Go toolchain into a temporary directory,
//     builds, and removes the toolchain afterwards:
//     ./main.go build -all   # or: ./webhost build -all
//
// A built binary needs neither Go, nor Internet access, nor libc: CGO is off.
// The build is static and works even in an empty FROM scratch container.
//
// Commands:
//
//	./webhost init   # create directory structure, config, CA, demo site
//	./webhost run    # start the server
//	./webhost        # the same: init if needed, then run
//
// Features:
//
//	Virtual hosts: static / spa / proxy / fastcgi (PHP-FPM) / redirect
//	TLS: local CA + self-signed over SNI, built-in ACME v2 (Let's Encrypt, http-01)
//	Cron scheduler, process supervisor (PHP-FPM etc.), outgoing mail with DKIM, backups
//	Static files: ETag, Range, Last-Modified, precompressed .br/.gz, Cache-Control, SPA fallback
//	On-the-fly gzip/deflate compression
//	Reverse proxy: upstream pool, round-robin/least-conn/ip-hash, health checks, retry, WebSocket
//	FastCGI client for PHP-FPM (WordPress, etc.)
//	Security headers, CORS, IP allow/deny (CIDR), basic auth (PBKDF2-SHA256)
//	Rate limiting (token bucket per IP), request body limit, slowloris protection
//	Access logs (combined + JSON) with rotation, Prometheus metrics, health endpoints
//	Admin API: status, reload, atomic tar.gz deploy, release rollback, site management
//	Graceful shutdown, reload on SIGHUP, systemd unit generation
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"log"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	// Embedded time zone database: on a bare system /usr/share/zoneinfo
	// may be missing entirely, and then time.LoadLocation fails, which breaks
	// time zones in cron and dates in feeds.
	// The import adds ~450 KB to the binary and removes the dependency on the OS.
	_ "time/tzdata"
)

const (
	appName = "webhost"
	version = "0.3"
)

// ============================================================================
// Configuration
// ============================================================================

// Config is the root server configuration (config.json).
type Config struct {
	DataDir  string         `json:"data_dir"`
	Listen   ListenConfig   `json:"listen"`
	Admin    AdminConfig    `json:"admin"`
	Log      LogConfig      `json:"log"`
	Limits   LimitsConfig   `json:"limits"`
	ACME     ACMEConfig     `json:"acme"`
	Database DatabaseConfig `json:"database"`
	Backup   BackupConfig   `json:"backup"`

	// Cron: jobs of the scheduler built into the process.
	Cron []CronJobConfig `json:"cron,omitempty"`
	// Processes are external processes under supervision (PHP-FPM and the like).
	Processes []ProcessConfig `json:"processes,omitempty"`

	// Mail - outgoing mail: feedback forms, notifications, password reset.
	Mail MailConfig `json:"mail"`

	Defaults SiteDefaults  `json:"defaults"`
	Sites    []*SiteConfig `json:"sites"`

	path string // file the config was loaded from
}

// CronJobConfig is a single scheduler task.
type CronJobConfig struct {
	Name string `json:"name"`
	// Spec is a five-field cron expression (*/5 * * * *) or a shorthand
	// (@hourly, @daily, @weekly, @monthly, @yearly, @reboot, @every 90s).
	Spec string `json:"spec"`
	// Task: backup | db-compact | mail-flush |
	// cert-renew | log-rotate | prune-releases. Mutually exclusive with Command.
	Task string `json:"task,omitempty"`
	// Command and Args: an external command.
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	// TimeoutSec: after how many seconds the job is killed; 0 = no limit.
	TimeoutSec int   `json:"timeout_sec,omitempty"`
	Enabled    *bool `json:"enabled,omitempty"`
}

// MailConfig configures outgoing mail.
type MailConfig struct {
	Enabled bool `json:"enabled"`
	// From is the default sender address: "Website <noreply@example.com>".
	From string `json:"from"`
	// Relay is the SMTP relay host:port. Empty: deliver directly to the
	// recipients' MX hosts. That needs outbound port 25 open and a correct
	// PTR record, otherwise the mail ends up in spam.
	Relay    string `json:"relay,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	// StartTLS: auto (if possible) | always | never.
	StartTLS string `json:"starttls,omitempty"`
	// InsecureSkipVerify accepts a self-signed relay certificate.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// HELO is the name we introduce ourselves with. Empty: the host name.
	HELO string `json:"helo,omitempty"`
	// DKIM: domain, selector and private RSA key in PEM. The public part
	// must be in the TXT record <selector>._domainkey.<domain>.
	DKIMDomain   string `json:"dkim_domain,omitempty"`
	DKIMSelector string `json:"dkim_selector,omitempty"`
	DKIMKeyFile  string `json:"dkim_key_file,omitempty"`
	// MaxRetries: delivery attempts; RetrySec: the base pause between them.
	// TimeoutSec limits one SMTP session.
	MaxRetries int `json:"max_retries,omitempty"`
	RetrySec   int `json:"retry_sec,omitempty"`
	TimeoutSec int `json:"timeout_sec,omitempty"`
}

// BackupConfig: scheduled full backups.
type BackupConfig struct {
	Enabled bool   `json:"enabled"`
	Dir     string `json:"dir,omitempty"`  // where to store; empty: <data dir>/backups
	Spec    string `json:"spec,omitempty"` // when; empty: @daily
	Keep    int    `json:"keep,omitempty"` // how many copies to keep
	// IncludeSites: whether to include site content in the backup. It can be
	// large, so it is a separate choice.
	IncludeSites bool `json:"include_sites"`
	// Extra: additional paths to back up.
	Extra []string `json:"extra,omitempty"`
}

// ProcessConfig is an external process supervised by the server (PHP-FPM,
// queue workers and the like).
type ProcessConfig struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	Env     []string `json:"env,omitempty"`
	// Restart: always | on-failure | never.
	Restart string `json:"restart,omitempty"`
	// MaxRetries: how many restarts before giving up;
	// 0 = no limit.
	MaxRetries int `json:"max_retries,omitempty"`
	// BackoffSec: initial delay before a restart; it doubles
	// up to BackoffMaxSec.
	BackoffSec     int    `json:"backoff_sec,omitempty"`
	BackoffMaxSec  int    `json:"backoff_max_sec,omitempty"`
	StopTimeoutSec int    `json:"stop_timeout_sec,omitempty"`
	LogFile        string `json:"log_file,omitempty"`
	Enabled        *bool  `json:"enabled,omitempty"`
}

// DatabaseConfig: settings of the embedded storage.
type DatabaseConfig struct {
	// Sync: always = fsync after every transaction (nothing is lost on a
	// power failure); interval = once per second (faster, may lose the
	// last second); never = left to the OS.
	Sync string `json:"sync"`
	// CompactAtMB: journal size at which compaction runs.
	CompactAtMB int `json:"compact_at_mb"`
}

type ListenConfig struct {
	HTTP           string   `json:"http"`            // ":80"
	HTTPS          string   `json:"https"`           // ":443"
	RedirectHTTPS  bool     `json:"redirect_https"`  // 80 → 443
	TrustedProxies []string `json:"trusted_proxies"` // CIDR of TCP peers allowed to set forwarding headers

	// AllowWideTrustedProxies is an explicit opt-in to trusted proxies beyond loopback.
	// Without this flag, run/reload rejects configs whose trusted_proxies are wider than loopback.
	AllowWideTrustedProxies bool `json:"allow_wide_trusted_proxies,omitempty"`

	// DNSServers are fallback DNS servers (1.1.1.1:53), used only
	// when the system has no /etc/resolv.conf. Empty: public resolvers.
	DNSServers []string `json:"dns_servers,omitempty"`
}

type AdminConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"` // "127.0.0.1:9080"
	Token   string `json:"token"`  // Bearer token for the Admin API and /metrics
}

type LogConfig struct {
	Dir        string `json:"dir"`
	AccessFile string `json:"access_file"`
	ErrorFile  string `json:"error_file"`
	Format     string `json:"format"`      // "combined" | "json"
	MaxSizeMB  int    `json:"max_size_mb"` // rotate after this size
	MaxBackups int    `json:"max_backups"`
	Level      string `json:"level"` // debug|info|warn|error
}

type LimitsConfig struct {
	ReadHeaderTimeoutSec int   `json:"read_header_timeout_sec"`
	ReadTimeoutSec       int   `json:"read_timeout_sec"`
	WriteTimeoutSec      int   `json:"write_timeout_sec"` // 0 = no limit (SSE/WebSocket)
	IdleTimeoutSec       int   `json:"idle_timeout_sec"`
	MaxHeaderBytes       int   `json:"max_header_bytes"`
	MaxBodyBytesMB       int64 `json:"max_body_bytes_mb"`
	MaxConnections       int   `json:"max_connections"`
	ShutdownTimeoutSec   int   `json:"shutdown_timeout_sec"`
}

type ACMEConfig struct {
	Enabled         bool   `json:"enabled"`
	DirectoryURL    string `json:"directory_url"`
	Email           string `json:"email"`
	AgreeTOS        bool   `json:"agree_tos"`
	RenewBeforeDays int    `json:"renew_before_days"`
}

// SiteDefaults are values inherited by all sites.
type SiteDefaults struct {
	Security  SecurityConfig  `json:"security"`
	Compress  CompressConfig  `json:"compress"`
	Cache     CacheConfig     `json:"cache"`
	RateLimit RateLimitConfig `json:"rate_limit"`
}

// SiteConfig is a virtual host.
type SiteConfig struct {
	Name     string   `json:"name"`
	Domains  []string `json:"domains"` // wildcards such as *.example.com are supported
	Disabled bool     `json:"disabled"`
	Default  bool     `json:"default"` // fallback if the host does not match

	Type string `json:"type"` // static | spa | proxy | fastcgi | redirect

	Root       string            `json:"root,omitempty"`
	Index      []string          `json:"index,omitempty"`
	TryFiles   []string          `json:"try_files,omitempty"`
	Listing    bool              `json:"dir_listing,omitempty"`
	ErrorPages map[string]string `json:"error_pages,omitempty"` // "404": "/404.html"

	Upstreams   []string     `json:"upstreams,omitempty"` // http://127.0.0.1:3000
	Balance     string       `json:"balance,omitempty"`   // roundrobin | leastconn | iphash
	HealthCheck HealthConfig `json:"health_check,omitempty"`
	ProxyConfig ProxyConfig  `json:"proxy,omitempty"`

	FastCGI FastCGIConfig `json:"fastcgi,omitempty"`

	RedirectTo   string `json:"redirect_to,omitempty"`
	RedirectCode int    `json:"redirect_code,omitempty"`

	TLS       TLSConfig         `json:"tls"`
	Auth      AuthConfig        `json:"auth,omitempty"`
	ACL       ACLConfig         `json:"acl,omitempty"`
	CORS      CORSConfig        `json:"cors,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Security  *SecurityConfig   `json:"security,omitempty"`
	Compress  *CompressConfig   `json:"compress,omitempty"`
	Cache     *CacheConfig      `json:"cache,omitempty"`
	RateLimit *RateLimitConfig  `json:"rate_limit,omitempty"`

	Maintenance bool         `json:"maintenance,omitempty"`
	Deploy      DeployConfig `json:"deploy,omitempty"`
}

type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ACME       bool   `json:"acme"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	MinVersion string `json:"min_version,omitempty"` // "1.2" | "1.3"
}

type AuthConfig struct {
	Enabled bool              `json:"enabled"`
	Realm   string            `json:"realm,omitempty"`
	Users   map[string]string `json:"users,omitempty"` // login -> pbkdf2-sha256$...
	Paths   []string          `json:"paths,omitempty"` // prefixes; empty = entire site
}

type ACLConfig struct {
	Allow []string `json:"allow,omitempty"` // CIDR
	Deny  []string `json:"deny,omitempty"`
}

type CORSConfig struct {
	Enabled          bool     `json:"enabled"`
	Origins          []string `json:"origins,omitempty"`
	Methods          []string `json:"methods,omitempty"`
	Headers          []string `json:"headers,omitempty"`
	ExposeHeaders    []string `json:"expose_headers,omitempty"`
	AllowCredentials bool     `json:"allow_credentials,omitempty"`
	MaxAgeSec        int      `json:"max_age_sec,omitempty"`
}

type SecurityConfig struct {
	Enabled               bool   `json:"enabled"`
	HSTSMaxAgeSec         int    `json:"hsts_max_age_sec"`
	HSTSIncludeSubdomains bool   `json:"hsts_include_subdomains"`
	HSTSPreload           bool   `json:"hsts_preload"`
	FrameOptions          string `json:"frame_options"`
	ContentTypeOptions    bool   `json:"content_type_options"`
	ReferrerPolicy        string `json:"referrer_policy"`
	PermissionsPolicy     string `json:"permissions_policy"`
	CSP                   string `json:"csp"`
	HideServerHeader      bool   `json:"hide_server_header"`
	BlockDotfiles         bool   `json:"block_dotfiles"`
}

type CompressConfig struct {
	Enabled       bool     `json:"enabled"`
	Level         int      `json:"level"`
	MinBytes      int      `json:"min_bytes"`
	Types         []string `json:"types"`
	Precompressed bool     `json:"precompressed"` // serve ready-made .br/.gz files
}

type CacheConfig struct {
	Enabled        bool              `json:"enabled"`
	HTMLControl    string            `json:"html_control"`
	AssetControl   string            `json:"asset_control"`
	DefaultControl string            `json:"default_control"`
	ByExtension    map[string]string `json:"by_extension,omitempty"`
	ETag           bool              `json:"etag"`
}

type RateLimitConfig struct {
	Enabled        bool     `json:"enabled"`
	RequestsPerSec float64  `json:"requests_per_sec"`
	Burst          int      `json:"burst"`
	Exempt         []string `json:"exempt,omitempty"` // CIDR
}

type HealthConfig struct {
	Enabled     bool   `json:"enabled"`
	Path        string `json:"path"`
	IntervalSec int    `json:"interval_sec"`
	TimeoutSec  int    `json:"timeout_sec"`
	FailAfter   int    `json:"fail_after"`
	RiseAfter   int    `json:"rise_after"`
}

type ProxyConfig struct {
	PreserveHost       bool              `json:"preserve_host"`
	StripPrefix        string            `json:"strip_prefix,omitempty"`
	Retries            int               `json:"retries"`
	DialTimeoutSec     int               `json:"dial_timeout_sec"`
	ResponseTimeoutSec int               `json:"response_timeout_sec"` // 0 = no limit
	SetHeaders         map[string]string `json:"set_headers,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
	// WebSocket is accepted so that existing configs load; WebSocket upgrades
	// are always proxied. Configs written by "init" up to 1.2.2 carry
	// "websocket": false in every site, so the key cannot mean "off".
	WebSocket bool `json:"websocket,omitempty"`
}

type FastCGIConfig struct {
	Address    string            `json:"address"`    // unix:/run/php/php-fpm.sock | 127.0.0.1:9000
	IndexFile  string            `json:"index_file"` // index.php
	SplitPath  string            `json:"split_path"` // ".php"
	Params     map[string]string `json:"params,omitempty"`
	TimeoutSec int               `json:"timeout_sec"`
	// ReadOnlyExt (static_extensions): when set, only files with these
	// extensions (".css", "js", ...) are served as files; anything else goes
	// to the application, so .env, *.sql or *.log in the root are never
	// handed out raw. Empty: every existing non-script file is served.
	ReadOnlyExt []string `json:"static_extensions,omitempty"`
}

type DeployConfig struct {
	Enabled      bool `json:"enabled"`
	KeepReleases int  `json:"keep_releases"`
}

// ---------------------------------------------------------------------------

func defaultConfig(dataDir string) *Config {
	httpAddr, httpsAddr, adminAddr := ":80", ":443", "127.0.0.1:9080"
	if os.Geteuid() != 0 {
		httpAddr, httpsAddr = ":8080", ":8443"
	}
	return &Config{
		DataDir: dataDir,
		Listen: ListenConfig{
			HTTP:           httpAddr,
			HTTPS:          httpsAddr,
			RedirectHTTPS:  true,
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		},
		Admin: AdminConfig{Enabled: true, Listen: adminAddr, Token: randomToken(32)},
		Log: LogConfig{
			Dir: filepath.Join(dataDir, "logs"), AccessFile: "access.log", ErrorFile: "error.log",
			Format: "combined", MaxSizeMB: 100, MaxBackups: 7, Level: "info",
		},
		Limits: LimitsConfig{
			ReadHeaderTimeoutSec: 10, ReadTimeoutSec: 120, WriteTimeoutSec: 0, IdleTimeoutSec: 120,
			MaxHeaderBytes: 1 << 20, MaxBodyBytesMB: 64, MaxConnections: 8192, ShutdownTimeoutSec: 25,
		},
		ACME: ACMEConfig{
			Enabled: false, DirectoryURL: acmeLetsEncryptProd, Email: "", AgreeTOS: false, RenewBeforeDays: 30,
		},
		Defaults: SiteDefaults{
			Security: SecurityConfig{
				Enabled: true, HSTSMaxAgeSec: 31536000, HSTSIncludeSubdomains: true, HSTSPreload: false,
				FrameOptions: "SAMEORIGIN", ContentTypeOptions: true, ReferrerPolicy: "strict-origin-when-cross-origin",
				PermissionsPolicy: "geolocation=(), microphone=(), camera=()", CSP: "",
				HideServerHeader: false, BlockDotfiles: true,
			},
			Compress: CompressConfig{
				Enabled: true, Level: 5, MinBytes: 1024, Precompressed: true,
				Types: []string{
					"text/html", "text/css", "text/plain", "text/xml", "text/javascript",
					"application/javascript", "application/json", "application/xml",
					"application/rss+xml", "image/svg+xml", "application/wasm", "application/manifest+json",
				},
			},
			Cache: CacheConfig{
				Enabled: true, ETag: true,
				HTMLControl:    "public, max-age=0, must-revalidate",
				AssetControl:   "public, max-age=31536000, immutable",
				DefaultControl: "public, max-age=604800",
			},
			RateLimit: RateLimitConfig{Enabled: true, RequestsPerSec: 50, Burst: 200},
		},
		Sites: []*SiteConfig{},
	}
}

func demoSite(dataDir string) *SiteConfig {
	return &SiteConfig{
		Name:       "default",
		Domains:    []string{"localhost", "127.0.0.1", "*"},
		Default:    true,
		Type:       "static",
		Root:       filepath.Join(dataDir, "sites", "default", "current"),
		Index:      []string{"index.html", "index.htm"},
		TLS:        TLSConfig{Enabled: true, ACME: false, MinVersion: "1.2"},
		Deploy:     DeployConfig{Enabled: true, KeepReleases: 5},
		ErrorPages: map[string]string{"404": "/404.html"},
	}
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b, path)
}

// parseConfig decodes config.json content over the defaults and normalizes it.
func parseConfig(b []byte, path string) (*Config, error) {
	cfg := defaultConfig(filepath.Dir(path))
	cfg.Sites = nil
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	cfg.path = path
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func saveConfig(cfg *Config, path string) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// setSiteDisabled flips one site's "disabled" flag in config.json and leaves
// everything else as written. Round-tripping through loadConfig+saveConfig
// stored the normalized form: a copy of "defaults" inside every site, after
// which edits of "defaults" no longer reached any site.
func setSiteDisabled(path, name string, disabled bool) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	top, err := decodeOrderedObject(b)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	var sites []json.RawMessage
	if raw, ok := top.vals["sites"]; ok {
		if err := json.Unmarshal(raw, &sites); err != nil {
			return fmt.Errorf("parsing %s: sites: %w", path, err)
		}
	}
	found := false
	for i, raw := range sites {
		site, err := decodeOrderedObject(raw)
		if err != nil {
			continue
		}
		// Sites without a name are called site-N after their position (normalize).
		siteName := fmt.Sprintf("site-%d", i+1)
		if v, ok := site.vals["name"]; ok {
			var n string
			if json.Unmarshal(v, &n) == nil && n != "" {
				siteName = n
			}
		}
		if siteName != name {
			continue
		}
		site.set("disabled", json.RawMessage(strconv.FormatBool(disabled)))
		sites[i] = site.encode()
		found = true
	}
	if !found {
		return fmt.Errorf("site not found in %s: %s", path, name)
	}
	arr := bytes.NewBufferString("[")
	for i, raw := range sites {
		if i > 0 {
			arr.WriteByte(',')
		}
		arr.Write(raw)
	}
	arr.WriteByte(']')
	top.set("sites", arr.Bytes())

	var out bytes.Buffer
	if err := json.Indent(&out, top.encode(), "", "  "); err != nil {
		return err
	}
	out.WriteByte('\n')
	if _, err := parseConfig(out.Bytes(), path); err != nil {
		return err // never write a config the server would refuse to load
	}
	return writeFileAtomic(path, out.Bytes())
}

// orderedObject is a JSON object decoded with its key order kept, so that a
// targeted edit does not reshuffle a hand-written file.
type orderedObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func decodeOrderedObject(b []byte) (*orderedObject, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, errors.New("expected a JSON object")
	}
	o := &orderedObject{vals: map[string]json.RawMessage{}}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, ok := t.(string)
		if !ok {
			return nil, errors.New("expected an object key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		o.set(k, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *orderedObject) set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *orderedObject) encode() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

// writeFileAtomic replaces path via a temporary file, keeping its mode.
func writeFileAtomic(path string, data []byte) error {
	mode := fs.FileMode(0o640)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// normalize fills in defaults and checks that the config makes sense.
func (c *Config) normalize() error {
	if c.DataDir == "" {
		c.DataDir = "."
	}
	abs, err := filepath.Abs(c.DataDir)
	if err == nil {
		c.DataDir = abs
	}
	if c.Log.Dir == "" {
		c.Log.Dir = filepath.Join(c.DataDir, "logs")
	}
	if c.Log.AccessFile == "" {
		c.Log.AccessFile = "access.log"
	}
	if c.Log.ErrorFile == "" {
		c.Log.ErrorFile = "error.log"
	}
	if c.Log.MaxSizeMB <= 0 {
		c.Log.MaxSizeMB = 100
	}
	if c.Limits.ReadHeaderTimeoutSec <= 0 {
		c.Limits.ReadHeaderTimeoutSec = 10
	}
	if c.Limits.IdleTimeoutSec <= 0 {
		c.Limits.IdleTimeoutSec = 120
	}
	if c.Limits.MaxHeaderBytes <= 0 {
		c.Limits.MaxHeaderBytes = 1 << 20
	}
	if c.Limits.MaxBodyBytesMB <= 0 {
		c.Limits.MaxBodyBytesMB = 64
	}
	if c.Limits.ShutdownTimeoutSec <= 0 {
		c.Limits.ShutdownTimeoutSec = 25
	}
	if c.ACME.DirectoryURL == "" {
		c.ACME.DirectoryURL = acmeLetsEncryptProd
	}
	if c.ACME.RenewBeforeDays <= 0 {
		c.ACME.RenewBeforeDays = 30
	}

	names := map[string]bool{}
	defaults := 0
	for i, s := range c.Sites {
		if s.Name == "" {
			s.Name = fmt.Sprintf("site-%d", i+1)
		}
		if names[s.Name] {
			return fmt.Errorf("duplicate site name: %s", s.Name)
		}
		names[s.Name] = true
		if s.Type == "" {
			s.Type = "static"
		}
		switch s.Type {
		case "static", "spa":
			if s.Root == "" {
				return fmt.Errorf("site %s: root is not set", s.Name)
			}
			if len(s.Index) == 0 {
				s.Index = []string{"index.html", "index.htm"}
			}
		case "proxy":
			if len(s.Upstreams) == 0 {
				return fmt.Errorf("site %s: upstreams are not set", s.Name)
			}
		case "fastcgi":
			if s.FastCGI.Address == "" {
				return fmt.Errorf("site %s: fastcgi.address is not set", s.Name)
			}
			if s.Root == "" {
				return fmt.Errorf("site %s: root is not set", s.Name)
			}
			if s.FastCGI.IndexFile == "" {
				s.FastCGI.IndexFile = "index.php"
			}
			if s.FastCGI.SplitPath == "" {
				s.FastCGI.SplitPath = ".php"
			}
			if s.FastCGI.TimeoutSec <= 0 {
				s.FastCGI.TimeoutSec = 60
			}
		case "redirect":
			if s.RedirectTo == "" {
				return fmt.Errorf("site %s: redirect_to is not set", s.Name)
			}
			if s.RedirectCode == 0 {
				s.RedirectCode = http.StatusMovedPermanently
			}
		default:
			return fmt.Errorf("site %s: unknown type %q", s.Name, s.Type)
		}
		if s.Balance == "" {
			s.Balance = "roundrobin"
		}
		if s.ProxyConfig.Retries == 0 {
			s.ProxyConfig.Retries = 2
		}
		if s.ProxyConfig.DialTimeoutSec == 0 {
			s.ProxyConfig.DialTimeoutSec = 10
		}
		if s.HealthCheck.Path == "" {
			s.HealthCheck.Path = "/"
		}
		if s.HealthCheck.IntervalSec <= 0 {
			s.HealthCheck.IntervalSec = 10
		}
		if s.HealthCheck.TimeoutSec <= 0 {
			s.HealthCheck.TimeoutSec = 3
		}
		if s.HealthCheck.FailAfter <= 0 {
			s.HealthCheck.FailAfter = 3
		}
		if s.HealthCheck.RiseAfter <= 0 {
			s.HealthCheck.RiseAfter = 2
		}
		if s.Auth.Realm == "" {
			s.Auth.Realm = "Restricted"
		}
		if s.Auth.Enabled {
			for user, hash := range s.Auth.Users {
				if _, _, _, err := parsePasswordHash(hash); err != nil {
					return fmt.Errorf("site %s: auth.users[%q]: %v (generate one with: webhost hash PASSWORD)", s.Name, user, err)
				}
			}
		}
		if s.Deploy.KeepReleases <= 0 {
			s.Deploy.KeepReleases = 5
		}
		if s.Security == nil {
			cp := c.Defaults.Security
			s.Security = &cp
		}
		if s.Compress == nil {
			cp := c.Defaults.Compress
			s.Compress = &cp
		}
		if s.Cache == nil {
			cp := c.Defaults.Cache
			s.Cache = &cp
		}
		if s.RateLimit == nil {
			cp := c.Defaults.RateLimit
			s.RateLimit = &cp
		}
		if s.Compress.Level <= 0 || s.Compress.Level > 9 {
			s.Compress.Level = 5
		}
		if s.Compress.MinBytes <= 0 {
			s.Compress.MinBytes = 1024
		}
		if s.Default {
			defaults++
		}
		if len(s.Domains) == 0 && !s.Default {
			return fmt.Errorf("site %s: domains are not set", s.Name)
		}
	}
	if defaults > 1 {
		return errors.New("more than one site is marked as default")
	}
	return nil
}

// ============================================================================
// Utilities
// ============================================================================

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// pbkdf2SHA256 is an implementation of PBKDF2 on stdlib (RFC 2898) so as not to pull x/crypto.

// secureTokenEqual compares secrets in constant time, whatever their length.
func secureTokenEqual(provided, want string) bool {
	sumP := sha256.Sum256([]byte(provided))
	sumW := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(sumP[:], sumW[:]) == 1
}

// parseBearerToken extracts the token from Authorization: Bearer ... (without query-leak).
func parseBearerToken(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// isAllInterfacesListen is true for ":port" / "0.0.0.0:port" / "[::]:port".
func isAllInterfacesListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "[::]" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified() || host == "0"
}

// resolveUnderRoot joins candidate onto root and returns the result only if,
// once cleaned and with symlinks resolved, it stays inside the root.
func resolveUnderRoot(root, candidate string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootEval := rootAbs
	if eval, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootEval = eval
	}

	within := func(base, p string) bool {
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return false
		}
		return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}

	candidate = filepath.Clean(filepath.FromSlash(candidate))
	var full string
	switch {
	case candidate == "." || candidate == "" || candidate == string(filepath.Separator):
		full = rootAbs
	case filepath.IsAbs(candidate):
		if !within(rootEval, candidate) && !within(rootAbs, candidate) {
			return "", fmt.Errorf("path escapes site root")
		}
		full = candidate
	default:
		if candidate == ".." || strings.HasPrefix(candidate, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("path escapes site root")
		}
		// Join on the evaluated root: for a non-existent path EvalSymlinks
		// fails below, and callers compare against the evaluated root.
		full = filepath.Join(rootEval, candidate)
	}
	full = filepath.Clean(full)

	if eval, err := filepath.EvalSymlinks(full); err == nil {
		if !within(rootEval, eval) && !within(rootAbs, eval) {
			return "", fmt.Errorf("path escapes site root")
		}
		return eval, nil
	}
	if !within(rootEval, full) && !within(rootAbs, full) {
		return "", fmt.Errorf("path escapes site root")
	}
	return full, nil
}

// urlPathRel turns the URL path (“/a/b”) into a relative path for resolveUnderRoot.
func urlPathRel(upath string) string {
	upath = path.Clean("/" + upath)
	rel := strings.TrimPrefix(upath, "/")
	if rel == "" || rel == "." {
		return "."
	}
	return rel
}

// evalRootAbs returns Abs+EvalSymlinks to the root of the site (current→releases/...).
func evalRootAbs(root string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if eval, err := filepath.EvalSymlinks(rootAbs); err == nil {
		return eval, nil
	}
	return rootAbs, nil
}

// mustEvalRoot is evalRootAbs for serving paths: on error it returns the root as given.
func mustEvalRoot(root string) string {
	if b, err := evalRootAbs(root); err == nil {
		return b
	}
	return root
}

// ensureNoSymlinkComponents runs Lstat on every existing path segment from the
// root to target. Any symlink is an error (except the root itself, which may be current→releases).
func ensureNoSymlinkComponents(root, target string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes root: %s", target)
	}
	if rel == "." {
		return nil
	}
	cur := rootAbs
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		st, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("rejected: path segment is a symbolic link: %s", cur)
		}
	}
	return nil
}

// validateTrustedProxies is fail-closed: anything wider than loopback needs allow_wide_trusted_proxies.
func validateTrustedProxies(cfg *ListenConfig) error {
	if cfg == nil {
		return nil
	}
	if trustedProxiesBeyondLoopback(cfg.TrustedProxies) && !cfg.AllowWideTrustedProxies {
		return fmt.Errorf("trusted_proxies is wider than loopback (only 127.0.0.0/8 and ::1/128 are allowed); set listen.allow_wide_trusted_proxies: true for explicit opt-in")
	}
	return nil
}

// trustedProxiesBeyondLoopback is true if the CIDR list is wider than loopback.
func trustedProxiesBeyondLoopback(list []string) bool {
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			if ip.IsLoopback() {
				continue
			}
			return true
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return true
		}
		ones, bits := n.Mask.Size()
		if n.IP.IsLoopback() && ((bits == 32 && ones >= 8) || (bits == 128 && ones == 128)) {
			continue
		}
		return true
	}
	return false
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	h := sha256.New
	hashLen := sha256.Size
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	buf := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		prf := hmac.New(h, password)
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

const pbkdf2Iterations = 210000

// dummyPasswordHash equalises basic-auth timing for unknown users. Computed
// lazily: a 210k-iteration PBKDF2 at package init would slow every CLI command.
var dummyPasswordHash = sync.OnceValue(func() string { return hashPassword(randomToken(16)) })

func hashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk))
}

// Minimum salt and derived-key sizes accepted in a stored hash. "webhost hash"
// writes 16 and 32 bytes.
const (
	minPasswordSaltLen = 8
	minPasswordKeyLen  = 16
)

// parsePasswordHash splits "pbkdf2-sha256$<iter>$<salt>$<key>".
func parsePasswordHash(encoded string) (iter int, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return 0, nil, nil, errors.New("expected pbkdf2-sha256$<iterations>$<salt>$<key>")
	}
	iter, err = strconv.Atoi(parts[1])
	if err != nil || iter <= 0 || iter > 5000000 {
		return 0, nil, nil, errors.New("invalid iteration count")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < minPasswordSaltLen {
		return 0, nil, nil, errors.New("salt is missing or too short")
	}
	// An empty (e.g. truncated) key used to compare equal to the empty
	// PBKDF2 output for ANY password, so short keys are rejected outright.
	key, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(key) < minPasswordKeyLen {
		return 0, nil, nil, errors.New("derived key is missing or too short")
	}
	return iter, salt, key, nil
}

func verifyPassword(password, encoded string) bool {
	iter, salt, want, err := parsePasswordHash(encoded)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parseCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func hostOnly(hostport string) string {
	h := hostport
	if strings.HasPrefix(h, "[") { // IPv6 literal
		if i := strings.Index(h, "]"); i >= 0 {
			return strings.ToLower(h[1:i])
		}
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		if !strings.Contains(h[:i], ":") {
			h = h[:i]
		}
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func clientIP(r *http.Request) net.IP {
	if v := r.Context().Value(ctxRealIP); v != nil {
		if ip, ok := v.(net.IP); ok {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func atoiDefault(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// ============================================================================
// Logging (size-based rotation, levels, access log)
// ============================================================================

type rotatingWriter struct {
	mu         sync.Mutex
	path       string
	maxSize    int64
	maxBackups int
	size       int64
	f          *os.File
}

func newRotatingWriter(path string, maxSizeMB, maxBackups int) (*rotatingWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	w := &rotatingWriter{path: path, maxSize: int64(maxSizeMB) << 20, maxBackups: maxBackups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f = f
	w.size = st.Size()
	return nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	if w.maxSize > 0 && w.size+int64(len(p)) > w.maxSize {
		w.rotate()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// Rotate forces a rotation now (cron task "log-rotate"). rotate itself
// expects w.mu to be held, as Write does; calling it bare raced with writers.
func (w *rotatingWriter) Rotate() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotate()
}

// rotate must be called with w.mu held.
func (w *rotatingWriter) rotate() {
	_ = w.f.Close()
	w.f = nil
	for i := w.maxBackups - 1; i >= 1; i-- {
		older := fmt.Sprintf("%s.%d", w.path, i+1)
		newer := fmt.Sprintf("%s.%d", w.path, i)
		if fileExists(newer) {
			_ = os.Rename(newer, older)
		}
	}
	if w.maxBackups >= 1 {
		_ = os.Rename(w.path, w.path+".1")
	} else {
		_ = os.Remove(w.path)
	}
	_ = w.open()
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		err := w.f.Close()
		w.f = nil
		return err
	}
	return nil
}

type logLevel int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarn
	levelError
)

func parseLevel(s string) logLevel {
	switch strings.ToLower(s) {
	case "debug":
		return levelDebug
	case "warn", "warning":
		return levelWarn
	case "error":
		return levelError
	default:
		return levelInfo
	}
}

// Logger is the system log, written to stdout and to a file.
type Logger struct {
	level atomic.Int32 // LogLevel; changes on reload
	out   *log.Logger
}

func newLogger(level string, w io.Writer) *Logger {
	l := &Logger{out: log.New(w, "", 0)}
	l.level.Store(int32(parseLevel(level)))
	return l
}

func (l *Logger) logf(lv logLevel, tag, format string, args ...interface{}) {
	if int32(lv) < l.level.Load() {
		return
	}
	msg := fmt.Sprintf(format, args...)
	l.out.Printf("%s %-5s %s", time.Now().Format("2006-01-02T15:04:05.000Z07:00"), tag, msg)
}

func (l *Logger) Debugf(f string, a ...interface{}) { l.logf(levelDebug, "DEBUG", f, a...) }
func (l *Logger) Infof(f string, a ...interface{})  { l.logf(levelInfo, "INFO", f, a...) }
func (l *Logger) Warnf(f string, a ...interface{})  { l.logf(levelWarn, "WARN", f, a...) }
func (l *Logger) Errorf(f string, a ...interface{}) { l.logf(levelError, "ERROR", f, a...) }

// accessLogger writes combined or JSON access lines.
type accessLogger struct {
	format atomic.Value // string; changes on reload
	w      io.Writer
	mu     sync.Mutex
}

type accessRecord struct {
	Time      string  `json:"time"`
	ID        string  `json:"id"`
	Site      string  `json:"site"`
	RemoteIP  string  `json:"remote_ip"`
	Method    string  `json:"method"`
	Host      string  `json:"host"`
	URI       string  `json:"uri"`
	Proto     string  `json:"proto"`
	Status    int     `json:"status"`
	Bytes     int64   `json:"bytes"`
	Duration  float64 `json:"duration_ms"`
	Referer   string  `json:"referer,omitempty"`
	UserAgent string  `json:"user_agent,omitempty"`
	Upstream  string  `json:"upstream,omitempty"`
	TLS       string  `json:"tls,omitempty"`
}

func newAccessLogger(format string, w io.Writer) *accessLogger {
	a := &accessLogger{w: w}
	a.format.Store(format)
	return a
}

func (a *accessLogger) log(rec *accessRecord) {
	if a == nil || a.w == nil {
		return
	}
	var line string
	if f, _ := a.format.Load().(string); f == "json" {
		b, err := json.Marshal(rec)
		if err != nil {
			return
		}
		line = string(b) + "\n"
	} else {
		// combined + response time and site name
		line = fmt.Sprintf("%s - - [%s] \"%s %s %s\" %d %d %q %q %.3fms %s\n",
			rec.RemoteIP, time.Now().Format("02/Jan/2006:15:04:05 -0700"),
			rec.Method, rec.URI, rec.Proto, rec.Status, rec.Bytes,
			rec.Referer, rec.UserAgent, rec.Duration, rec.Site)
	}
	a.mu.Lock()
	_, _ = io.WriteString(a.w, line)
	a.mu.Unlock()
}

// ============================================================================
// Metrics (Prometheus text format, without external dependencies)
// ============================================================================

var metricBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

type siteMetrics struct {
	mu          sync.Mutex
	requests    map[string]uint64 // "method|code" -> count
	bytesOut    uint64
	bytesIn     uint64
	durCount    uint64
	durSum      float64
	durBuckets  []uint64
	upstreamUp  map[string]int
	rateLimited uint64
	errors      uint64
}

func newSiteMetrics() *siteMetrics {
	return &siteMetrics{
		requests:   map[string]uint64{},
		durBuckets: make([]uint64, len(metricBuckets)),
		upstreamUp: map[string]int{},
	}
}

type Metrics struct {
	mu         sync.RWMutex
	sites      map[string]*siteMetrics
	started    time.Time
	inFlight   int64
	totalConns int64
}

func newMetrics() *Metrics {
	return &Metrics{sites: map[string]*siteMetrics{}, started: time.Now()}
}

func (m *Metrics) site(name string) *siteMetrics {
	m.mu.RLock()
	sm := m.sites[name]
	m.mu.RUnlock()
	if sm != nil {
		return sm
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if sm = m.sites[name]; sm == nil {
		sm = newSiteMetrics()
		m.sites[name] = sm
	}
	return sm
}

func (m *Metrics) observe(site, method string, code int, bytesOut, bytesIn int64, dur time.Duration) {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
	default:
		method = "OTHER"
	}
	if bytesIn < 0 { // ContentLength = -1 for chunked/unknown bodies
		bytesIn = 0
	}
	if bytesOut < 0 {
		bytesOut = 0
	}
	sm := m.site(site)
	sm.mu.Lock()
	sm.requests[method+"|"+strconv.Itoa(code)]++
	sm.bytesOut += uint64(bytesOut)
	sm.bytesIn += uint64(bytesIn)
	sm.durCount++
	secs := dur.Seconds()
	sm.durSum += secs
	for i, b := range metricBuckets {
		if secs <= b {
			sm.durBuckets[i]++
		}
	}
	if code >= 500 {
		sm.errors++
	}
	sm.mu.Unlock()
}

func (m *Metrics) rateLimited(site string) {
	sm := m.site(site)
	sm.mu.Lock()
	sm.rateLimited++
	sm.mu.Unlock()
}

func (m *Metrics) setUpstream(site, up string, healthy bool) {
	sm := m.site(site)
	sm.mu.Lock()
	if healthy {
		sm.upstreamUp[up] = 1
	} else {
		sm.upstreamUp[up] = 0
	}
	sm.mu.Unlock()
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

func (m *Metrics) writeProm(w io.Writer) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# HELP webhost_build_info Build information\n# TYPE webhost_build_info gauge\n")
	fmt.Fprintf(&b, "webhost_build_info{version=%q,go=%q} 1\n", version, runtime.Version())
	fmt.Fprintf(&b, "# HELP webhost_uptime_seconds Uptime\n# TYPE webhost_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "webhost_uptime_seconds %.3f\n", time.Since(m.started).Seconds())
	fmt.Fprintf(&b, "# HELP webhost_requests_in_flight In-flight requests\n# TYPE webhost_requests_in_flight gauge\n")
	fmt.Fprintf(&b, "webhost_requests_in_flight %d\n", atomic.LoadInt64(&m.inFlight))
	fmt.Fprintf(&b, "# HELP webhost_connections_total Total accepted connections\n# TYPE webhost_connections_total counter\n")
	fmt.Fprintf(&b, "webhost_connections_total %d\n", atomic.LoadInt64(&m.totalConns))

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(&b, "# HELP webhost_goroutines Number of goroutines\n# TYPE webhost_goroutines gauge\nwebhost_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(&b, "# HELP webhost_memory_alloc_bytes Allocated memory\n# TYPE webhost_memory_alloc_bytes gauge\nwebhost_memory_alloc_bytes %d\n", ms.Alloc)
	fmt.Fprintf(&b, "# HELP webhost_memory_sys_bytes Memory obtained from the OS\n# TYPE webhost_memory_sys_bytes gauge\nwebhost_memory_sys_bytes %d\n", ms.Sys)
	fmt.Fprintf(&b, "# HELP webhost_gc_pause_seconds_total Total GC pause time\n# TYPE webhost_gc_pause_seconds_total counter\nwebhost_gc_pause_seconds_total %.6f\n", float64(ms.PauseTotalNs)/1e9)

	fmt.Fprintf(&b, "# HELP webhost_http_requests_total Number of requests\n# TYPE webhost_http_requests_total counter\n")
	m.mu.RLock()
	names := make([]string, 0, len(m.sites))
	for n := range m.sites {
		names = append(names, n)
	}
	m.mu.RUnlock()
	sort.Strings(names)

	type snapshot struct {
		name string
		sm   *siteMetrics
	}
	snaps := make([]snapshot, 0, len(names))
	for _, n := range names {
		snaps = append(snaps, snapshot{n, m.site(n)})
	}
	for _, s := range snaps {
		s.sm.mu.Lock()
		keys := make([]string, 0, len(s.sm.requests))
		for k := range s.sm.requests {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts := strings.SplitN(k, "|", 2)
			fmt.Fprintf(&b, "webhost_http_requests_total{site=%q,method=%q,code=%q} %d\n",
				escapeLabel(s.name), parts[0], parts[1], s.sm.requests[k])
		}
		s.sm.mu.Unlock()
	}

	fmt.Fprintf(&b, "# HELP webhost_http_request_duration_seconds Request duration histogram\n# TYPE webhost_http_request_duration_seconds histogram\n")
	for _, s := range snaps {
		s.sm.mu.Lock()
		for i, bk := range metricBuckets {
			fmt.Fprintf(&b, "webhost_http_request_duration_seconds_bucket{site=%q,le=%q} %d\n",
				escapeLabel(s.name), strconv.FormatFloat(bk, 'g', -1, 64), s.sm.durBuckets[i])
		}
		fmt.Fprintf(&b, "webhost_http_request_duration_seconds_bucket{site=%q,le=\"+Inf\"} %d\n", escapeLabel(s.name), s.sm.durCount)
		fmt.Fprintf(&b, "webhost_http_request_duration_seconds_sum{site=%q} %.6f\n", escapeLabel(s.name), s.sm.durSum)
		fmt.Fprintf(&b, "webhost_http_request_duration_seconds_count{site=%q} %d\n", escapeLabel(s.name), s.sm.durCount)
		s.sm.mu.Unlock()
	}

	fmt.Fprintf(&b, "# HELP webhost_response_bytes_total Bytes sent\n# TYPE webhost_response_bytes_total counter\n")
	for _, s := range snaps {
		s.sm.mu.Lock()
		fmt.Fprintf(&b, "webhost_response_bytes_total{site=%q} %d\n", escapeLabel(s.name), s.sm.bytesOut)
		fmt.Fprintf(&b, "webhost_request_bytes_total{site=%q} %d\n", escapeLabel(s.name), s.sm.bytesIn)
		fmt.Fprintf(&b, "webhost_rate_limited_total{site=%q} %d\n", escapeLabel(s.name), s.sm.rateLimited)
		fmt.Fprintf(&b, "webhost_server_errors_total{site=%q} %d\n", escapeLabel(s.name), s.sm.errors)
		ups := make([]string, 0, len(s.sm.upstreamUp))
		for u := range s.sm.upstreamUp {
			ups = append(ups, u)
		}
		sort.Strings(ups)
		for _, u := range ups {
			fmt.Fprintf(&b, "webhost_upstream_healthy{site=%q,upstream=%q} %d\n", escapeLabel(s.name), escapeLabel(u), s.sm.upstreamUp[u])
		}
		s.sm.mu.Unlock()
	}
	_, _ = w.Write(b.Bytes())
}

// ============================================================================
// RATE LIMITING (token bucket over IP)
// ============================================================================

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   float64
	exempt  []*net.IPNet
}

func newRateLimiter(rps float64, burst int, exempt []string) *rateLimiter {
	if rps <= 0 {
		rps = 50
	}
	if burst <= 0 {
		burst = int(rps * 4)
	}
	return &rateLimiter{
		buckets: map[string]*bucket{},
		rate:    rps,
		burst:   float64(burst),
		exempt:  parseCIDRs(exempt),
	}
}

func (rl *rateLimiter) allow(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ipInAny(ip, rl.exempt) {
		return true
	}
	key := rateLimitKey(ip)
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.buckets[key]
	if b == nil {
		if len(rl.buckets) >= rateLimitMaxBuckets {
			rl.evictLocked(now)
		}
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateLimitMaxBuckets caps the number of tracked clients. Without it, a flood of
// requests from millions of addresses (IPv6 gives them away for free) would grow
// the map until OOM: the scheduled cleanup runs only every few minutes.
const rateLimitMaxBuckets = 100000

// rateLimitKey: IPv4 by address, IPv6 by /64 prefix, which is usually
// assigned to a single client as a whole.
func rateLimitKey(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

// evictLocked frees space in a full table. A full bucket is no different
// from a new one, so removing it is safe. If there are too few of those (an
// attack from many addresses), a tenth of the entries is removed at random:
// Go's map iteration order is random.
func (rl *rateLimiter) evictLocked(now time.Time) {
	refill := time.Duration(rl.burst / rl.rate * float64(time.Second))
	for k, b := range rl.buckets {
		if now.Sub(b.last) >= refill {
			delete(rl.buckets, k)
		}
	}
	if n := len(rl.buckets) - rateLimitMaxBuckets*9/10; n > 0 {
		for k := range rl.buckets {
			delete(rl.buckets, k)
			if n--; n == 0 {
				break
			}
		}
	}
}

func (rl *rateLimiter) cleanup(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	rl.mu.Lock()
	for k, b := range rl.buckets {
		if b.last.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
	rl.mu.Unlock()
}

// ============================================================================
// TLS: local CA, self-signed over SNI, built-in ACME v2 (RFC 8555)
// ============================================================================

const (
	acmeLetsEncryptProd    = "https://acme-v02.api.letsencrypt.org/directory"
	acmeLetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type certManager struct {
	dir string
	log *Logger

	mu     sync.RWMutex
	cache  map[string]*tls.Certificate // host -> certificate (self-signed/ACME)
	manual map[string]*tls.Certificate // host -> certificate from the config (tls.cert_file)

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte

	challenges sync.Map // token -> keyAuthorization

	acme      *acmeClient
	acmeHosts map[string]bool
	renewDays int

	// allowHost reports whether a self-signed certificate may be minted for
	// an SNI name and under which name: exact domains mint for themselves,
	// names matched by "*.example.com" mint ONE wildcard certificate (not one
	// per random subdomain). nil = allow all.
	allowHost   func(host string) (mintAs string, ok bool)
	renewCancel context.CancelFunc
}

func validSNIHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return !strings.Contains(h, "..")
}

func newCertManager(dir string, lg *Logger) (*certManager, error) {
	for _, d := range []string{dir, filepath.Join(dir, "local"), filepath.Join(dir, "acme")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	cm := &certManager{
		dir: dir, log: lg,
		cache: map[string]*tls.Certificate{}, manual: map[string]*tls.Certificate{},
		acmeHosts: map[string]bool{}, renewDays: 30,
	}
	if err := cm.loadOrCreateCA(); err != nil {
		return nil, err
	}
	return cm, nil
}

func (cm *certManager) caPaths() (string, string) {
	return filepath.Join(cm.dir, "ca.crt"), filepath.Join(cm.dir, "ca.key")
}

func (cm *certManager) loadOrCreateCA() error {
	crtPath, keyPath := cm.caPaths()
	if fileExists(crtPath) && fileExists(keyPath) {
		crtPEM, err := os.ReadFile(crtPath)
		if err != nil {
			return err
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		blk, _ := pem.Decode(crtPEM)
		if blk == nil {
			return errors.New("corrupt ca.crt")
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return err
		}
		kblk, _ := pem.Decode(keyPEM)
		if kblk == nil {
			return errors.New("corrupt ca.key")
		}
		key, err := x509.ParseECPrivateKey(kblk.Bytes)
		if err != nil {
			return err
		}
		if time.Now().Before(cert.NotAfter) {
			cm.caCert, cm.caKey, cm.caPEM = cert, key, crtPEM
			return nil
		}
		cm.log.Warnf("local CA expired, generating a new one")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   appName + " local CA",
			Organization: []string{appName},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(crtPath, crtPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	cm.caCert, cm.caKey, cm.caPEM = cert, key, crtPEM
	cm.log.Infof("created local CA: %s", crtPath)
	return nil
}

// selfSigned issues a certificate for host, signed by the local CA.
func (cm *certManager) selfSigned(host string) (*tls.Certificate, error) {
	safe := strings.NewReplacer("*", "_wildcard", "/", "_", ":", "_").Replace(host)
	crtPath := filepath.Join(cm.dir, "local", safe+".crt")
	keyPath := filepath.Join(cm.dir, "local", safe+".key")

	if fileExists(crtPath) && fileExists(keyPath) {
		if c, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
			if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
				if time.Now().Before(leaf.NotAfter.Add(-24 * time.Hour)) {
					c.Leaf = leaf
					return &c, nil
				}
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{appName + " self-signed"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 397),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
		if !strings.HasPrefix(host, "*.") && strings.Count(host, ".") >= 1 {
			tpl.DNSNames = append(tpl.DNSNames, "*."+host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, cm.caCert, &key.PublicKey, cm.caKey)
	if err != nil {
		return nil, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	crtPEM = append(crtPEM, cm.caPEM...)
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	_ = os.WriteFile(crtPath, crtPEM, 0o644)
	_ = os.WriteFile(keyPath, keyPEM, 0o600)

	c, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
		c.Leaf = leaf
	}
	return &c, nil
}

// loadKeyPair loads a certificate configured in tls.cert_file / tls.key_file.
func loadKeyPair(certFile, keyFile string) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
		c.Leaf = leaf
	}
	return &c, nil
}

// manualCert returns the configured certificate currently served for host.
func (cm *certManager) manualCert(host string) *tls.Certificate {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.manual[host]
}

// replaceManual installs the configured certificates of a new runtime state.
// The set is replaced, not merged: a domain that left the config, or a site
// that switched from cert_file to ACME, no longer gets the old certificate.
func (cm *certManager) replaceManual(m map[string]*tls.Certificate) {
	if m == nil {
		m = map[string]*tls.Certificate{}
	}
	cm.mu.Lock()
	cm.manual = m
	cm.mu.Unlock()
}

func (cm *certManager) lookup(host string) *tls.Certificate {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if c, ok := cm.manual[host]; ok {
		return c
	}
	if c, ok := cm.cache[host]; ok {
		return c
	}
	// wildcard *.example.com
	if i := strings.Index(host, "."); i > 0 {
		wc := "*" + host[i:]
		if c, ok := cm.manual[wc]; ok {
			return c
		}
		if c, ok := cm.cache[wc]; ok {
			return c
		}
	}
	return nil
}

func (cm *certManager) store(host string, c *tls.Certificate) {
	cm.mu.Lock()
	cm.cache[host] = c
	cm.mu.Unlock()
}

// GetCertificate is the tls.Config callback: it returns the certificate for the SNI name.
func (cm *certManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if host == "" {
		if h, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String()); err == nil {
			host = h
		} else {
			host = "localhost"
		}
	}
	if c := cm.lookup(host); c != nil {
		if c.Leaf == nil || time.Now().Before(c.Leaf.NotAfter) {
			return c, nil
		}
	}
	// Unknown / malformed SNI (including arbitrary IP literals): never mint a new
	// key+cert per name (disk/memory DoS, path tricks like "..\\" on Windows).
	// Serve the listener-IP certificate instead.
	localIP := "localhost"
	if hello.Conn != nil {
		if h, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String()); err == nil {
			localIP = h
		}
	}
	allowed := host == localIP
	if !allowed && (net.ParseIP(host) != nil || validSNIHost(host)) {
		if cm.allowHost == nil {
			allowed = true
		} else if mintAs, ok := cm.allowHost(host); ok {
			allowed, host = true, mintAs
		}
	}
	if !allowed {
		host = localIP
	}
	if c := cm.lookup(host); c != nil && (c.Leaf == nil || time.Now().Before(c.Leaf.NotAfter)) {
		return c, nil
	}
	// ACME domains are renewed in the background; meanwhile a temporary self-signed certificate is issued.
	c, err := cm.selfSigned(host)
	if err != nil {
		return nil, err
	}
	cm.store(host, c)
	return c, nil
}

// --- ACME HTTP-01 ---

func (cm *certManager) acmeChallengeHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			token := strings.TrimPrefix(r.URL.Path, prefix)
			if v, ok := cm.challenges.Load(token); ok {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, v.(string))
				return
			}
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type acmeClient struct {
	dirURL   string
	email    string
	agreeTOS bool
	dir      struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
		RevokeCert string `json:"revokeCert"`
		KeyChange  string `json:"keyChange"`
	}
	key    *ecdsa.PrivateKey
	kid    string
	nonce  string
	mu     sync.Mutex
	client *http.Client
	cm     *certManager
	log    *Logger
}

func newACMEClient(cm *certManager, cfg ACMEConfig, lg *Logger) (*acmeClient, error) {
	// webhost's outbound client: system roots plus imported/baked ones and the
	// fallback resolver. The default client ignored both, so on a system
	// without a CA bundle "webhost roots -import" did not help ACME.
	client, err := newOutboundClient(45 * time.Second)
	if err != nil {
		lg.Warnf("acme: %v — falling back to the default HTTP client", err)
		client = &http.Client{Timeout: 45 * time.Second}
	}
	a := &acmeClient{
		dirURL: cfg.DirectoryURL, email: cfg.Email, agreeTOS: cfg.AgreeTOS,
		client: client, cm: cm, log: lg,
	}
	if err := cm.switchACMEDirectory(cfg.DirectoryURL); err != nil {
		lg.Warnf("acme: %v", err)
	}
	keyPath := filepath.Join(cm.dir, "acme", "account.key")
	if fileExists(keyPath) {
		b, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("corrupt account.key")
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		a.key = k
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		a.key = k
	}
	if b, err := os.ReadFile(filepath.Join(cm.dir, "acme", "account.kid")); err == nil {
		a.kid = strings.TrimSpace(string(b))
	}
	return a, nil
}

// switchACMEDirectory keeps one ACME server's account and certificates apart
// from another's. After directory_url changed (staging → production) the old
// account.kid broke every request, and staging certificates kept being served
// until they neared expiry. They are moved aside to acme/previous-<host>-<time>/;
// account.key stays (one key may hold accounts at several CAs).
func (cm *certManager) switchACMEDirectory(dirURL string) error {
	acmeDir := filepath.Join(cm.dir, "acme")
	marker := filepath.Join(acmeDir, "directory.txt")
	b, err := os.ReadFile(marker)
	prev := strings.TrimSpace(string(b))
	if err == nil && prev == dirURL {
		return nil
	}
	if err == nil && prev != "" {
		host := "unknown"
		if u, perr := url.Parse(prev); perr == nil && u.Host != "" {
			host = strings.NewReplacer(":", "_", "/", "_").Replace(u.Host)
		}
		old := filepath.Join(acmeDir, "previous-"+host+"-"+time.Now().Format("20060102-150405"))
		if err := os.MkdirAll(old, 0o700); err != nil {
			return err
		}
		ents, _ := os.ReadDir(acmeDir)
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || n == "account.key" {
				continue
			}
			if n == "account.kid" || strings.HasSuffix(n, ".crt") || strings.HasSuffix(n, ".key") {
				if err := os.Rename(filepath.Join(acmeDir, n), filepath.Join(old, n)); err != nil {
					return err
				}
			}
		}
		if cm.log != nil {
			cm.log.Infof("acme: directory changed from %s to %s — previous account and certificates moved to %s", prev, dirURL, old)
		}
	}
	if err := os.MkdirAll(acmeDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(marker, []byte(dirURL+"\n"), 0o600)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *acmeClient) jwk() map[string]string {
	x := a.key.PublicKey.X.Bytes()
	y := a.key.PublicKey.Y.Bytes()
	xb, yb := make([]byte, 32), make([]byte, 32)
	copy(xb[32-len(x):], x)
	copy(yb[32-len(y):], y)
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64u(xb), "y": b64u(yb)}
}

func (a *acmeClient) thumbprint() string {
	j := a.jwk()
	canon := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, j["crv"], j["kty"], j["x"], j["y"])
	sum := sha256.Sum256([]byte(canon))
	return b64u(sum[:])
}

func (a *acmeClient) loadDirectory() error {
	if a.dir.NewOrder != "" {
		return nil
	}
	resp, err := a.client.Get(a.dirURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&a.dir)
}

func (a *acmeClient) getNonce() (string, error) {
	a.mu.Lock()
	n := a.nonce
	a.nonce = ""
	a.mu.Unlock()
	if n != "" {
		return n, nil
	}
	req, err := http.NewRequest(http.MethodHead, a.dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	n = resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", errors.New("acme: empty Replay-Nonce")
	}
	return n, nil
}

// post sends a signed JWS request (payload == nil → POST-as-GET).
func (a *acmeClient) post(url string, payload interface{}) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		nonce, err := a.getNonce()
		if err != nil {
			return nil, nil, err
		}
		protected := map[string]interface{}{"alg": "ES256", "nonce": nonce, "url": url}
		if a.kid != "" {
			protected["kid"] = a.kid
		} else {
			protected["jwk"] = a.jwk()
		}
		ph, err := json.Marshal(protected)
		if err != nil {
			return nil, nil, err
		}
		var pl string
		if payload != nil {
			pb, err := json.Marshal(payload)
			if err != nil {
				return nil, nil, err
			}
			pl = b64u(pb)
		}
		signing := b64u(ph) + "." + pl
		sum := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, a.key, sum[:])
		if err != nil {
			return nil, nil, err
		}
		sig := make([]byte, 64)
		rb, sb := r.Bytes(), s.Bytes()
		copy(sig[32-len(rb):32], rb)
		copy(sig[64-len(sb):], sb)
		body, err := json.Marshal(map[string]string{"protected": b64u(ph), "payload": pl, "signature": b64u(sig)})
		if err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("User-Agent", appName+"/"+version)
		resp, err := a.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if n := resp.Header.Get("Replay-Nonce"); n != "" {
			a.mu.Lock()
			a.nonce = n
			a.mu.Unlock()
		}
		if resp.StatusCode >= 400 && bytes.Contains(data, []byte("badNonce")) {
			lastErr = fmt.Errorf("acme: badNonce")
			continue
		}
		if resp.StatusCode >= 400 {
			return resp, data, fmt.Errorf("acme %s: %d %s", url, resp.StatusCode, strings.TrimSpace(string(data)))
		}
		return resp, data, nil
	}
	if lastErr == nil {
		lastErr = errors.New("acme: request failed")
	}
	return nil, nil, lastErr
}

func (a *acmeClient) register() error {
	if err := a.loadDirectory(); err != nil {
		return err
	}
	if a.kid != "" {
		return nil
	}
	payload := map[string]interface{}{"termsOfServiceAgreed": a.agreeTOS}
	if a.email != "" {
		payload["contact"] = []string{"mailto:" + a.email}
	}
	resp, _, err := a.post(a.dir.NewAccount, payload)
	if err != nil {
		return err
	}
	kid := resp.Header.Get("Location")
	if kid == "" {
		return errors.New("acme: server did not return account Location")
	}
	a.kid = kid
	_ = os.WriteFile(filepath.Join(a.cm.dir, "acme", "account.kid"), []byte(kid), 0o600)
	a.log.Infof("acme: account registered")
	return nil
}

type acmeOrder struct {
	Status         string   `json:"status"`
	Expires        string   `json:"expires"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

type acmeAuthz struct {
	Status     string `json:"status"`
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Token  string `json:"token"`
		Status string `json:"status"`
	} `json:"challenges"`
}

// obtain gets a certificate for a set of domains (the first one is the CN).
func (a *acmeClient) obtain(domains []string) (*tls.Certificate, error) {
	if !a.agreeTOS {
		return nil, errors.New("acme: terms of service not accepted (acme.agree_tos=false)")
	}
	if err := a.register(); err != nil {
		return nil, err
	}
	ids := make([]map[string]string, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, map[string]string{"type": "dns", "value": d})
	}
	resp, data, err := a.post(a.dir.NewOrder, map[string]interface{}{"identifiers": ids})
	if err != nil {
		return nil, err
	}
	orderURL := resp.Header.Get("Location")
	var order acmeOrder
	if err := json.Unmarshal(data, &order); err != nil {
		return nil, err
	}

	for _, authzURL := range order.Authorizations {
		_, ad, err := a.post(authzURL, nil)
		if err != nil {
			return nil, err
		}
		var az acmeAuthz
		if err := json.Unmarshal(ad, &az); err != nil {
			return nil, err
		}
		if az.Status == "valid" {
			continue
		}
		var chURL, token string
		for _, ch := range az.Challenges {
			if ch.Type == "http-01" {
				chURL, token = ch.URL, ch.Token
				break
			}
		}
		if chURL == "" {
			return nil, fmt.Errorf("acme: no http-01 challenge for %s", az.Identifier.Value)
		}
		keyAuth := token + "." + a.thumbprint()
		a.cm.challenges.Store(token, keyAuth)

		if _, _, err := a.post(chURL, map[string]string{}); err != nil {
			a.cm.challenges.Delete(token)
			return nil, err
		}
		deadline := time.Now().Add(2 * time.Minute)
		for {
			time.Sleep(2 * time.Second)
			_, pd, err := a.post(authzURL, nil)
			if err != nil {
				a.cm.challenges.Delete(token)
				return nil, err
			}
			var st acmeAuthz
			if err := json.Unmarshal(pd, &st); err != nil {
				a.cm.challenges.Delete(token)
				return nil, err
			}
			if st.Status == "valid" {
				break
			}
			if st.Status == "invalid" || st.Status == "revoked" || st.Status == "expired" {
				a.cm.challenges.Delete(token)
				return nil, fmt.Errorf("acme: validation for %s finished with status %s", az.Identifier.Value, st.Status)
			}
			if time.Now().After(deadline) {
				a.cm.challenges.Delete(token)
				return nil, fmt.Errorf("acme: validation timeout for %s", az.Identifier.Value)
			}
		}
		a.cm.challenges.Delete(token)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           domains,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, certKey)
	if err != nil {
		return nil, err
	}
	if _, fd, err := a.post(order.Finalize, map[string]string{"csr": b64u(csrDER)}); err != nil {
		return nil, err
	} else if err := json.Unmarshal(fd, &order); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(2 * time.Minute)
	for order.Status != "valid" {
		if order.Status == "invalid" {
			return nil, errors.New("acme: order rejected")
		}
		if time.Now().After(deadline) {
			return nil, errors.New("acme: order finalization timeout")
		}
		time.Sleep(2 * time.Second)
		_, od, err := a.post(orderURL, nil)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(od, &order); err != nil {
			return nil, err
		}
	}
	if order.Certificate == "" {
		return nil, errors.New("acme: empty certificate URL")
	}
	_, chain, err := a.post(order.Certificate, nil)
	if err != nil {
		return nil, err
	}
	kb, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})

	safe := strings.ReplaceAll(domains[0], "*", "_wildcard")
	_ = os.WriteFile(filepath.Join(a.cm.dir, "acme", safe+".crt"), chain, 0o644)
	_ = os.WriteFile(filepath.Join(a.cm.dir, "acme", safe+".key"), keyPEM, 0o600)

	c, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return nil, err
	}
	if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
		c.Leaf = leaf
	}
	a.log.Infof("acme: obtained certificate for %s (valid until %s)", domains[0], c.Leaf.NotAfter.Format(time.RFC3339))
	return &c, nil
}

// ensureACME loads the certificate from disk or issues a new one if needed.
func (cm *certManager) ensureACME(domain string) {
	if cm.acme == nil {
		return
	}
	safe := strings.ReplaceAll(domain, "*", "_wildcard")
	crtPath := filepath.Join(cm.dir, "acme", safe+".crt")
	keyPath := filepath.Join(cm.dir, "acme", safe+".key")
	if fileExists(crtPath) && fileExists(keyPath) {
		if c, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
			if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
				c.Leaf = leaf
				if time.Now().Before(leaf.NotAfter.AddDate(0, 0, -cm.renewDays)) {
					cm.store(domain, &c)
					return
				}
			}
		}
	}
	cm.log.Infof("acme: requesting certificate for %s", domain)
	c, err := cm.acme.obtain([]string{domain})
	if err != nil {
		cm.log.Errorf("acme: %s: %v", domain, err)
		return
	}
	cm.store(domain, c)
}

func (cm *certManager) startRenewal(ctx context.Context, domains []string) {
	if cm.acme == nil {
		return
	}
	cm.mu.Lock()
	if cm.renewCancel != nil {
		cm.renewCancel()
		cm.renewCancel = nil
	}
	if len(domains) == 0 {
		cm.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	cm.renewCancel = cancel
	cm.mu.Unlock()
	go func() {
		run := func() {
			for _, d := range domains {
				select {
				case <-ctx.Done():
					return
				default:
				}
				cm.ensureACME(d)
			}
		}
		run()
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
}

func isPublicDomain(h string) bool {
	h = strings.TrimPrefix(h, "*.")
	if h == "" || h == "localhost" || net.ParseIP(h) != nil {
		return false
	}
	if !strings.Contains(h, ".") {
		return false
	}
	for _, suf := range []string{".local", ".localhost", ".test", ".invalid", ".internal", ".lan", ".home"} {
		if strings.HasSuffix(h, suf) {
			return false
		}
	}
	return true
}

func tlsMinVersion(s string) uint16 {
	switch s {
	case "1.3":
		return tls.VersionTLS13
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	default:
		return tls.VersionTLS12
	}
}

// ============================================================================
// FASTCGI (PHP-FPM client)
// ============================================================================

const (
	fcgiVersion      = 1
	fcgiBeginRequest = 1
	fcgiEndRequest   = 3
	fcgiParams       = 4
	fcgiStdin        = 5
	fcgiStdout       = 6
	fcgiStderr       = 7
	fcgiResponder    = 1
	fcgiMaxContent   = 65528
)

func parseFCGIAddr(addr string) (string, string) {
	if strings.HasPrefix(addr, "unix:") {
		return "unix", strings.TrimPrefix(addr, "unix:")
	}
	if strings.HasPrefix(addr, "/") {
		return "unix", addr
	}
	if strings.HasPrefix(addr, "tcp://") {
		return "tcp", strings.TrimPrefix(addr, "tcp://")
	}
	return "tcp", addr
}

func writeFCGIRecord(w io.Writer, recType byte, reqID uint16, content []byte) error {
	hdr := make([]byte, 8)
	hdr[0] = fcgiVersion
	hdr[1] = recType
	binary.BigEndian.PutUint16(hdr[2:4], reqID)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(content)))
	hdr[6] = 0
	hdr[7] = 0
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(content) > 0 {
		if _, err := w.Write(content); err != nil {
			return err
		}
	}
	return nil
}

func writeFCGIStream(w io.Writer, recType byte, reqID uint16, data []byte) error {
	for len(data) > 0 {
		n := len(data)
		if n > fcgiMaxContent {
			n = fcgiMaxContent
		}
		if err := writeFCGIRecord(w, recType, reqID, data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func encodeFCGIParams(params map[string]string) []byte {
	var buf bytes.Buffer
	putLen := func(n int) {
		if n < 128 {
			buf.WriteByte(byte(n))
			return
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(n)|1<<31)
		buf.Write(b)
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := params[k]
		putLen(len(k))
		putLen(len(v))
		buf.WriteString(k)
		buf.WriteString(v)
	}
	return buf.Bytes()
}

func writeFCGIRequest(conn net.Conn, reqID uint16, params map[string]string, body io.Reader) error {
	bw := bufio.NewWriterSize(conn, 32*1024)
	begin := make([]byte, 8)
	binary.BigEndian.PutUint16(begin[0:2], fcgiResponder)
	begin[2] = fcgiKeepConn // The connection is reused, the backend does not close it
	if err := writeFCGIRecord(bw, fcgiBeginRequest, reqID, begin); err != nil {
		return err
	}
	if err := writeFCGIStream(bw, fcgiParams, reqID, encodeFCGIParams(params)); err != nil {
		return err
	}
	if err := writeFCGIRecord(bw, fcgiParams, reqID, nil); err != nil {
		return err
	}
	if body != nil {
		buf := make([]byte, 32*1024)
		for {
			n, err := body.Read(buf)
			if n > 0 {
				if werr := writeFCGIStream(bw, fcgiStdin, reqID, buf[:n]); werr != nil {
					return werr
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	}
	if err := writeFCGIRecord(bw, fcgiStdin, reqID, nil); err != nil {
		return err
	}
	return bw.Flush()
}

// errFCGIClosed: the backend closed the connection without FCGI_END_REQUEST. The
// response is there and counts as complete, but the connection is not returned to the pool.
var errFCGIClosed = errors.New("fastcgi: connection closed without END_REQUEST")

func readFCGIResponse(conn net.Conn, reqID uint16, stdout io.Writer, stderr *bytes.Buffer) error {
	br := bufio.NewReaderSize(conn, 32*1024)
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return errFCGIClosed
			}
			return err
		}
		recType := hdr[1]
		id := binary.BigEndian.Uint16(hdr[2:4])
		length := int(binary.BigEndian.Uint16(hdr[4:6]))
		padding := int(hdr[6]) // paddingLength; hdr[7] reserved (PHP-FPM aligns records to 8 bytes)
		content := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(br, content); err != nil {
				return err
			}
		}
		if padding > 0 {
			if _, err := io.CopyN(io.Discard, br, int64(padding)); err != nil {
				return err
			}
		}
		if id != reqID {
			continue
		}
		switch recType {
		case fcgiStdout:
			if length > 0 {
				if _, err := stdout.Write(content); err != nil {
					return err
				}
			}
		case fcgiStderr:
			if stderr.Len() < 64*1024 {
				stderr.Write(content)
			}
		case fcgiEndRequest:
			return nil
		}
	}
}

// fcgiParamsFor collects the CGI variables for a request. Behind a trusted
// proxy PHP sees the client, not the proxy: REMOTE_ADDR is the resolved client
// IP, and HTTPS / REQUEST_SCHEME / SERVER_PORT follow X-Forwarded-Proto and
// X-Forwarded-Port (both only survive ServeHTTP when the peer is trusted).
func fcgiParamsFor(r *http.Request, scriptFile, scriptName, pathInfo, docRoot string, extra map[string]string, listenAddr string) map[string]string {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host, port = r.RemoteAddr, ""
	}
	if ip := clientIP(r); ip != nil {
		if peer := net.ParseIP(host); peer == nil || !peer.Equal(ip) {
			host, port = ip.String(), "" // the client's port is not known
		}
	}
	scheme := schemeOf(r)
	isTLS := scheme == "https"
	serverPort := "80"
	if isTLS {
		serverPort = "443"
	}
	if fp := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); validPortString(fp) {
		serverPort = fp
	} else if isTLS == (r.TLS != nil) {
		// The client talked to this listener directly: its port is the one.
		if _, p, err := net.SplitHostPort(listenAddr); err == nil && p != "" {
			serverPort = p
		}
	}
	p := map[string]string{
		"GATEWAY_INTERFACE": "CGI/1.1",
		"SERVER_SOFTWARE":   appName + "/" + version,
		"SERVER_PROTOCOL":   r.Proto,
		"SERVER_NAME":       hostOnly(r.Host),
		"SERVER_PORT":       serverPort,
		"REQUEST_METHOD":    r.Method,
		"REQUEST_URI":       r.URL.RequestURI(),
		"DOCUMENT_URI":      r.URL.Path,
		"DOCUMENT_ROOT":     docRoot,
		"SCRIPT_FILENAME":   scriptFile,
		"SCRIPT_NAME":       scriptName,
		"PATH_INFO":         pathInfo,
		"QUERY_STRING":      r.URL.RawQuery,
		"REMOTE_ADDR":       host,
		"REMOTE_PORT":       port,
		"CONTENT_TYPE":      r.Header.Get("Content-Type"),
		"REQUEST_SCHEME":    scheme,
	}
	if pathInfo != "" {
		p["PATH_TRANSLATED"] = filepath.Join(docRoot, filepath.FromSlash(pathInfo))
	}
	if r.ContentLength > 0 {
		p["CONTENT_LENGTH"] = strconv.FormatInt(r.ContentLength, 10)
	} else {
		p["CONTENT_LENGTH"] = ""
	}
	if isTLS {
		p["HTTPS"] = "on"
	}
	for k, vs := range r.Header {
		if strings.Contains(k, "_") {
			continue // "X-Forwarded_For" would alias HTTP_X_FORWARDED_FOR (trust-model bypass)
		}
		key := "HTTP_" + strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
		if key == "HTTP_PROXY" { // httpoxy protection
			continue
		}
		p[key] = strings.Join(vs, ", ")
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// Pool of idle FastCGI connections (FCGI_KEEP_CONN). Without it every
// request opened a new TCP connection, and under load the local ports
// ran out (TIME_WAIT). An idle connection holds a PHP-FPM worker, so
// the pool is bounded and closes connections idle longer than fcgiIdleTimeout.
const (
	fcgiKeepConn       = 1
	fcgiMaxIdlePerAddr = 32
	fcgiIdleTimeout    = 30 * time.Second
)

type fcgiIdleConn struct {
	c     net.Conn
	since time.Time
}

var (
	fcgiIdleMu    sync.Mutex
	fcgiIdle      = map[string][]fcgiIdleConn{}
	fcgiSweepOnce sync.Once
)

func fcgiGetConn(network, address string) (net.Conn, error) {
	key := network + "|" + address
	for {
		fcgiIdleMu.Lock()
		list := fcgiIdle[key]
		if len(list) == 0 {
			fcgiIdleMu.Unlock()
			break
		}
		ic := list[len(list)-1]
		fcgiIdle[key] = list[:len(list)-1]
		fcgiIdleMu.Unlock()
		if time.Since(ic.since) < fcgiIdleTimeout && fcgiConnAlive(ic.c) {
			return ic.c, nil
		}
		_ = ic.c.Close()
	}
	return net.DialTimeout(network, address, 10*time.Second)
}

// fcgiConnAlive: the backend may have closed an idle connection (e.g.
// PHP-FPM after pm.max_requests); such a connection cannot be reused.
func fcgiConnAlive(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
	var one [1]byte
	_, err := c.Read(one[:])
	_ = c.SetReadDeadline(time.Time{})
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func fcgiPutConn(network, address string, c net.Conn) {
	fcgiSweepOnce.Do(func() { go fcgiSweep() })
	_ = c.SetDeadline(time.Time{})
	key := network + "|" + address
	fcgiIdleMu.Lock()
	if len(fcgiIdle[key]) < fcgiMaxIdlePerAddr {
		fcgiIdle[key] = append(fcgiIdle[key], fcgiIdleConn{c: c, since: time.Now()})
		c = nil
	}
	fcgiIdleMu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// fcgiSweep closes connections idle for too long and frees their workers.
func fcgiSweep() {
	for range time.Tick(fcgiIdleTimeout / 2) {
		var stale []net.Conn
		fcgiIdleMu.Lock()
		for key, list := range fcgiIdle {
			keep := list[:0]
			for _, ic := range list {
				if time.Since(ic.since) >= fcgiIdleTimeout {
					stale = append(stale, ic.c)
				} else {
					keep = append(keep, ic)
				}
			}
			if len(keep) == 0 {
				delete(fcgiIdle, key)
			} else {
				fcgiIdle[key] = keep
			}
		}
		fcgiIdleMu.Unlock()
		for _, c := range stale {
			_ = c.Close()
		}
	}
}

func serveFastCGI(w http.ResponseWriter, r *http.Request, addr string, params map[string]string, timeout time.Duration) error {
	network, address := parseFCGIAddr(addr)
	conn, err := fcgiGetConn(network, address)
	if err != nil {
		return fmt.Errorf("fastcgi dial %s: %w", addr, err)
	}
	reusable := false
	defer func() {
		if reusable {
			fcgiPutConn(network, address, conn)
		} else {
			_ = conn.Close()
		}
	}()
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	const reqID uint16 = 1
	writeErr := make(chan error, 1)
	go func() { writeErr <- writeFCGIRequest(conn, reqID, params, r.Body) }()

	var stderr bytes.Buffer
	pr, pw := io.Pipe()
	readErr := make(chan error, 1)
	go func() {
		err := readFCGIResponse(conn, reqID, pw, &stderr)
		readErr <- err
		if errors.Is(err, errFCGIClosed) {
			err = nil
		}
		pw.CloseWithError(err)
	}()
	defer pr.Close()

	br := bufio.NewReader(pr)
	mh, err := textproto.NewReader(br).ReadMIMEHeader()
	if err != nil {
		if e := <-writeErr; e != nil {
			return fmt.Errorf("fastcgi write: %w", e)
		}
		if stderr.Len() > 0 {
			return fmt.Errorf("fastcgi: %s", strings.TrimSpace(stderr.String()))
		}
		return fmt.Errorf("fastcgi response: %w", err)
	}

	status := http.StatusOK
	if s := mh.Get("Status"); s != "" {
		if code, err := strconv.Atoi(strings.Fields(s)[0]); err == nil && code >= 100 && code < 600 {
			status = code
		}
		mh.Del("Status")
	}
	h := w.Header()
	for k, vs := range mh {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	w.WriteHeader(status)
	_, copyErr := io.Copy(w, br)
	wErr := <-writeErr
	// Back to the pool only after a clean exchange: the request was written in full
	// and the response read up to FCGI_END_REQUEST.
	if copyErr == nil && wErr == nil {
		select {
		case rErr := <-readErr:
			reusable = rErr == nil
		default:
		}
	}
	return copyErr
}

// ============================================================================
// UPSTREAM POOL / REVERSE PROXY
// ============================================================================

type upstream struct {
	raw      string
	url      *url.URL
	healthy  int32 // 1 = healthy
	fails    int32
	rises    int32
	inflight int64
	proxy    *httputil.ReverseProxy
}

func (u *upstream) isHealthy() bool { return atomic.LoadInt32(&u.healthy) == 1 }

type upstreamPool struct {
	name  string
	ups   []*upstream
	rr    uint64
	mode  string
	check HealthConfig
	// transport is shared by the proxy and the health checks, so both see
	// the same TLS settings (insecure_skip_verify, roots) and dial timeout.
	transport *http.Transport
}

type ctxKey string

const (
	ctxRealIP    ctxKey = "real_ip"
	ctxSiteName  ctxKey = "site"
	ctxRequestID ctxKey = "req_id"
	ctxAttempt   ctxKey = "proxy_attempt"
	ctxUpstream  ctxKey = "upstream"
	ctxScheme    ctxKey = "scheme"
)

type proxyAttempt struct {
	err   error
	wrote bool
}

// rewriteProxyPath maps the request path onto the upstream. strip_prefix is
// removed only at a segment boundary ("/api" covers "/api" and "/api/x", not
// "/apiary"), then the upstream URL's own path is prepended. RawPath is kept
// in step, so encoded characters such as %2F reach the upstream as sent.
func rewriteProxyPath(u *url.URL, strip string, target *url.URL) {
	p, raw := u.Path, u.EscapedPath()
	if strip = strings.TrimSuffix(strip, "/"); strip != "" && (p == strip || strings.HasPrefix(p, strip+"/")) {
		p = strings.TrimPrefix(p, strip)
		esc := (&url.URL{Path: strip}).EscapedPath()
		if raw == esc || strings.HasPrefix(raw, esc+"/") {
			raw = strings.TrimPrefix(raw, esc)
		} else {
			raw = (&url.URL{Path: p}).EscapedPath() // the prefix itself was percent-encoded
		}
		if p == "" {
			p, raw = "/", "/"
		}
	}
	if target.Path != "" && target.Path != "/" {
		p = strings.TrimSuffix(target.Path, "/") + p
		raw = strings.TrimSuffix(target.EscapedPath(), "/") + raw
	}
	u.Path, u.RawPath = p, ""
	if raw != (&url.URL{Path: p}).EscapedPath() {
		u.RawPath = raw
	}
}

func newUpstreamPool(site *SiteConfig, lg *Logger) (*upstreamPool, error) {
	p := &upstreamPool{name: site.Name, mode: site.Balance, check: site.HealthCheck}
	tlsCfg := &tls.Config{InsecureSkipVerify: site.ProxyConfig.InsecureSkipVerify}
	if pool, _, err := rootPool(); err == nil {
		// Same roots as all other outbound HTTPS: system store plus
		// imported/baked roots (the only ones on a system without a bundle).
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(site.ProxyConfig.DialTimeoutSec) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       tlsCfg,
	}
	if site.ProxyConfig.ResponseTimeoutSec > 0 {
		transport.ResponseHeaderTimeout = time.Duration(site.ProxyConfig.ResponseTimeoutSec) * time.Second
	}
	p.transport = transport

	for _, raw := range site.Upstreams {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("site %s: invalid upstream %q", site.Name, raw)
		}
		if u.Scheme == "" {
			u.Scheme = "http"
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("site %s: upstream scheme %q is not allowed (http/https only)", site.Name, u.Scheme)
		}
		up := &upstream{raw: raw, url: u, healthy: 1}
		target := u
		sc := site
		rp := &httputil.ReverseProxy{
			// Rewrite instead of the legacy Director: with Director a client could
			// strip X-Real-IP and other headers added by the proxy by naming them in
			// Connection. Here they are restored after the hop-by-hop headers are removed.
			Rewrite: func(pr *httputil.ProxyRequest) {
				r := pr.Out
				for _, k := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-Ip", "X-Request-Id"} {
					if vals := pr.In.Header.Values(k); len(vals) > 0 {
						r.Header.Del(k)
						for _, v := range vals {
							r.Header.Add(k, v)
						}
					}
				}
				r.URL.Scheme = target.Scheme
				r.URL.Host = target.Host
				rewriteProxyPath(r.URL, sc.ProxyConfig.StripPrefix, target)
				if !sc.ProxyConfig.PreserveHost {
					r.Host = target.Host
				}
				if _, ok := r.Header["User-Agent"]; !ok {
					r.Header.Set("User-Agent", appName+"/"+version)
				}
				for k, v := range sc.ProxyConfig.SetHeaders {
					r.Header.Set(k, v)
				}
			},
			Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if a, ok := r.Context().Value(ctxAttempt).(*proxyAttempt); ok {
					a.err = err
					return
				}
				lg.Warnf("proxy %s: %v", target.Host, err)
				http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
			},
			ModifyResponse: func(resp *http.Response) error {
				resp.Header.Del("X-Powered-By")
				return nil
			},
			FlushInterval: 200 * time.Millisecond,
		}
		up.proxy = rp
		p.ups = append(p.ups, up)
	}
	return p, nil
}

func (p *upstreamPool) pick(r *http.Request, skip map[string]bool) *upstream {
	healthy := make([]*upstream, 0, len(p.ups))
	for _, u := range p.ups {
		if u.isHealthy() && !skip[u.raw] {
			healthy = append(healthy, u)
		}
	}
	if len(healthy) == 0 {
		for _, u := range p.ups { // all are down: try any upstream not tried yet
			if !skip[u.raw] {
				healthy = append(healthy, u)
			}
		}
	}
	if len(healthy) == 0 {
		return nil
	}
	switch p.mode {
	case "leastconn":
		best := healthy[0]
		for _, u := range healthy[1:] {
			if atomic.LoadInt64(&u.inflight) < atomic.LoadInt64(&best.inflight) {
				best = u
			}
		}
		return best
	case "iphash":
		ip := clientIP(r)
		key := "-"
		if ip != nil {
			key = ip.String()
		}
		sum := sha256.Sum256([]byte(key))
		idx := int(binary.BigEndian.Uint32(sum[:4])) % len(healthy)
		if idx < 0 {
			idx = -idx
		}
		return healthy[idx]
	default:
		n := atomic.AddUint64(&p.rr, 1)
		return healthy[int(n%uint64(len(healthy)))]
	}
}

func (p *upstreamPool) startHealthChecks(ctx context.Context, m *Metrics, lg *Logger) {
	if !p.check.Enabled || len(p.ups) == 0 {
		for _, u := range p.ups {
			m.setUpstream(p.name, u.raw, true)
		}
		return
	}
	client := &http.Client{
		// The proxy's own transport: with the default one, an upstream behind
		// a self-signed certificate (proxy.insecure_skip_verify) was proxied
		// fine but always reported unhealthy.
		Transport: p.transport,
		Timeout:   time.Duration(p.check.TimeoutSec) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, u := range p.ups {
		up := u
		go func() {
			t := time.NewTicker(time.Duration(p.check.IntervalSec) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
				target := strings.TrimSuffix(up.url.String(), "/") + p.check.Path
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					continue
				}
				resp, err := client.Do(req)
				ok := err == nil && resp.StatusCode < 500
				if resp != nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
					resp.Body.Close()
				}
				if ok {
					atomic.StoreInt32(&up.fails, 0)
					if !up.isHealthy() {
						if atomic.AddInt32(&up.rises, 1) >= int32(p.check.RiseAfter) {
							atomic.StoreInt32(&up.healthy, 1)
							atomic.StoreInt32(&up.rises, 0)
							lg.Infof("upstream %s (%s) is available again", up.raw, p.name)
						}
					}
				} else {
					atomic.StoreInt32(&up.rises, 0)
					if up.isHealthy() {
						if atomic.AddInt32(&up.fails, 1) >= int32(p.check.FailAfter) {
							atomic.StoreInt32(&up.healthy, 0)
							lg.Warnf("upstream %s (%s) marked unavailable: %v", up.raw, p.name, err)
						}
					}
				}
				m.setUpstream(p.name, up.raw, up.isHealthy())
			}
		}()
	}
}

// ============================================================================
// ResponseWriter wrappers + compression
// ============================================================================

type respWriter struct {
	http.ResponseWriter
	status   int
	size     int64
	wrote    bool
	upstream string
}

func (w *respWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		// 1xx (100 Continue, 103 Early Hints) is informational: the final
		// status is still to come, so do not mark the response as written.
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.wrote = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *respWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += int64(n)
	return n, err
}

func (w *respWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack is not supported")
}

func (w *respWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type gzipResponseWriter struct {
	http.ResponseWriter
	site     *runtimeSite
	gz       *gzip.Writer
	wrote    bool
	compress bool
	status   int
}

func (g *gzipResponseWriter) shouldCompress() bool {
	h := g.Header()
	if h.Get("Content-Encoding") != "" {
		return false
	}
	if g.status == http.StatusNoContent || g.status == http.StatusNotModified || g.status == http.StatusPartialContent {
		return false
	}
	ct := h.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	if !g.site.compressTypes[ct] {
		return false
	}
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.Atoi(cl); err == nil && n < g.site.cfg.Compress.MinBytes {
			return false
		}
	}
	return true
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.wrote {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		g.ResponseWriter.WriteHeader(code) // informational, final status follows
		return
	}
	g.wrote = true
	g.status = code
	h := g.Header()
	h.Add("Vary", "Accept-Encoding")
	if g.shouldCompress() {
		g.compress = true
		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
		g.gz = g.site.gzPool.Get().(*gzip.Writer)
		g.gz.Reset(g.ResponseWriter)
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wrote {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(b))
		}
		g.WriteHeader(http.StatusOK)
	}
	if g.compress {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

func (g *gzipResponseWriter) Flush() {
	if g.compress && g.gz != nil {
		_ = g.gz.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := g.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack is not supported")
}

func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *gzipResponseWriter) close() {
	if g.compress && g.gz != nil {
		_ = g.gz.Close()
		g.site.gzPool.Put(g.gz)
		g.gz = nil
	}
}

// ============================================================================
// RUNTIME: compiled state of sites
// ============================================================================

type runtimeSite struct {
	cfg           *SiteConfig
	srv           *Server
	root          string
	handler       http.Handler
	pool          *upstreamPool
	limiter       *rateLimiter
	allow, deny   []*net.IPNet
	authPaths     []string
	compressTypes map[string]bool
	gzPool        *sync.Pool
	maintenance   int32
	disabled      int32
}

type wildcardEntry struct {
	suffix string // ".example.com"
	site   *runtimeSite
}

type runtimeState struct {
	cfg      *Config
	sites    []*runtimeSite
	exact    map[string]*runtimeSite
	wildcard []wildcardEntry
	fallback *runtimeSite
	trusted  []*net.IPNet
	maxBody  int64
	cancel   context.CancelFunc
	// manual: certificates from tls.cert_file/key_file by host, installed
	// into the cert manager together with this state.
	manual map[string]*tls.Certificate
}

func (s *runtimeState) match(host string) *runtimeSite {
	if rs, ok := s.exact[host]; ok {
		return rs
	}
	for _, w := range s.wildcard {
		if strings.HasSuffix(host, w.suffix) || host == strings.TrimPrefix(w.suffix, ".") {
			return w.site
		}
	}
	return s.fallback
}

func (s *Server) buildRuntime(cfg *Config, parent context.Context) (*runtimeState, error) {
	ctx, cancel := context.WithCancel(parent)
	st := &runtimeState{
		cfg:     cfg,
		exact:   map[string]*runtimeSite{},
		trusted: parseCIDRs(cfg.Listen.TrustedProxies),
		maxBody: cfg.Limits.MaxBodyBytesMB << 20,
		cancel:  cancel,
		manual:  map[string]*tls.Certificate{},
	}
	for _, sc := range cfg.Sites {
		if sc.Disabled {
			continue
		}
		rs := &runtimeSite{cfg: sc, srv: s}
		if sc.Root != "" {
			abs, err := filepath.Abs(sc.Root)
			if err != nil {
				cancel()
				return nil, err
			}
			rs.root = abs
		}
		rs.allow = parseCIDRs(sc.ACL.Allow)
		rs.deny = parseCIDRs(sc.ACL.Deny)
		rs.authPaths = sc.Auth.Paths
		if sc.Maintenance {
			rs.maintenance = 1
		}
		rs.compressTypes = map[string]bool{}
		for _, t := range sc.Compress.Types {
			rs.compressTypes[strings.ToLower(strings.TrimSpace(t))] = true
		}
		level := sc.Compress.Level
		rs.gzPool = &sync.Pool{New: func() interface{} {
			zw, err := gzip.NewWriterLevel(io.Discard, level)
			if err != nil {
				zw = gzip.NewWriter(io.Discard)
			}
			return zw
		}}
		if sc.RateLimit.Enabled {
			rs.limiter = newRateLimiter(sc.RateLimit.RequestsPerSec, sc.RateLimit.Burst, sc.RateLimit.Exempt)
			lim := rs.limiter
			go func() {
				t := time.NewTicker(5 * time.Minute)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						lim.cleanup(15 * time.Minute)
					}
				}
			}()
		}
		if sc.Type == "proxy" {
			pool, err := newUpstreamPool(sc, s.log)
			if err != nil {
				cancel()
				return nil, err
			}
			rs.pool = pool
			pool.startHealthChecks(ctx, s.metrics, s.log)
		}
		rs.handler = rs.buildHandler()

		for _, d := range sc.Domains {
			d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
			switch {
			case d == "" || d == "*":
				if st.fallback == nil {
					st.fallback = rs
				}
			case strings.HasPrefix(d, "*."):
				st.wildcard = append(st.wildcard, wildcardEntry{suffix: d[1:], site: rs})
			default:
				st.exact[d] = rs
			}
		}
		if sc.Default {
			st.fallback = rs
		}
		// TLS certificates from files. They take effect when this state is
		// installed (replaceManual), so removed domains stop using them.
		if sc.TLS.Enabled && sc.TLS.CertFile != "" && sc.TLS.KeyFile != "" {
			c, err := loadKeyPair(sc.TLS.CertFile, sc.TLS.KeyFile)
			if err != nil {
				s.log.Errorf("site %s: certificate: %v", sc.Name, err)
			}
			for _, d := range sc.Domains {
				d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
				if d == "" || d == "*" {
					continue
				}
				switch {
				case c != nil:
					st.manual[d] = c
				case s.certs != nil && s.certs.manualCert(d) != nil:
					// Unreadable file (mid-renewal?): keep serving the
					// certificate loaded before rather than none.
					st.manual[d] = s.certs.manualCert(d)
				}
			}
		}
		st.sites = append(st.sites, rs)
	}
	if st.fallback == nil && len(st.sites) > 0 {
		st.fallback = st.sites[0]
	}
	// The most specific wildcard wins ("*.a.example.com" before
	// "*.example.com"), not whichever comes first in the config.
	sort.SliceStable(st.wildcard, func(i, j int) bool {
		return len(st.wildcard[i].suffix) > len(st.wildcard[j].suffix)
	})
	return st, nil
}

// ============================================================================
// SITE MIDDLEWARE
// ============================================================================

func (rs *runtimeSite) buildHandler() http.Handler {
	var h http.Handler = http.HandlerFunc(rs.serveContent)
	h = rs.withCompression(h)
	h = rs.withResponseHeaders(h)
	h = rs.withCORS(h)
	h = rs.withAuth(h)
	h = rs.withACL(h)
	h = rs.withRateLimit(h)
	h = rs.withMaintenance(h)
	return h
}

func (rs *runtimeSite) withMaintenance(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&rs.maintenance) == 1 && !strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Retry-After", "120")
			rs.serveError(w, r, http.StatusServiceUnavailable, "Under maintenance")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rs *runtimeSite) withRateLimit(next http.Handler) http.Handler {
	if rs.limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rs.limiter.allow(clientIP(r)) {
			rs.srv.metrics.rateLimited(rs.cfg.Name)
			w.Header().Set("Retry-After", "1")
			rs.serveError(w, r, http.StatusTooManyRequests, "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rs *runtimeSite) withACL(next http.Handler) http.Handler {
	if len(rs.allow) == 0 && len(rs.deny) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if ipInAny(ip, rs.deny) {
			rs.serveError(w, r, http.StatusForbidden, "Access denied")
			return
		}
		if len(rs.allow) > 0 && !ipInAny(ip, rs.allow) {
			rs.serveError(w, r, http.StatusForbidden, "Access denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rs *runtimeSite) withAuth(next http.Handler) http.Handler {
	a := rs.cfg.Auth
	if !a.Enabled || len(a.Users) == 0 {
		return next
	}
	split := ""
	if rs.cfg.Type == "fastcgi" {
		split = strings.ToLower(rs.cfg.FastCGI.SplitPath)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected := len(rs.authPaths) == 0
		// Compare the cleaned path in lower case: otherwise "/./admin",
		// "//admin" or "/ADMIN" (on a case-insensitive file system) bypass the protection.
		cleanPath := strings.ToLower(path.Clean("/" + r.URL.Path))
		for _, candidate := range authCandidatePaths(cleanPath, split) {
			for _, p := range rs.authPaths {
				lp := strings.ToLower(p)
				if strings.HasPrefix(candidate, lp) || strings.HasPrefix(candidate+"/", lp) {
					protected = true
					break
				}
			}
			if protected {
				break
			}
		}
		if !protected {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if ok {
			hash, found := a.Users[user]
			if !found {
				hash = dummyPasswordHash() // equalise timing: no user enumeration
			}
			if basicAuthVerifier().verify(r.Context(), user, pass, hash) && found {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q, charset=\"UTF-8\"", a.Realm))
		rs.serveError(w, r, http.StatusUnauthorized, "Authorization required")
	})
}

// authCandidatePaths lists the paths auth.paths must be matched against. On a
// FastCGI site "/index.php/admin" runs index.php with PATH_INFO "/admin", and
// front controllers (Laravel, Symfony, ...) route that to /admin, so every
// tail after "<split_path>/" counts as a requested path too.
func authCandidatePaths(cleanPath, split string) []string {
	out := []string{cleanPath}
	if split == "" {
		return out
	}
	rest := cleanPath
	for {
		i := strings.Index(rest, split+"/")
		if i < 0 {
			return out
		}
		rest = rest[i+len(split):]
		out = append(out, rest)
	}
}

// basicAuthCache remembers recent successful basic-auth checks: without it
// every request (each asset of a page) costs a 210k-iteration PBKDF2. It also
// bounds how many PBKDF2 computations run at once, so a flood of wrong
// passwords queues up instead of occupying every core.
type basicAuthCache struct {
	mu      sync.Mutex
	key     []byte
	entries map[[sha256.Size]byte]time.Time
	sem     chan struct{}
}

const (
	basicAuthCacheTTL = 5 * time.Minute
	basicAuthCacheMax = 4096
)

var basicAuthVerifier = sync.OnceValue(func() *basicAuthCache {
	n := runtime.NumCPU() / 2
	if n < 1 {
		n = 1
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &basicAuthCache{key: key, entries: map[[sha256.Size]byte]time.Time{}, sem: make(chan struct{}, n)}
})

func (c *basicAuthCache) verify(ctx context.Context, user, pass, encoded string) bool {
	// Keyed HMAC, not the password itself: the hash is part of the key, so a
	// password change in the config invalidates old entries by itself.
	m := hmac.New(sha256.New, c.key)
	for _, part := range []string{user, pass, encoded} {
		m.Write([]byte(part))
		m.Write([]byte{0})
	}
	var id [sha256.Size]byte
	copy(id[:], m.Sum(nil))

	now := time.Now()
	c.mu.Lock()
	exp, ok := c.entries[id]
	c.mu.Unlock()
	if ok && now.Before(exp) {
		return true
	}

	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	good := verifyPassword(pass, encoded)
	<-c.sem
	if !good {
		return false
	}
	c.mu.Lock()
	if len(c.entries) >= basicAuthCacheMax {
		for k, e := range c.entries {
			if now.After(e) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= basicAuthCacheMax {
			c.entries = map[[sha256.Size]byte]time.Time{}
		}
	}
	c.entries[id] = now.Add(basicAuthCacheTTL)
	c.mu.Unlock()
	return true
}

func (rs *runtimeSite) withCORS(next http.Handler) http.Handler {
	c := rs.cfg.CORS
	if !c.Enabled {
		return next
	}
	allowed := map[string]bool{}
	any := false
	for _, o := range c.Origins {
		if o == "*" {
			any = true
		}
		allowed[strings.ToLower(o)] = true
	}
	methods := strings.Join(c.Methods, ", ")
	if methods == "" {
		methods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
	}
	headers := strings.Join(c.Headers, ", ")
	if headers == "" {
		headers = "Content-Type, Authorization, X-Requested-With"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Add("Vary", "Origin")
		}
		// "*" + credentials used to reflect ANY origin (even "null") with
		// Allow-Credentials, i.e. switch off SOP for cookie requests.
		// Reflection and credentials are only for explicitly listed origins.
		explicit := origin != "*" && origin != "null" && allowed[strings.ToLower(origin)]
		if origin != "" && (any || explicit) {
			h := w.Header()
			if explicit {
				h.Set("Access-Control-Allow-Origin", origin)
				if c.AllowCredentials {
					h.Set("Access-Control-Allow-Credentials", "true")
				}
			} else {
				h.Set("Access-Control-Allow-Origin", "*")
			}
			if len(c.ExposeHeaders) > 0 {
				h.Set("Access-Control-Expose-Headers", strings.Join(c.ExposeHeaders, ", "))
			}
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", methods)
				h.Set("Access-Control-Allow-Headers", headers)
				if c.MaxAgeSec > 0 {
					h.Set("Access-Control-Max-Age", strconv.Itoa(c.MaxAgeSec))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (rs *runtimeSite) withResponseHeaders(next http.Handler) http.Handler {
	sec := rs.cfg.Security
	custom := rs.cfg.Headers
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if sec != nil && sec.Enabled {
			// Also behind a trusted proxy that terminated TLS for the client.
			if schemeOf(r) == "https" && sec.HSTSMaxAgeSec > 0 {
				v := "max-age=" + strconv.Itoa(sec.HSTSMaxAgeSec)
				if sec.HSTSIncludeSubdomains {
					v += "; includeSubDomains"
				}
				if sec.HSTSPreload {
					v += "; preload"
				}
				h.Set("Strict-Transport-Security", v)
			}
			if sec.FrameOptions != "" {
				h.Set("X-Frame-Options", sec.FrameOptions)
			}
			if sec.ContentTypeOptions {
				h.Set("X-Content-Type-Options", "nosniff")
			}
			if sec.ReferrerPolicy != "" {
				h.Set("Referrer-Policy", sec.ReferrerPolicy)
			}
			if sec.PermissionsPolicy != "" {
				h.Set("Permissions-Policy", sec.PermissionsPolicy)
			}
			if sec.CSP != "" {
				h.Set("Content-Security-Policy", sec.CSP)
			}
		}
		if sec == nil || !sec.HideServerHeader {
			h.Set("Server", appName+"/"+version)
		}
		for k, v := range custom {
			h.Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

func (rs *runtimeSite) withCompression(next http.Handler) http.Handler {
	c := rs.cfg.Compress
	if c == nil || !c.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(strings.ToLower(r.Header.Get("Accept-Encoding")), "gzip") ||
			r.Header.Get("Range") != "" ||
			strings.EqualFold(r.Header.Get("Connection"), "Upgrade") ||
			r.Header.Get("Upgrade") != "" {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: w, site: rs, status: http.StatusOK}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}

// ============================================================================
// Content handlers
// ============================================================================

func (rs *runtimeSite) serveContent(w http.ResponseWriter, r *http.Request) {
	switch rs.cfg.Type {
	case "proxy":
		rs.serveProxy(w, r)
	case "fastcgi":
		rs.serveFCGI(w, r)
	case "redirect":
		rs.serveRedirect(w, r)
	default:
		rs.serveStatic(w, r)
	}
}

func (rs *runtimeSite) serveRedirect(w http.ResponseWriter, r *http.Request) {
	target := rs.cfg.RedirectTo
	if u, err := url.Parse(target); err == nil && (u.Path == "" || strings.HasSuffix(target, "/")) && u.RawQuery == "" {
		uri := r.URL.RequestURI()
		if u.Host == "" && strings.HasPrefix(uri, "//") { // never build "//evil.com/..." from a relative redirect_to
			uri = "/" + strings.TrimLeft(uri, "/")
		}
		target = strings.TrimSuffix(target, "/") + uri
	}
	http.Redirect(w, r, target, rs.cfg.RedirectCode)
}

func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 1 && seg[0] == '.' {
			return true
		}
	}
	return false
}

func (rs *runtimeSite) cacheControlFor(name string) string {
	c := rs.cfg.Cache
	if c == nil || !c.Enabled {
		return ""
	}
	ext := strings.ToLower(filepath.Ext(name))
	if v, ok := c.ByExtension[ext]; ok {
		return v
	}
	switch ext {
	case ".html", ".htm", ".json", ".xml", ".txt", ".webmanifest":
		if c.HTMLControl != "" {
			return c.HTMLControl
		}
	case ".js", ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".png", ".jpg", ".jpeg",
		".gif", ".webp", ".avif", ".svg", ".ico", ".mp4", ".webm", ".wasm", ".map":
		if c.AssetControl != "" {
			return c.AssetControl
		}
	}
	return c.DefaultControl
}

func etagFor(st os.FileInfo) string {
	return fmt.Sprintf(`W/"%x-%x"`, st.Size(), st.ModTime().UnixNano())
}

// tryFiles tries alternatives such as "$uri.html" or "/index.html".
func (rs *runtimeSite) tryFiles(w http.ResponseWriter, r *http.Request, upath string) bool {
	for _, tpl := range rs.cfg.TryFiles {
		cand := strings.ReplaceAll(tpl, "$uri", upath)
		if cand == "" || strings.Contains(cand, "..") {
			continue
		}
		full, err := resolveUnderRoot(rs.root, urlPathRel(cand))
		if err != nil || ensureNoSymlinkComponents(mustEvalRoot(rs.root), full) != nil {
			continue
		}
		if st, err := os.Lstat(full); err == nil && !st.IsDir() && st.Mode()&os.ModeSymlink == 0 && st.Mode().IsRegular() {
			rs.serveFile(w, r, full, st)
			return true
		}
	}
	return false
}

func (rs *runtimeSite) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		rs.serveError(w, r, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	upath := path.Clean("/" + r.URL.Path)
	if strings.ContainsRune(upath, 0) {
		rs.serveError(w, r, http.StatusBadRequest, "Invalid path")
		return
	}
	sec := rs.cfg.Security
	if sec != nil && sec.BlockDotfiles && hasDotSegment(upath) && !strings.HasPrefix(upath, "/.well-known/") {
		rs.serveError(w, r, http.StatusForbidden, "Access denied")
		return
	}
	// The site root may not exist at all: the directory was not created, the
	// volume is not mounted, or the first deploy has not happened yet. A plain
	// 404 would be misleading: the site exists, it is just not deployed. So the
	// home page gets the built-in placeholder (503), which explains what to do
	// next.
	if !dirExists(rs.root) {
		if upath == "/" || upath == "/index.html" {
			rs.servePlaceholder(w, r)
			return
		}
		rs.serveError(w, r, http.StatusNotFound, "Site is not deployed yet")
		return
	}

	full, err := resolveUnderRoot(rs.root, urlPathRel(upath))
	if err != nil {
		rs.serveError(w, r, http.StatusForbidden, "Access denied")
		return
	}
	if err := ensureNoSymlinkComponents(mustEvalRoot(rs.root), full); err != nil {
		rs.serveError(w, r, http.StatusForbidden, "Access denied")
		return
	}
	st, err := os.Lstat(full)
	if err == nil && st.Mode()&os.ModeSymlink != 0 {
		rs.serveError(w, r, http.StatusForbidden, "Access denied")
		return
	}

	if err == nil && st.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			// Only the cleaned path: the raw "//evil.com%2f..%2fdir" would make a
			// protocol-relative Location that leads to someone else's domain.
			target := upath
			if !strings.HasSuffix(target, "/") {
				target += "/"
			}
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		found := false
		for _, idx := range rs.cfg.Index {
			cand, cerr := resolveUnderRoot(full, idx)
			if cerr != nil || ensureNoSymlinkComponents(mustEvalRoot(rs.root), cand) != nil {
				continue
			}
			cst, cerr := os.Lstat(cand)
			if cerr == nil && !cst.IsDir() && cst.Mode()&os.ModeSymlink == 0 && cst.Mode().IsRegular() {
				full, st, found = cand, cst, true
				break
			}
		}
		if !found {
			if rs.cfg.Listing {
				rs.serveListing(w, r, full, upath)
				return
			}
			// An empty root is treated like a missing one: show the
			// built-in page instead of an error.
			if upath == "/" && dirIsEmpty(full) {
				rs.servePlaceholder(w, r)
				return
			}
			rs.serveError(w, r, http.StatusForbidden, "Directory listing is forbidden")
			return
		}
	} else if err != nil {
		if rs.tryFiles(w, r, upath) {
			return
		}
		if rs.cfg.Type == "spa" {
			index, ierr := resolveUnderRoot(rs.root, "index.html")
			if ierr == nil && ensureNoSymlinkComponents(mustEvalRoot(rs.root), index) == nil {
				if ist, ierr := os.Lstat(index); ierr == nil && ist.Mode()&os.ModeSymlink == 0 && ist.Mode().IsRegular() {
					w.Header().Set("Cache-Control", "no-cache")
					rs.serveFile(w, r, index, ist)
					return
				}
			}
		}
		rs.serveError(w, r, http.StatusNotFound, "Page not found")
		return
	}
	rs.serveFile(w, r, full, st)
}

// dirIsEmpty reports whether the directory has no entries.
func dirIsEmpty(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	return err == io.EOF || len(names) == 0
}

// servePlaceholder serves the built-in placeholder page from memory: it
// depends neither on the file system nor on whether the site is deployed.
func (rs *runtimeSite) servePlaceholder(w http.ResponseWriter, r *http.Request) {
	body := []byte(demoIndexHTML)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Webhost-Placeholder", "1")
	// The site is not deployed yet: 503 and noindex, so that search engines
	// do not index the placeholder and come back later.
	h.Set("Retry-After", "3600")
	h.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusServiceUnavailable)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (rs *runtimeSite) serveFile(w http.ResponseWriter, r *http.Request, full string, st os.FileInfo) {
	h := w.Header()
	if cc := rs.cacheControlFor(full); cc != "" && h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", cc)
	}
	if rs.cfg.Cache != nil && rs.cfg.Cache.ETag {
		h.Set("ETag", etagFor(st))
	}

	// Precompressed variants (.br/.gz) if the client accepts them.
	if rs.cfg.Compress != nil && rs.cfg.Compress.Precompressed && r.Header.Get("Range") == "" {
		ae := strings.ToLower(r.Header.Get("Accept-Encoding"))
		type variant struct{ suffix, encoding string }
		for _, v := range []variant{{".br", "br"}, {".gz", "gzip"}} {
			if !strings.Contains(ae, v.encoding) {
				continue
			}
			cand, cerr := resolveUnderRoot(filepath.Dir(full), filepath.Base(full)+v.suffix)
			if cerr != nil || ensureNoSymlinkComponents(mustEvalRoot(rs.root), cand) != nil {
				continue
			}
			cst, err := os.Lstat(cand)
			if err != nil || cst.IsDir() || cst.Mode()&os.ModeSymlink != 0 || !cst.Mode().IsRegular() {
				continue
			}
			if ctype := mime.TypeByExtension(filepath.Ext(full)); ctype != "" {
				h.Set("Content-Type", ctype)
			}
			h.Set("Content-Encoding", v.encoding)
			h.Add("Vary", "Accept-Encoding")
			h.Set("ETag", etagFor(cst))
			f, err := os.Open(cand)
			if err != nil {
				break
			}
			defer f.Close()
			http.ServeContent(w, r, "", cst.ModTime(), f)
			return
		}
	}

	if ensureNoSymlinkComponents(mustEvalRoot(rs.root), full) != nil {
		rs.serveError(w, r, http.StatusForbidden, "Access denied")
		return
	}
	f, err := os.Open(full)
	if err != nil {
		rs.serveError(w, r, http.StatusNotFound, "File unavailable")
		return
	}
	defer f.Close()
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}

func (rs *runtimeSite) serveListing(w http.ResponseWriter, r *http.Request, dir, upath string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		rs.serveError(w, r, http.StatusForbidden, "Directory unavailable")
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	var b bytes.Buffer
	fmt.Fprintf(&b, "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">"+
		"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"+
		"<title>Index of %s</title><style>body{font:14px/1.6 system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 16px}"+
		"table{width:100%%;border-collapse:collapse}td,th{padding:6px 10px;border-bottom:1px solid #e5e7eb;text-align:left}"+
		"a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}</style></head><body>"+
		"<h1>Index of %s</h1><table><tr><th>Name</th><th>Size</th><th>Modified</th></tr>",
		htmlEscape(upath), htmlEscape(upath))
	if upath != "/" {
		b.WriteString(`<tr><td><a href="../">../</a></td><td>—</td><td>—</td></tr>`)
	}
	for _, e := range entries {
		if rs.cfg.Security != nil && rs.cfg.Security.BlockDotfiles && strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		name := e.Name()
		size := humanBytes(info.Size())
		if e.IsDir() {
			name += "/"
			size = "—"
		}
		fmt.Fprintf(&b, "<tr><td><a href=\"%s\">%s</a></td><td>%s</td><td>%s</td></tr>",
			(&url.URL{Path: name}).String(), htmlEscape(name), size, info.ModTime().Format("2006-01-02 15:04"))
	}
	b.WriteString("</table></body></html>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b.Bytes())
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func (rs *runtimeSite) serveError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if rs.cfg.ErrorPages != nil && rs.root != "" {
		if p, ok := rs.cfg.ErrorPages[strconv.Itoa(code)]; ok {
			full, rerr := resolveUnderRoot(rs.root, urlPathRel(p))
			var data []byte
			err := rerr
			if err == nil {
				err = ensureNoSymlinkComponents(mustEvalRoot(rs.root), full)
			}
			if err == nil {
				if st, lerr := os.Lstat(full); lerr != nil || !st.Mode().IsRegular() {
					err = errors.New("error page is not a regular file")
				}
			}
			if err == nil {
				data, err = os.ReadFile(full)
			}
			if err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(code)
				_, _ = w.Write(data)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	fmt.Fprintf(w, `<!doctype html><html lang="ru"><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>%d</title>`+
		`<style>body{font:16px/1.6 system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;`+
		`justify-content:center;margin:0;background:#0b1020;color:#e5e7eb}.c{text-align:center;padding:32px}`+
		`h1{font-size:64px;margin:0;color:#60a5fa}p{opacity:.8}</style></head><body><div class="c">`+
		`<h1>%d</h1><p>%s</p><p style="font-size:12px;opacity:.5">%s</p></div></body></html>`,
		code, code, htmlEscape(msg), htmlEscape(http.StatusText(code)))
}

// --- proxy ---

// unwrapRespWriter finds the accounting respWriter in the wrapper chain
// (gzip, http.maxBytesWriter and others). The depth limit guards against
// a wrapper that returns itself.
func unwrapRespWriter(w http.ResponseWriter) *respWriter {
	for i := 0; i < 8; i++ {
		if rw, ok := w.(*respWriter); ok {
			return rw
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil
		}
		next := u.Unwrap()
		if next == nil || next == w {
			return nil
		}
		w = next
	}
	return nil
}

func (rs *runtimeSite) serveProxy(w http.ResponseWriter, r *http.Request) {
	if rs.pool == nil || len(rs.pool.ups) == 0 {
		rs.serveError(w, r, http.StatusBadGateway, "No available backends")
		return
	}
	attempts := rs.cfg.ProxyConfig.Retries + 1
	if attempts < 1 {
		attempts = 1
	}

	// Buffer a small body to be able to repeat the request.
	var bodyBytes []byte
	canRetry := true
	if r.Body != nil && r.ContentLength != 0 {
		if r.ContentLength > 0 && r.ContentLength <= 1<<20 {
			b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				rs.serveError(w, r, http.StatusBadRequest, "Failed to read request body")
				return
			}
			bodyBytes = b
			r.Body = io.NopCloser(bytes.NewReader(b))
		} else {
			canRetry = false
		}
	}
	isUpgrade := r.Header.Get("Upgrade") != ""
	if isUpgrade {
		canRetry = false
	}

	skip := map[string]bool{}
	var lastErr error
	for i := 0; i < attempts; i++ {
		up := rs.pool.pick(r, skip)
		if up == nil {
			break
		}
		att := &proxyAttempt{}
		req := r.WithContext(context.WithValue(r.Context(), ctxAttempt, att))
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		setForwardedHeaders(req, r)

		rw := &respWriter{ResponseWriter: w, status: http.StatusOK, upstream: up.raw}
		proxyThrough(up, rw, req)

		if att.err == nil {
			// Record the backend name for the access log. A type assertion
			// w.(*respWriter) does not work here: withCompression wraps the writer
			// in *gzipResponseWriter, so the accounting writer is found through the
			// Unwrap chain. Status and size are not copied: the top respWriter has
			// already counted them, since the response went through it.
			if top := unwrapRespWriter(w); top != nil {
				top.upstream = up.raw
			}
			return
		}
		lastErr = att.err
		skip[up.raw] = true
		rs.srv.log.Warnf("site %s: upstream %s: %v", rs.cfg.Name, up.raw, att.err)
		if rw.wrote {
			return
		}
		if !canRetry || (!idempotentMethod(r.Method) && !isDialError(att.err)) {
			break
		}
	}
	var mbe *http.MaxBytesError
	if errors.As(lastErr, &mbe) {
		rs.serveError(w, r, http.StatusRequestEntityTooLarge, "Request body too large")
		return
	}
	if lastErr != nil {
		rs.srv.log.Errorf("site %s: all backends unavailable: %v", rs.cfg.Name, lastErr)
	}
	rs.serveError(w, r, http.StatusBadGateway, "Backend unavailable")
}

// proxyThrough runs one attempt and keeps up.inflight (leastconn) accurate.
// ReverseProxy ends a response whose client went away with
// panic(http.ErrAbortHandler), so the decrement has to be deferred: inline it
// was skipped and the counter grew with every aborted download.
func proxyThrough(up *upstream, w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&up.inflight, 1)
	defer atomic.AddInt64(&up.inflight, -1)
	up.proxy.ServeHTTP(w, r)
}

// idempotentMethod: requests that may be safely replayed on another upstream.
func idempotentMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

// isDialError: the request never reached the upstream (connect failed).
func isDialError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

func setForwardedHeaders(req *http.Request, orig *http.Request) {
	ip := clientIP(orig) // resolved real IP from context (never raw spoofable headers)
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}
	req.Header = orig.Header.Clone()
	// Do not forward client-supplied Forwarded; rebuild from resolved IP.
	req.Header.Del("Forwarded")
	if ipStr != "" {
		if prior := forwardedForChain(orig.Header); prior != "" {
			// prior only exists when TCP peer was trusted (untrusted headers stripped).
			hop := ipStr
			if peer := peerIPFromRemoteAddr(orig.RemoteAddr); peer != nil {
				hop = peer.String()
			}
			req.Header.Set("X-Forwarded-For", prior+", "+hop)
		} else {
			req.Header.Set("X-Forwarded-For", ipStr)
		}
		req.Header.Set("X-Real-IP", ipStr)
	}
	// The scheme and host the client used. When a trusted proxy in front of
	// us terminated TLS, its X-Forwarded-Proto/-Host are the truth: replacing
	// them with "http" and our Host sent apps into endless https redirects.
	// (From untrusted peers these headers were already stripped.)
	req.Header.Set("X-Forwarded-Proto", schemeOf(orig))
	if req.Header.Get("X-Forwarded-Host") == "" {
		req.Header.Set("X-Forwarded-Host", orig.Host)
	}
	if id, ok := orig.Context().Value(ctxRequestID).(string); ok && id != "" {
		req.Header.Set("X-Request-Id", id)
	}
}

// --- fastcgi ---

func (rs *runtimeSite) serveFCGI(w http.ResponseWriter, r *http.Request) {
	cfg := rs.cfg.FastCGI
	upath := path.Clean("/" + r.URL.Path)
	sec := rs.cfg.Security
	if sec != nil && sec.BlockDotfiles && hasDotSegment(upath) && !strings.HasPrefix(upath, "/.well-known/") {
		rs.serveError(w, r, http.StatusForbidden, "Access denied")
		return
	}

	// Static files are served directly, bypassing PHP.
	split := strings.ToLower(cfg.SplitPath)
	full, rerr := resolveUnderRoot(rs.root, urlPathRel(upath))
	if rerr == nil && ensureNoSymlinkComponents(mustEvalRoot(rs.root), full) == nil {
		if st, err := os.Lstat(full); err == nil && !st.IsDir() && st.Mode()&os.ModeSymlink == 0 && st.Mode().IsRegular() &&
			!strings.HasSuffix(strings.ToLower(upath), split) && staticExtAllowed(cfg.ReadOnlyExt, upath) {
			rs.serveFile(w, r, full, st)
			return
		}
	}

	scriptName, pathInfo := upath, ""
	if idx := strings.Index(strings.ToLower(upath), split+"/"); idx >= 0 {
		scriptName = upath[:idx+len(split)]
		pathInfo = upath[idx+len(split):]
	}
	scriptFile, serr := resolveUnderRoot(rs.root, urlPathRel(scriptName))
	if serr != nil || ensureNoSymlinkComponents(mustEvalRoot(rs.root), scriptFile) != nil {
		rs.serveError(w, r, http.StatusForbidden, "Access denied")
		return
	}
	// Only scripts go to PHP by name; any other file (one left out by
	// static_extensions, say) is the front controller's business.
	if st, err := os.Lstat(scriptFile); err != nil || st.IsDir() || st.Mode()&os.ModeSymlink != 0 || !strings.HasSuffix(strings.ToLower(scriptName), split) {
		// front controller: /index.php
		scriptName = "/" + cfg.IndexFile
		var ierr error
		scriptFile, ierr = resolveUnderRoot(rs.root, cfg.IndexFile)
		if ierr != nil || ensureNoSymlinkComponents(mustEvalRoot(rs.root), scriptFile) != nil {
			rs.serveError(w, r, http.StatusForbidden, "Access denied")
			return
		}
		pathInfo = upath
		if _, err := os.Lstat(scriptFile); err != nil {
			rs.serveError(w, r, http.StatusNotFound, "Script not found")
			return
		}
	}

	listen := rs.srv.httpsAddr
	if r.TLS == nil {
		listen = rs.srv.httpAddr
	}
	if r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody {
		// Chunked request: PHP reads exactly CONTENT_LENGTH bytes, so spool it
		// (already bounded by limits.max_body_bytes_mb via MaxBytesReader).
		// Up to 1 MiB in memory, the rest in a temp file: io.ReadAll of a
		// 64 MiB body per request lets clients exhaust RAM.
		body, n, err := spoolBody(r.Body, 1<<20)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				rs.serveError(w, r, http.StatusRequestEntityTooLarge, "Request body too large")
				return
			}
			rs.serveError(w, r, http.StatusBadRequest, "Failed to read request body")
			return
		}
		defer body.Close()
		r.Body = body
		r.ContentLength = n
	}
	params := fcgiParamsFor(r, scriptFile, scriptName, pathInfo, rs.root, cfg.Params, listen)
	if err := serveFastCGI(w, r, cfg.Address, params, time.Duration(cfg.TimeoutSec)*time.Second); err != nil {
		rs.srv.log.Errorf("site %s: fastcgi: %v", rs.cfg.Name, err)
		if !responseStarted(w) {
			rs.serveError(w, r, http.StatusBadGateway, "Application handler error")
		}
	}
}

// staticExtAllowed applies fastcgi.static_extensions to a request path; an
// empty list allows every extension.
func staticExtAllowed(exts []string, upath string) bool {
	if len(exts) == 0 {
		return true
	}
	ext := strings.ToLower(path.Ext(upath))
	if ext == "" {
		return false
	}
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" && !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if e == ext {
			return true
		}
	}
	return false
}

// responseStarted walks the wrapper chain (gzip, respWriter, ...) and reports
// whether a final status has already been sent.
func responseStarted(w http.ResponseWriter) bool {
	for i := 0; i < 8 && w != nil; i++ {
		switch t := w.(type) {
		case *respWriter:
			if t.wrote {
				return true
			}
		case *gzipResponseWriter:
			if t.wrote {
				return true
			}
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = u.Unwrap()
	}
	return false
}

// spoolBody reads r fully: up to memLimit bytes in memory, beyond that into
// an anonymous temp file. The returned ReadCloser removes the temp file.
func spoolBody(r io.Reader, memLimit int64) (io.ReadCloser, int64, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, memLimit+1))
	if err != nil {
		return nil, 0, err
	}
	if n <= memLimit {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), n, nil
	}
	f, err := os.CreateTemp("", appName+"-body-*")
	if err != nil {
		return nil, 0, err
	}
	cleanup := func() { f.Close(); os.Remove(f.Name()) }
	if _, err := f.Write(buf.Bytes()); err != nil {
		cleanup()
		return nil, 0, err
	}
	m, err := io.Copy(f, r)
	if err != nil {
		cleanup()
		return nil, 0, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, err
	}
	return &tempFileBody{f}, n + m, nil
}

type tempFileBody struct{ *os.File }

func (t *tempFileBody) Close() error {
	err := t.File.Close()
	_ = os.Remove(t.File.Name())
	return err
}

// ============================================================================
// Server
// ============================================================================

type Server struct {
	mu      sync.RWMutex
	state   *runtimeState
	cfg     *Config
	cfgPath string

	log     *Logger
	access  *accessLogger
	metrics *Metrics
	certs   *certManager
	db      *DB
	sched   *scheduler
	sup     *supervisor
	mail    *mailer

	httpAddr  string
	httpsAddr string

	httpSrv  *http.Server
	httpsSrv *http.Server
	adminSrv *http.Server

	startedAt time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	closers   []io.Closer
	reloads   int64

	reloadMu sync.Mutex // SIGHUP and the Admin API must not reload at the same time
	editMu   sync.Mutex // read-modify-write of config.json from the Admin API
}

func newServer(cfgPath string) (*Server, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Log.Dir, 0o755); err != nil {
		return nil, err
	}
	errW, err := newRotatingWriter(filepath.Join(cfg.Log.Dir, cfg.Log.ErrorFile), cfg.Log.MaxSizeMB, cfg.Log.MaxBackups)
	if err != nil {
		return nil, err
	}
	accW, err := newRotatingWriter(filepath.Join(cfg.Log.Dir, cfg.Log.AccessFile), cfg.Log.MaxSizeMB, cfg.Log.MaxBackups)
	if err != nil {
		return nil, err
	}
	lg := newLogger(cfg.Log.Level, io.MultiWriter(os.Stdout, errW))
	// Before anything asks rootPool (proxy transports, ACME): it is computed
	// once, and imported roots set only in Run arrived too late.
	extraRootsPath.Store(filepath.Join(cfg.DataDir, "certs", "roots.pem"))

	certs, err := newCertManager(filepath.Join(cfg.DataDir, "certs"), lg)
	if err != nil {
		return nil, err
	}
	certs.renewDays = cfg.ACME.RenewBeforeDays

	db, err := openDB(filepath.Join(cfg.DataDir, "db"), dbSyncMode(cfg.Database.Sync), lg)
	if err != nil {
		return nil, err
	}
	if cfg.Database.CompactAtMB > 0 {
		db.compactAt = int64(cfg.Database.CompactAtMB) << 20
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg: cfg, cfgPath: cfgPath, log: lg,
		access:    newAccessLogger(cfg.Log.Format, accW),
		metrics:   newMetrics(),
		certs:     certs,
		db:        db,
		httpAddr:  cfg.Listen.HTTP,
		httpsAddr: cfg.Listen.HTTPS,
		startedAt: time.Now(),
		ctx:       ctx, cancel: cancel,
		closers: []io.Closer{errW, accW, db},
	}
	if cfg.ACME.Enabled {
		ac, err := newACMEClient(certs, cfg.ACME, lg)
		if err != nil {
			lg.Errorf("acme: initialization failed: %v", err)
		} else {
			certs.acme = ac
		}
	}
	certs.allowHost = func(h string) (string, bool) {
		st := s.getState()
		if st == nil {
			return "", false
		}
		// Certificates only for sites with tls.enabled: a site configured
		// for plain HTTP used to get a self-signed certificate anyway.
		if rs, ok := st.exact[h]; ok {
			return h, rs.cfg.TLS.Enabled
		}
		for _, w := range st.wildcard {
			if h == strings.TrimPrefix(w.suffix, ".") {
				return h, w.site.cfg.TLS.Enabled
			}
			// Only one label below the wildcard is covered by "*.example.com".
			if strings.HasSuffix(h, w.suffix) && !strings.Contains(strings.TrimSuffix(h, w.suffix), ".") {
				return "*" + w.suffix, w.site.cfg.TLS.Enabled
			}
		}
		return "", false
	}
	s.sched = newScheduler(s)
	s.sup = newSupervisor(s)
	s.mail = newMailer(s)
	st, err := s.buildRuntime(cfg, ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	s.state = st
	s.certs.replaceManual(st.manual)
	return s, nil
}

func (s *Server) getState() *runtimeState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Server) getConfig() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// ServeHTTP is a root handler: routing over Host + shared middleware.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	state := s.getState()
	// Strip spoofable forwarding headers before handlers/proxy unless TCP peer is trusted.
	peer := peerIPFromRemoteAddr(r.RemoteAddr)
	if peer == nil || !ipInAny(peer, state.trusted) {
		stripUntrustedForwardingHeaders(r)
	}
	stripUnderscoreAliases(r)
	reqID := r.Header.Get("X-Request-Id")
	if !validRequestID(reqID) {
		reqID = randomID()
	}

	ctx := context.WithValue(r.Context(), ctxRequestID, reqID)
	if ip := realIPFrom(r, state.trusted); ip != nil {
		ctx = context.WithValue(ctx, ctxRealIP, ip)
	}
	ctx = context.WithValue(ctx, ctxScheme, requestScheme(r, state.trusted))
	r = r.WithContext(ctx)

	host := hostOnly(r.Host)
	rs := state.match(host)

	rw := &respWriter{ResponseWriter: w, status: http.StatusOK}
	rw.Header().Set("X-Request-Id", reqID)

	if state.maxBody > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(rw, r.Body, state.maxBody)
	}

	siteName := "-"
	if rs != nil {
		siteName = rs.cfg.Name
	}
	atomic.AddInt64(&s.metrics.inFlight, 1)

	defer func() {
		atomic.AddInt64(&s.metrics.inFlight, -1)
		rec := recover()
		// http.ErrAbortHandler (client gone mid-response, raised by
		// ReverseProxy) is re-raised for net/http, but only after the
		// request has been logged and counted: re-panicking first dropped
		// every aborted download from the access log and the metrics.
		aborted := rec == http.ErrAbortHandler
		if rec != nil && !aborted {
			buf := make([]byte, 8192)
			n := runtime.Stack(buf, false)
			s.log.Errorf("panic [%s] %s %s: %v\n%s", reqID, r.Method, r.URL.Path, rec, buf[:n])
			if !rw.wrote {
				http.Error(rw, "500 Internal Server Error", http.StatusInternalServerError)
			}
		}
		if aborted {
			defer panic(rec)
		}
		dur := time.Since(start)
		tlsInfo := ""
		if r.TLS != nil {
			tlsInfo = tlsVersionName(r.TLS.Version)
		}
		ipStr := ""
		if ip := clientIP(r); ip != nil {
			ipStr = ip.String()
		}
		s.access.log(&accessRecord{
			Time: start.UTC().Format(time.RFC3339Nano), ID: reqID, Site: siteName,
			RemoteIP: ipStr, Method: r.Method, Host: r.Host, URI: r.URL.RequestURI(),
			Proto: r.Proto, Status: rw.status, Bytes: rw.size,
			Duration: float64(dur.Microseconds()) / 1000.0,
			Referer:  r.Referer(), UserAgent: r.UserAgent(), Upstream: rw.upstream, TLS: tlsInfo,
		})
		s.metrics.observe(siteName, r.Method, rw.status, rw.size, r.ContentLength, dur)
	}()

	if rs == nil {
		http.Error(rw, "404 — no site configured for this domain", http.StatusNotFound)
		return
	}
	rs.handler.ServeHTTP(rw, r)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	}
	return "TLS"
}

// IP trust model (spoofing defense):
// Forwarding headers (X-Forwarded-For, X-Real-IP, Forwarded) are trusted ONLY when
// the TCP peer (RemoteAddr) is listed in listen.trusted_proxies. Otherwise they are
// ignored and stripped from the inbound request so handlers/upstreams cannot treat
// client-supplied values as truth. When the peer is trusted, XFF and RFC 7239
// Forwarded for= are walked right-to-left, skipping trusted hops, rejecting
// empty/invalid entries, with a chain length cap; the leftmost hop is never used
// blindly. Rate-limit and ACL always use the resolved IP from request context.
const maxForwardedChain = 20

func peerIPFromRemoteAddr(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

func stripUntrustedForwardingHeaders(r *http.Request) {
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-IP")
	r.Header.Del("X-Real-Ip")
	r.Header.Del("Forwarded")
	// Scheme/host/port claims are just as spoofable: PHP gets them as
	// HTTP_X_FORWARDED_*, and apps that trust them build absolute URLs
	// (password reset links) for whatever host the client named.
	r.Header.Del("X-Forwarded-Proto")
	r.Header.Del("X-Forwarded-Host")
	r.Header.Del("X-Forwarded-Port")
}

// stripUnderscoreAliases drops headers such as "X-Forwarded_For" that many
// backends (CGI/PHP, some frameworks) normalise to a trusted forwarding header.
func stripUnderscoreAliases(r *http.Request) {
	for k := range r.Header {
		if strings.Contains(k, "_") {
			switch http.CanonicalHeaderKey(strings.ReplaceAll(k, "_", "-")) {
			case "X-Forwarded-For", "X-Real-Ip", "Forwarded", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port":
				delete(r.Header, k)
			}
		}
	}
}

// validRequestID accepts a client X-Request-Id only if it is short and plain.
func validRequestID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

// parseForwardedIP parses a single hop from XFF or Forwarded for= (optional
// quotes, IPv6 brackets, and :port). Empty/invalid values yield nil.
func parseForwardedIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "unknown") {
		return nil
	}
	if strings.HasPrefix(s, "_") { // RFC 7239 obfuscated identifier
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			host := s[1:i]
			rest := s[i+1:]
			if rest == "" {
				return net.ParseIP(host)
			}
			if strings.HasPrefix(rest, ":") {
				return net.ParseIP(host)
			}
		}
		return nil
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(s)
}

// parseForwardedHeaderForIPs extracts for= addresses from RFC 7239 Forwarded
// header values, left-to-right (same order as XFF). Invalid hops are omitted.
func parseForwardedHeaderForIPs(values []string) []net.IP {
	var out []net.IP
	for _, hv := range values {
		for _, elem := range strings.Split(hv, ",") {
			elem = strings.TrimSpace(elem)
			if elem == "" {
				continue
			}
			for _, part := range strings.Split(elem, ";") {
				part = strings.TrimSpace(part)
				low := strings.ToLower(part)
				if !strings.HasPrefix(low, "for=") {
					continue
				}
				raw := strings.TrimSpace(part[len("for="):])
				if ip := parseForwardedIP(raw); ip != nil {
					out = append(out, ip)
				}
				break
			}
		}
	}
	return out
}

func capForwardedChain(ips []net.IP) []net.IP {
	if len(ips) <= maxForwardedChain {
		return ips
	}
	// Keep the rightmost hops (closest to us); drop the client-spoofable left side.
	return ips[len(ips)-maxForwardedChain:]
}

func firstUntrustedFromRight(ips []net.IP, trusted []*net.IPNet) net.IP {
	for i := len(ips) - 1; i >= 0; i-- {
		ip := ips[i]
		if ip == nil {
			continue
		}
		if !ipInAny(ip, trusted) {
			return ip
		}
	}
	return nil
}

func realIPFrom(r *http.Request, trusted []*net.IPNet) net.IP {
	peer := peerIPFromRemoteAddr(r.RemoteAddr)
	if peer == nil || !ipInAny(peer, trusted) {
		// Untrusted peer: never honor client-supplied forwarding headers.
		return peer
	}
	// Trusted peer: walk X-Forwarded-For right-to-left, skipping trusted hops.
	// All header lines form one list (RFC 9110 §5.3): proxies such as HAProxy
	// ("option forwardfor") append their own line after the client's, so
	// reading only the first line would hand the choice of IP to the client.
	if xff := forwardedForChain(r.Header); xff != "" {
		raw := strings.Split(xff, ",")
		ips := make([]net.IP, 0, len(raw))
		for _, p := range raw {
			if ip := parseForwardedIP(p); ip != nil {
				ips = append(ips, ip)
			}
			// empty/invalid hops are rejected (skipped), not trusted
		}
		ips = capForwardedChain(ips)
		if ip := firstUntrustedFromRight(ips, trusted); ip != nil {
			return ip
		}
		// All remaining hops trusted — do not fall back to leftmost blindly.
	}
	// RFC 7239 Forwarded: for=...
	if vals := r.Header.Values("Forwarded"); len(vals) > 0 {
		ips := capForwardedChain(parseForwardedHeaderForIPs(vals))
		if ip := firstUntrustedFromRight(ips, trusted); ip != nil {
			return ip
		}
	}
	// Single-hop X-Real-IP from a trusted peer only; ignore if invalid or trusted.
	// With several lines the last one was set closest to us.
	if vals := r.Header.Values("X-Real-IP"); len(vals) > 0 {
		if ip := parseForwardedIP(vals[len(vals)-1]); ip != nil && !ipInAny(ip, trusted) {
			return ip
		}
	}
	return peer
}

// forwardedForChain joins every X-Forwarded-For line, in order, into one
// comma-separated chain (empty lines are dropped).
func forwardedForChain(h http.Header) string {
	vals := h.Values("X-Forwarded-For")
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ", ")
}

// httpEntryHandler: ACME challenges + HTTPS redirect.
func (s *Server) httpEntryHandler() http.Handler {
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.getConfig()
		if cfg.Listen.RedirectHTTPS && cfg.Listen.HTTPS != "" && s.shouldRedirectToHTTPS(r) {
			http.Redirect(w, r, httpsRedirectURL(r, cfg.Listen.HTTPS), http.StatusMovedPermanently)
			return
		}
		s.ServeHTTP(w, r)
	})
	return s.certs.acmeChallengeHandler(h)
}

// shouldRedirectToHTTPS: not for sites with tls.enabled=false (they are served
// over plain HTTP), and not when a trusted proxy already terminated TLS for
// the client (X-Forwarded-Proto: https) — redirecting that loops forever.
func (s *Server) shouldRedirectToHTTPS(r *http.Request) bool {
	host := hostOnly(r.Host)
	if host == "" {
		return false
	}
	st := s.getState()
	if st == nil {
		return true
	}
	if rs := st.match(host); rs != nil && !rs.cfg.TLS.Enabled {
		return false
	}
	return requestScheme(r, st.trusted) != "https"
}

// httpsRedirectURL builds the https:// URL for r; IPv6 literals keep their
// brackets ("https://::1:8443/" is not a URL).
func httpsRedirectURL(r *http.Request, httpsListen string) string {
	host := hostOnly(r.Host)
	port := ""
	if _, p, err := net.SplitHostPort(httpsListen); err == nil && p != "443" {
		port = p
	}
	switch {
	case port != "":
		host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	return "https://" + host + r.URL.RequestURI()
}

// requestScheme is "https" when r arrived over TLS, or when a trusted proxy
// terminated TLS and says so in X-Forwarded-Proto; otherwise "http".
func requestScheme(r *http.Request, trusted []*net.IPNet) string {
	if r.TLS != nil {
		return "https"
	}
	if peer := peerIPFromRemoteAddr(r.RemoteAddr); peer != nil && ipInAny(peer, trusted) {
		v := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
		if v == "https" || v == "http" {
			return v
		}
	}
	return "http"
}

// schemeOf is the scheme the client used, as resolved in ServeHTTP.
func schemeOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxScheme).(string); ok && v != "" {
		return v
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// validPortString reports whether s is a TCP port number (1-65535).
func validPortString(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == s
}

func (s *Server) tlsConfig() *tls.Config {
	base := &tls.Config{
		GetCertificate: s.certs.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
	}
	// tls.min_version is per site: choose it from the SNI name at handshake
	// time (which also follows reloads). The single listener-wide minimum
	// used to be the lowest of all sites, so "1.3" on one site did nothing.
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		min := s.siteMinTLS(hello.ServerName)
		if min == base.MinVersion {
			return nil, nil
		}
		c := base.Clone()
		c.GetConfigForClient = nil
		c.MinVersion = min
		return c, nil
	}
	return base
}

// siteMinTLS returns the minimum TLS version of the site serving serverName.
func (s *Server) siteMinTLS(serverName string) uint16 {
	host := strings.ToLower(strings.TrimSuffix(serverName, "."))
	if st := s.getState(); st != nil {
		if rs := st.match(host); rs != nil && rs.cfg.TLS.MinVersion != "" {
			return tlsMinVersion(rs.cfg.TLS.MinVersion)
		}
	}
	return tls.VersionTLS12
}

func (s *Server) acmeDomains() []string {
	seen := map[string]bool{}
	var out []string
	for _, sc := range s.getConfig().Sites {
		if sc.Disabled || !sc.TLS.Enabled || !sc.TLS.ACME {
			continue
		}
		for _, d := range sc.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if !isPublicDomain(d) || strings.HasPrefix(d, "*.") || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func (s *Server) newHTTPServer(addr string, h http.Handler) *http.Server {
	c := s.getConfig().Limits
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: time.Duration(c.ReadHeaderTimeoutSec) * time.Second,
		ReadTimeout:       time.Duration(c.ReadTimeoutSec) * time.Second,
		WriteTimeout:      time.Duration(c.WriteTimeoutSec) * time.Second,
		IdleTimeout:       time.Duration(c.IdleTimeoutSec) * time.Second,
		MaxHeaderBytes:    c.MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				atomic.AddInt64(&s.metrics.totalConns, 1)
			}
		},
	}
	return srv
}

func listenLimited(addr string, maxConns int) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if maxConns > 0 {
		return &limitedListener{Listener: ln, sem: make(chan struct{}, maxConns)}, nil
	}
	return ln, nil
}

type limitedListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.sem <- struct{}{}
	return &limitedConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// Run starts all listeners and blocks until a shutdown signal.
func (s *Server) Run() error {
	cfg := s.getConfig()
	var wg sync.WaitGroup

	if err := validateTrustedProxies(&cfg.Listen); err != nil {
		return err
	}
	if cfg.Admin.Enabled && cfg.Admin.Listen != "" && isAllInterfacesListen(cfg.Admin.Listen) {
		return fmt.Errorf("admin.listen %q binds all interfaces — use 127.0.0.1:… or a specific IP (not 0.0.0.0/::)", cfg.Admin.Listen)
	}
	if cfg.Admin.Enabled && cfg.Admin.Listen != "" && len(cfg.Admin.Token) < 16 {
		return fmt.Errorf("admin.token is too short (need ≥16 characters); recreate via init or set a longer secret")
	}

	// Prepare for a bare system: CA roots and a resolver of our own if the OS
	// provides neither. This must happen before the first outgoing
	// connections, that is, before ACME and upstream health checks.
	extraRootsPath.Store(filepath.Join(cfg.DataDir, "certs", "roots.pem"))
	if pool, from, err := rootPool(); err == nil {
		s.log.Debugf("trusted roots: %s", describeRoots(pool, from))
	} else if cfg.ACME.Enabled {
		s.log.Warnf("outbound HTTPS will not work: %v", err)
	}
	installFallbackResolver(cfg.Listen.DNSServers, s.log)

	if cfg.Listen.HTTPS != "" {
		ln, err := listenLimited(cfg.Listen.HTTPS, cfg.Limits.MaxConnections)
		if err != nil {
			return fmt.Errorf("HTTPS listener %s: %w", cfg.Listen.HTTPS, err)
		}
		s.httpsSrv = s.newHTTPServer(cfg.Listen.HTTPS, s.certs.acmeChallengeHandler(s))
		s.httpsSrv.TLSConfig = s.tlsConfig()
		tlsLn := tls.NewListener(ln, s.httpsSrv.TLSConfig)
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.log.Infof("HTTPS listening on %s", cfg.Listen.HTTPS)
			if err := s.httpsSrv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
				s.log.Errorf("HTTPS: %v", err)
			}
		}()
	}

	if cfg.Listen.HTTP != "" {
		ln, err := listenLimited(cfg.Listen.HTTP, cfg.Limits.MaxConnections)
		if err != nil {
			return fmt.Errorf("HTTP listener %s: %w", cfg.Listen.HTTP, err)
		}
		s.httpSrv = s.newHTTPServer(cfg.Listen.HTTP, s.httpEntryHandler())
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.log.Infof("HTTP listening on %s", cfg.Listen.HTTP)
			if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.log.Errorf("HTTP: %v", err)
			}
		}()
	}

	if cfg.Admin.Enabled && cfg.Admin.Listen != "" {
		if isAllInterfacesListen(cfg.Admin.Listen) {
			return fmt.Errorf("admin.listen %q binds all interfaces — use 127.0.0.1:… or a specific IP (not 0.0.0.0/::)", cfg.Admin.Listen)
		}
		if len(cfg.Admin.Token) < 16 {
			return fmt.Errorf("admin.token is too short (need ≥16 characters); recreate via init or set a longer secret")
		}
		ln, err := net.Listen("tcp", cfg.Admin.Listen)
		if err != nil {
			return fmt.Errorf("admin listener %s: %w", cfg.Admin.Listen, err)
		}
		s.adminSrv = s.newHTTPServer(cfg.Admin.Listen, s.adminHandler())
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.log.Infof("Admin API listening on http://%s", cfg.Admin.Listen)
			if err := s.adminSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.log.Errorf("Admin: %v", err)
			}
		}()
	}

	if s.certs.acme != nil {
		domains := s.acmeDomains()
		if len(domains) > 0 {
			s.log.Infof("acme: serving domains: %s", strings.Join(domains, ", "))
			s.certs.startRenewal(s.ctx, domains)
		}
	}

	// Scheduler, mail and external processes run on s.ctx: it is
	// cancelled when the server stops, and they shut down with it.
	s.sched.load(cfg)
	go s.sched.run(s.ctx)
	s.mail.start(s.ctx, cfg)
	s.sup.start(s.ctx, cfg)

	s.printBanner()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		sg := <-sig
		if sg == syscall.SIGHUP {
			if err := s.Reload(); err != nil {
				s.log.Errorf("reload: %v", err)
			}
			continue
		}
		s.log.Infof("received signal %s, shutting down...", sg)
		break
	}

	timeout := time.Duration(cfg.Limits.ShutdownTimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, srv := range []*http.Server{s.httpSrv, s.httpsSrv, s.adminSrv} {
		if srv != nil {
			_ = srv.Shutdown(ctx)
		}
	}
	s.cancel()
	// External processes are stopped gracefully, before the logs are closed:
	// their last lines should still reach the log.
	s.sup.stopAll()
	wg.Wait()
	for _, c := range s.closers {
		_ = c.Close()
	}
	s.log.Infof("stopped")
	return nil
}

// stdoutIsTerminal: escape sequences only for an interactive terminal, not
// for journald, log files or pipes (they showed up there as "^[[1m").
func stdoutIsTerminal() bool {
	if runtime.GOOS == "windows" || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func (s *Server) printBanner() {
	cfg := s.getConfig()
	title := appName + " " + version
	if stdoutIsTerminal() {
		title = "\x1b[1m" + title + "\x1b[0m" // bold, only for a person at a terminal
	}
	fmt.Printf("\n  %s — server started\n", title)
	fmt.Printf("  data directory : %s\n", cfg.DataDir)
	fmt.Printf("  config         : %s\n", s.cfgPath)
	if cfg.Listen.HTTP != "" {
		fmt.Printf("  HTTP           : %s\n", cfg.Listen.HTTP)
	}
	if cfg.Listen.HTTPS != "" {
		fmt.Printf("  HTTPS          : %s\n", cfg.Listen.HTTPS)
	}
	if cfg.Admin.Enabled {
		fmt.Printf("  Admin API      : http://%s (Bearer token in config)\n", cfg.Admin.Listen)
		fmt.Printf("  metrics        : http://%s/metrics\n", cfg.Admin.Listen)
	}
	fmt.Printf("  local CA       : %s/certs/ca.crt\n", cfg.DataDir)
	fmt.Printf("  sites (%d):\n", len(cfg.Sites))
	for _, sc := range cfg.Sites {
		mark := " "
		if sc.Disabled {
			mark = "×"
		}
		fmt.Printf("   %s %-16s %-8s %s\n", mark, sc.Name, sc.Type, strings.Join(sc.Domains, ", "))
	}
	fmt.Println()
}

// Reload rereads the config and atomically replaces the working state.
func (s *Server) Reload() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	cfg, err := loadConfig(s.cfgPath)
	if err != nil {
		return err
	}
	if err := validateTrustedProxies(&cfg.Listen); err != nil {
		return err
	}
	newState, err := s.buildRuntime(cfg, s.ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	old := s.state
	s.state = newState
	s.cfg = cfg
	s.access.format.Store(cfg.Log.Format)
	s.log.level.Store(int32(parseLevel(cfg.Log.Level)))
	s.mu.Unlock()
	s.certs.replaceManual(newState.manual)
	if old != nil && old.cancel != nil {
		old.cancel()
	}
	atomic.AddInt64(&s.reloads, 1)
	s.log.Infof("configuration reloaded: %d site(s)", len(cfg.Sites))
	if s.certs.acme != nil {
		s.certs.startRenewal(s.ctx, s.acmeDomains())
	}
	s.sched.load(cfg)
	s.mail.reload(cfg)
	s.sup.reload(s.ctx, cfg)
	return nil
}

// ============================================================================
// ADMIN API + Deploy
// ============================================================================

func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "ok", "uptime_sec": int64(time.Since(s.startedAt).Seconds()), "version": version,
		})
	})
	mux.HandleFunc("/metrics", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.metrics.writeProm(w)
	}))
	mux.HandleFunc("/api/v1/status", s.requireToken(s.handleStatus))
	mux.HandleFunc("/api/v1/sites", s.requireToken(s.handleSites))
	mux.HandleFunc("/api/v1/reload", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		if err := s.Reload(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
	}))
	mux.HandleFunc("/api/v1/certs", s.requireToken(s.handleCerts))
	mux.HandleFunc("/api/v1/sites/", s.requireToken(s.handleSiteAction))
	mux.HandleFunc("/api/v1/backups", s.requireToken(s.handleBackups))
	mux.HandleFunc("/api/v1/backups/", s.requireToken(s.handleBackupAction))
	mux.HandleFunc("/api/v1/cron", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.sched.jobsSnapshot())
	}))
	mux.HandleFunc("/api/v1/cron/", s.requireToken(s.handleCronAction))
	mux.HandleFunc("/api/v1/mail/queue", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		q := s.mail.queueSnapshot(limit)
		if q == nil {
			q = []map[string]interface{}{}
		}
		writeJSON(w, http.StatusOK, q)
	}))
	mux.HandleFunc("/api/v1/mail/send", s.requireToken(s.handleMailSend))
	mux.HandleFunc("/api/v1/processes", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.sup.snapshot())
	}))
	mux.HandleFunc("/api/v1/processes/", s.requireToken(s.handleProcessAction))
	mux.HandleFunc("/", s.requireToken(s.handleDashboard))
	return mux
}

func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.getConfig().Admin.Token
		if token == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin.token is not set"})
			return
		}
		provided := parseBearerToken(r.Header.Get("Authorization"))
		if provided == "" || !secureTokenEqual(provided, token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="webhost admin"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "a valid Bearer token is required"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	state := s.getState()
	type upInfo struct {
		URL      string `json:"url"`
		Healthy  bool   `json:"healthy"`
		InFlight int64  `json:"in_flight"`
	}
	type siteInfo struct {
		Name        string   `json:"name"`
		Type        string   `json:"type"`
		Domains     []string `json:"domains"`
		Root        string   `json:"root,omitempty"`
		TLS         bool     `json:"tls"`
		ACME        bool     `json:"acme"`
		Disabled    bool     `json:"disabled"`
		Maintenance bool     `json:"maintenance"`
		Upstreams   []upInfo `json:"upstreams,omitempty"`
	}
	sites := []siteInfo{}
	for _, rs := range state.sites {
		si := siteInfo{
			Name: rs.cfg.Name, Type: rs.cfg.Type, Domains: rs.cfg.Domains, Root: rs.root,
			TLS: rs.cfg.TLS.Enabled, ACME: rs.cfg.TLS.ACME, Disabled: rs.cfg.Disabled,
			Maintenance: atomic.LoadInt32(&rs.maintenance) == 1,
		}
		if rs.pool != nil {
			for _, u := range rs.pool.ups {
				si.Upstreams = append(si.Upstreams, upInfo{u.raw, u.isHealthy(), atomic.LoadInt64(&u.inflight)})
			}
		}
		sites = append(sites, si)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":     version,
		"go":          runtime.Version(),
		"pid":         os.Getpid(),
		"uptime_sec":  int64(time.Since(s.startedAt).Seconds()),
		"reloads":     atomic.LoadInt64(&s.reloads),
		"in_flight":   atomic.LoadInt64(&s.metrics.inFlight),
		"conns_total": atomic.LoadInt64(&s.metrics.totalConns),
		"goroutines":  runtime.NumGoroutine(),
		"mem_alloc":   ms.Alloc,
		"listen":      cfg.Listen,
		"data_dir":    cfg.DataDir,
		"config":      s.cfgPath,
		"sites":       sites,
	})
}

func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.getConfig().Sites)
}

// handleMailSend queues a message for delivery (POST JSON: to, subject,
// text and/or html; from and headers are optional). Until 1.2.3 nothing could
// put a message into the queue, so the mail settings had no effect.
func (s *Server) handleMailSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
		return
	}
	var in struct {
		From    string            `json:"from"`
		To      []string          `json:"to"`
		Subject string            `json:"subject"`
		Text    string            `json:"text"`
		HTML    string            `json:"html"`
		Headers map[string]string `json:"headers"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	id, err := s.mail.Send(r.Context(), outgoingMail{
		From: in.From, To: in.To, Subject: in.Subject, Text: in.Text, HTML: in.HTML, Headers: in.Headers,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "state": "queued"})
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	type certInfo struct {
		Host     string `json:"host"`
		Source   string `json:"source"`
		Subject  string `json:"subject"`
		Issuer   string `json:"issuer"`
		NotAfter string `json:"not_after"`
		DaysLeft int    `json:"days_left"`
	}
	out := []certInfo{}
	add := func(host, src string, c *tls.Certificate) {
		if c == nil || c.Leaf == nil {
			return
		}
		out = append(out, certInfo{
			Host: host, Source: src, Subject: c.Leaf.Subject.CommonName, Issuer: c.Leaf.Issuer.CommonName,
			NotAfter: c.Leaf.NotAfter.Format(time.RFC3339),
			DaysLeft: int(time.Until(c.Leaf.NotAfter).Hours() / 24),
		})
	}
	s.certs.mu.RLock()
	for h, c := range s.certs.manual {
		add(h, "manual", c)
	}
	for h, c := range s.certs.cache {
		src := "self-signed"
		if c.Leaf != nil && c.Leaf.Issuer.CommonName != appName+" local CA" {
			src = "acme"
		}
		add(h, src, c)
	}
	s.certs.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	writeJSON(w, http.StatusOK, map[string]interface{}{"ca": filepath.Join(s.certs.dir, "ca.crt"), "certificates": out})
}

// splitAction parses <prefix>{name}/{action} (the action may be absent).
func splitAction(p, prefix string) (name, action string) {
	rest := strings.Trim(strings.TrimPrefix(p, prefix), "/")
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

// /api/v1/backups: GET lists backups, POST creates one now.
func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list := listBackups(s.backupDir())
		if list == nil {
			list = []map[string]interface{}{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"dir": s.backupDir(), "backups": list})
	case http.MethodPost:
		file, err := s.makeBackup()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.log.Infof("backup created via Admin API: %s", file)
		writeJSON(w, http.StatusOK, map[string]string{"name": filepath.Base(file), "file": file})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
	}
}

// /api/v1/backups/{name} GET - download the archive
// /api/v1/backups/{name}/restore POST - restore (?sites=1 also restores site content)
func (s *Server) handleBackupAction(w http.ResponseWriter, r *http.Request) {
	name, action := splitAction(r.URL.Path, "/api/v1/backups/")
	if name == "" || name != filepath.Base(name) || !strings.HasPrefix(name, "backup-") || !strings.HasSuffix(name, ".tar.gz") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid backup name: " + name})
		return
	}
	archive := filepath.Join(s.backupDir(), name)
	if !fileExists(archive) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "backup not found: " + name})
		return
	}
	switch {
	case action == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		http.ServeFile(w, r, archive)
	case action == "restore" && r.Method == http.MethodPost:
		v := r.URL.Query().Get("sites")
		withSites := v == "1" || v == "true"
		// Restore from a hard link (or a copy): the safety backup made
		// below triggers rotation, which may delete this very archive.
		work := archive + ".restoring"
		_ = os.Remove(work)
		if err := os.Link(archive, work); err != nil {
			if err := copyFile(archive, work, 0o600); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}
		defer os.Remove(work)
		safety, err := s.makeBackup()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "safety backup was not created, restore cancelled: " + err.Error()})
			return
		}
		report, err := s.restoreBackup(work, withSites)
		if report == nil {
			report = map[string]interface{}{}
		}
		report["restored_from"] = name
		report["safety_backup"] = filepath.Base(safety)
		if err != nil {
			report["error"] = err.Error()
			writeJSON(w, http.StatusInternalServerError, report)
			return
		}
		if _, ok := report["config"]; ok {
			if err := s.Reload(); err != nil {
				report["reload_error"] = err.Error()
			} else {
				report["reloaded"] = true
			}
		}
		s.log.Infof("restoring from %s (sites: %v), safety backup: %s", name, withSites, filepath.Base(safety))
		writeJSON(w, http.StatusOK, report)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "need GET /api/v1/backups/{name} or POST /api/v1/backups/{name}/restore"})
	}
}

// /api/v1/cron/{name}/run - run the job outside its schedule.
func (s *Server) handleCronAction(w http.ResponseWriter, r *http.Request) {
	name, action := splitAction(r.URL.Path, "/api/v1/cron/")
	if r.Method != http.MethodPost || action != "run" || name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "need POST /api/v1/cron/{name}/run"})
		return
	}
	if err := s.sched.runNow(s.ctx, name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"job": name, "started": true})
}

// /api/v1/processes/{name}/restart - restart the external process.
func (s *Server) handleProcessAction(w http.ResponseWriter, r *http.Request) {
	name, action := splitAction(r.URL.Path, "/api/v1/processes/")
	if r.Method != http.MethodPost || action != "restart" || name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "need POST /api/v1/processes/{name}/restart"})
		return
	}
	if err := s.sup.restart(s.ctx, name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"process": name, "restarted": true})
}

// /api/v1/sites/{name}/{action}
func (s *Server) handleSiteAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/sites/")
	parts := strings.SplitN(strings.Trim(rest, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "site name not specified"})
		return
	}
	name := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	var target *SiteConfig
	for _, sc := range s.getConfig().Sites {
		if sc.Name == name {
			target = sc
			break
		}
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "site not found: " + name})
		return
	}
	var rsite *runtimeSite
	for _, rs := range s.getState().sites {
		if rs.cfg.Name == name {
			rsite = rs
			break
		}
	}

	switch action {
	case "":
		writeJSON(w, http.StatusOK, target)
	case "deploy":
		s.handleDeploy(w, r, target)
	case "rollback":
		s.handleRollback(w, r, target)
	case "releases":
		rels, err := listReleases(target.Root)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"current":  currentRelease(target.Root),
			"releases": rels,
		})
	case "maintenance/on", "maintenance/off":
		if rsite == nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "site is not active"})
			return
		}
		on := strings.HasSuffix(action, "on")
		if on {
			atomic.StoreInt32(&rsite.maintenance, 1)
		} else {
			atomic.StoreInt32(&rsite.maintenance, 0)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"site": name, "maintenance": on})
	case "enable", "disable":
		disable := action == "disable"
		// Edit only this site's flag in the file on disk (not the live
		// config, which request handlers are reading right now).
		s.editMu.Lock()
		err := setSiteDisabled(s.cfgPath, name, disable)
		s.editMu.Unlock()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := s.Reload(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"site": name, "disabled": disable})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown action: " + action})
	}
}

func releasesDir(root string) string { return filepath.Join(filepath.Dir(root), "releases") }

func listReleases(root string) ([]string, error) {
	if root == "" {
		return nil, errors.New("site has no root set")
	}
	entries, err := os.ReadDir(releasesDir(root))
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	out := []string{}
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sortReleases(out)
	return out, nil
}

// swapSymlink atomically switches root to release.
func swapSymlink(root, releasePath string) error {
	tmp := root + ".tmp-" + randomID()
	if err := os.Symlink(releasePath, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, root); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// currentReleaseFile is where the active release name is recorded when symbolic
// links are not available.
func currentReleaseFile(root string) string {
	return filepath.Join(filepath.Dir(root), "current.txt")
}

// swapRelease switches the site to the specified release.
//
// The main path is a symbolic link: the switch is atomic, rollback is instant.
// But on Windows creating links needs administrator rights or Developer
// Mode, and some file systems (FAT32, some network mounts) have no links
// at all. Then a fallback is used: the directory is assembled next to the
// root and swapped in by renaming, also without a moment when the site is down.
func swapRelease(root, releasePath string) error {
	if err := swapSymlink(root, releasePath); err == nil {
		_ = os.Remove(currentReleaseFile(root))
		return nil
	}
	// Fallback: copy the release next to the root, then swap it in by renaming.
	staging := root + ".new-" + randomID()
	if err := copyTree(releasePath, staging); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("preparing release copy: %w", err)
	}
	old := root + ".old-" + randomID()
	if fileExists(root) || dirExists(root) {
		if err := os.Rename(root, old); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("freeing %s: %w", root, err)
		}
	} else {
		old = ""
	}
	if err := os.Rename(staging, root); err != nil {
		if old != "" {
			_ = os.Rename(old, root) // put the old one back
		}
		_ = os.RemoveAll(staging)
		return fmt.Errorf("replacing %s: %w", root, err)
	}
	if old != "" {
		_ = os.RemoveAll(old)
	}
	// Record which release is active (there is no symlink to tell).
	return os.WriteFile(currentReleaseFile(root), []byte(filepath.Base(releasePath)+"\n"), 0o644)
}

// releasesManaged reports whether webhost manages the "releases" directory
// next to root: root is a symlink into it, or current.txt (copy mode) exists.
func releasesManaged(root string) bool {
	rels := releasesDir(root)
	if target, err := os.Readlink(root); err == nil {
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(root), target)
		}
		target = filepath.Clean(target)
		return target != rels && pathInside(rels, target)
	}
	return fileExists(currentReleaseFile(root))
}

// currentRelease returns the active release name, whether the site uses a
// symlink or a copy.
func currentRelease(root string) string {
	if target, err := os.Readlink(root); err == nil && target != "" {
		return filepath.Base(target)
	}
	if b, err := os.ReadFile(currentReleaseFile(root)); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// copyTree recursively copies the directory, keeping permissions.
// Symbolic links inside the tree are recreated as links or, if the file system
// does not support them, as copies of their content.
func copyTree(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() {
		return copyFile(src, dst, srcInfo.Mode().Perm())
	}
	if err := os.MkdirAll(dst, srcInfo.Mode().Perm()|0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		sp := filepath.Join(src, e.Name())
		dp := filepath.Join(dst, e.Name())
		switch {
		case e.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(sp)
			if err != nil {
				continue
			}
			// Only relative links within the tree; absolute ones and ".." are skipped.
			if filepath.IsAbs(target) || target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
				continue
			}
			joined := filepath.Clean(filepath.Join(filepath.Dir(sp), target))
			if !pathInside(src, joined) && joined != src {
				continue
			}
			_ = os.Symlink(target, dp)
		case e.IsDir():
			if err := copyTree(sp, dp); err != nil {
				return err
			}
		default:
			info, err := e.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				continue // Sockets, devices, etc. are not needed in the release
			}
			if err := copyFile(sp, dp, info.Mode().Perm()); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o644
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func unpackTarGz(r io.Reader, dest string, maxBytes int64) (int, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := 0
	var total int64
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return 0, err
	}
	// All checks use resolved paths: symbolic links from the archive
	// must not let a file be written or read outside the release directory.
	destReal, err := filepath.EvalSymlinks(destAbs)
	if err != nil {
		return 0, err
	}
	ensureDir := func(dir string) error {
		existing := dir
		for {
			if _, err := os.Lstat(existing); err == nil {
				break
			}
			parent := filepath.Dir(existing)
			if parent == existing {
				break
			}
			existing = parent
		}
		if real, err := filepath.EvalSymlinks(existing); err != nil || !pathInside(destReal, real) {
			return fmt.Errorf("unsafe path in archive: %s", dir)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if real, err := filepath.EvalSymlinks(dir); err != nil || !pathInside(destReal, real) {
			return fmt.Errorf("unsafe path in archive: %s", dir)
		}
		return nil
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return files, err
		}
		clean := filepath.Clean(hdr.Name)
		if clean == "." || clean == "/" {
			continue
		}
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
			return files, fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		target := filepath.Join(destAbs, clean)
		rel, err := filepath.Rel(destAbs, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return files, fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := ensureDir(target); err != nil {
				return files, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if files >= 100000 {
				return files, errors.New("archive file count limit exceeded")
			}
			if err := ensureDir(filepath.Dir(target)); err != nil {
				return files, err
			}
			if st, err := os.Lstat(target); err == nil && !st.Mode().IsRegular() {
				return files, fmt.Errorf("unsafe path in archive: %s", hdr.Name)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return files, err
			}
			limit := maxBytes - total
			if limit <= 0 {
				f.Close()
				return files, errors.New("archive size limit exceeded")
			}
			n, err := io.Copy(f, io.LimitReader(tr, limit+1))
			f.Close()
			if err != nil {
				return files, err
			}
			if n > limit {
				return files, errors.New("archive size limit exceeded")
			}
			total += n
			files++
		case tar.TypeSymlink, tar.TypeLink:
			return files, fmt.Errorf("symlinks in archive are forbidden: %s", hdr.Name)
		default:
			// FIFOs, devices etc. are ignored
		}
	}
	return files, nil
}

// pathInside reports whether p lies within base.
func pathInside(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

// sortReleases orders releases from newest to oldest. "legacy-<stamp>" is
// sorted by its time and counts as older than a release with the same stamp.
func sortReleases(names []string) {
	sort.SliceStable(names, func(i, j int) bool {
		a, b := names[i], names[j]
		la, lb := strings.HasPrefix(a, "legacy-"), strings.HasPrefix(b, "legacy-")
		sa, sb := strings.TrimPrefix(a, "legacy-"), strings.TrimPrefix(b, "legacy-")
		if sa != sb {
			return sa > sb
		}
		return !la && lb
	})
}

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request, site *SiteConfig) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "need POST with tar.gz body"})
		return
	}
	if !site.Deploy.Enabled {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "deploy is disabled for site " + site.Name})
		return
	}
	if site.Root == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "site has no root set"})
		return
	}
	root, err := filepath.Abs(site.Root)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rels := releasesDir(root)
	if err := os.MkdirAll(rels, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Mkdir (not MkdirAll): two deploys within one second must not write
	// into one directory, least of all into the release that is already active.
	base := time.Now().Format("20060102-150405")
	stamp := base
	releasePath := filepath.Join(rels, stamp)
	for i := 2; ; i++ {
		err := os.Mkdir(releasePath, 0o755)
		if err == nil {
			break
		}
		if !os.IsExist(err) || i > 99 {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		stamp = fmt.Sprintf("%s-%02d", base, i)
		releasePath = filepath.Join(rels, stamp)
	}

	files, err := unpackTarGz(r.Body, releasePath, 1<<30)
	if err != nil {
		_ = os.RemoveAll(releasePath)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "extract: " + err.Error()})
		return
	}
	if files == 0 {
		_ = os.RemoveAll(releasePath)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "archive is empty"})
		return
	}

	// If root is a regular directory with content of its own, turn it into the
	// first release so that nothing is lost. But if releases are already managed
	// (current.txt means a system without symbolic links), the directory must
	// not be touched: it is a deployed copy of the previous release.
	if !fileExists(currentReleaseFile(root)) {
		if st, err := os.Lstat(root); err == nil && st.Mode()&os.ModeSymlink == 0 {
			if st.IsDir() {
				legacy := filepath.Join(rels, "legacy-"+stamp)
				if err := os.Rename(root, legacy); err != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "moving old directory: " + err.Error()})
					return
				}
			} else {
				_ = os.Remove(root)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := swapRelease(root, releasePath); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "switching release: " + err.Error()})
		return
	}
	pruneReleases(rels, site.Deploy.KeepReleases)
	s.log.Infof("deploy site %s: release %s (%d files)", site.Name, stamp, files)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"site": site.Name, "release": stamp, "files": files, "path": releasePath,
	})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, site *SiteConfig) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	root, err := filepath.Abs(site.Root)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rels, err := listReleases(root)
	if err != nil || len(rels) < 2 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no previous release"})
		return
	}
	want := r.URL.Query().Get("release")
	currentName := currentRelease(root)
	if want == "" {
		// The previous release is the next older one relative to the current.
		idx := -1
		for i, rel := range rels {
			if rel == currentName {
				idx = i
				break
			}
		}
		switch {
		case idx < 0:
			want = rels[0]
		case idx+1 < len(rels):
			want = rels[idx+1]
		default:
			writeJSON(w, http.StatusConflict, map[string]string{"error": "no previous release"})
			return
		}
	}
	found := false
	for _, rel := range rels {
		if rel == want {
			found = true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "release not found: " + want})
		return
	}
	if err := swapRelease(root, filepath.Join(releasesDir(root), want)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.log.Infof("rollback site %s to release %s", site.Name, want)
	writeJSON(w, http.StatusOK, map[string]interface{}{"site": site.Name, "release": want})
}

func pruneReleases(rels string, keep int) {
	if keep <= 0 {
		keep = 5
	}
	entries, err := os.ReadDir(rels)
	if err != nil {
		return
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sortReleases(dirs)
	for i, d := range dirs {
		if i >= keep {
			_ = os.RemoveAll(filepath.Join(rels, d))
		}
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such endpoint"})
		return
	}
	cfg := s.getConfig()
	state := s.getState()
	var b bytes.Buffer
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>webhost — panel</title>
<style>body{font:14px/1.6 system-ui,sans-serif;margin:0;background:#0b1020;color:#e5e7eb}
.wrap{max-width:1000px;margin:0 auto;padding:32px 16px}h1{font-size:22px}
table{width:100%;border-collapse:collapse;margin:16px 0;background:#111827;border-radius:8px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #1f2937;font-size:13px}
th{background:#1f2937;color:#9ca3af;font-weight:600}
.ok{color:#34d399}.bad{color:#f87171}.muted{color:#9ca3af}code{background:#1f2937;padding:2px 6px;border-radius:4px}</style>
</head><body><div class="wrap"><h1>webhost — control panel</h1>`)
	fmt.Fprintf(&b, `<p class="muted">version %s · uptime %s · in-flight requests: %d · goroutines: %d</p>`,
		version, time.Since(s.startedAt).Truncate(time.Second), atomic.LoadInt64(&s.metrics.inFlight), runtime.NumGoroutine())
	b.WriteString(`<table><tr><th>Site</th><th>Type</th><th>Domains</th><th>Source</th><th>Status</th></tr>`)
	for _, rs := range state.sites {
		src := rs.root
		if rs.cfg.Type == "proxy" {
			src = strings.Join(rs.cfg.Upstreams, ", ")
		} else if rs.cfg.Type == "redirect" {
			src = rs.cfg.RedirectTo
		}
		status := `<span class="ok">active</span>`
		if atomic.LoadInt32(&rs.maintenance) == 1 {
			status = `<span class="bad">maintenance</span>`
		}
		if rs.pool != nil {
			up, total := 0, len(rs.pool.ups)
			for _, u := range rs.pool.ups {
				if u.isHealthy() {
					up++
				}
			}
			status += fmt.Sprintf(` <span class="muted">(backends %d/%d)</span>`, up, total)
		}
		fmt.Fprintf(&b, `<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>`,
			htmlEscape(rs.cfg.Name), htmlEscape(rs.cfg.Type), htmlEscape(strings.Join(rs.cfg.Domains, ", ")),
			htmlEscape(src), status)
	}
	b.WriteString(`</table>`)
	fmt.Fprintf(&b, `<p class="muted">config: <code>%s</code> · data: <code>%s</code> · metrics: <a style="color:#60a5fa" href="/metrics">/metrics</a> (Bearer)</p>`,
		htmlEscape(s.cfgPath), htmlEscape(cfg.DataDir))
	b.WriteString(`</div></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b.Bytes())
}

// ============================================================================
// CLI
// ============================================================================

func init() {
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
	_ = mime.AddExtensionType(".wasm", "application/wasm")
	_ = mime.AddExtensionType(".avif", "image/avif")
	_ = mime.AddExtensionType(".webp", "image/webp")
	_ = mime.AddExtensionType(".woff2", "font/woff2")
	_ = mime.AddExtensionType(".mjs", "application/javascript")
}

// defaultDataDir picks a data directory that is writable on any system:
// as root a system-wide path, otherwise the user's config directory
// (WEBHOST_DIR overrides both).
func defaultDataDir() string {
	if v := os.Getenv("WEBHOST_DIR"); v != "" {
		return v
	}
	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" && isRootUser() {
			return filepath.Join(pd, appName)
		}
	case "darwin":
		if isRootUser() {
			return filepath.Join("/usr/local/var", appName)
		}
	default:
		if isRootUser() {
			return filepath.Join("/srv", appName)
		}
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, appName)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "."+appName)
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), appName+"-data")
	}
	return appName + "-data"
}

// isRootUser answers "are there enough rights for system-wide paths?"
// On Windows Geteuid returns -1, so it is checked differently: by trying
// to write to ProgramData, the real sign of administrator rights.
func isRootUser() bool {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			return false
		}
		probe := filepath.Join(pd, "."+appName+"-probe")
		f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return false
		}
		f.Close()
		_ = os.Remove(probe)
		return true
	}
	return os.Geteuid() == 0
}

func usage() {
	fmt.Printf(`%s %s — universal production website hosting
Single file, stdlib only, no go.mod and no external dependencies.

With no arguments:
  webhost                                                           bootstrap on first run and start

Deploy and build:
  webhost build     [-all] [-os OS] [-arch ARCH] [-out DIR]         build binaries (downloads Go if missing)
  webhost init      [-dir DIR] [-domain DOMAIN] [-email EMAIL]      prepare data dir, config, CA, demo site
  webhost run       [-config FILE]                                  start the server
  webhost service   [-install] [-uninstall] [-user USER]            autostart: systemd, rc.d, OpenRC, launchd, schtasks
  webhost doctor    [-config FILE] [-dir DIR]                       check config, CA, sites before start

Operations:
  webhost status    [-config FILE] [-url URL] [-token TOKEN]        status of a running server
  webhost deploy    SITE PATH [-config FILE] [-url URL] [-token T]  deploy a directory or tar.gz (atomic + rollback)
  webhost rollback  SITE [-release NAME] [-config FILE]             roll back to the previous release
  webhost reload    [-config FILE]                                  reload config without restart
  webhost backup    [create | list] [-config FILE]                  backup: create / list
  webhost restore   ARCHIVE [-sites] [-config FILE]                 restore (makes a safety backup first)
  webhost cron      [list | run JOB] [-config FILE]                 scheduler jobs
  webhost mail      [queue] [-limit N] [-config FILE]               outbound mail queue
  webhost mail send -to ADDR -subject TEXT -text TEXT|-text-file F  queue a message (also -html-file, -from)
  webhost ps        [list | restart NAME] [-config FILE]            supervised processes (PHP-FPM, etc.)
  webhost hash      PASSWORD                                        password hash for basic-auth
  webhost ca        [-config FILE]                                  local CA path and how to trust it
  webhost roots     [-import FILE.pem] [-config FILE]              trusted roots for outbound HTTPS
  webhost version

Quick start — three options:
  chmod +x main.go && ./main.go                 run straight from source (Go required on the system)
  go build -o webhost main.go && ./webhost      normal build
  ./main.go build -all                          binaries for all platforms in ./dist
`, appName, version)
}

func main() {
	// Starting without arguments means "set up and run": the first start
	// creates a data directory, a config, a local CA and a demo site, then
	// starts the server. Later starts just run it.
	if len(os.Args) < 2 {
		if err := cmdAuto(nil); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "run", "serve":
		err = cmdRun(os.Args[2:])
	case "build":
		err = cmdBuild(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "deploy":
		err = cmdDeploy(os.Args[2:])
	case "rollback":
		err = cmdRollback(os.Args[2:])
	case "reload":
		err = cmdReload(os.Args[2:])
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "restore":
		err = cmdRestore(os.Args[2:])
	case "cron":
		err = cmdCron(os.Args[2:])
	case "mail":
		err = cmdMail(os.Args[2:])
	case "ps":
		err = cmdPS(os.Args[2:])
	case "hash":
		err = cmdHash(os.Args[2:])
	case "ca":
		err = cmdCA(os.Args[2:])
	case "roots":
		err = cmdRoots(os.Args[2:])
	case "service", "systemd":
		err = cmdService(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "version", "-v", "--version":
		printVersion()
	case "help", "-h", "--help":
		usage()
	default:
		// A flag instead of a command ("webhost -config x") means run:
		// that is the most common case.
		if strings.HasPrefix(os.Args[1], "-") {
			err = cmdRun(os.Args[1:])
			break
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("%s %s\n", appName, version)
	fmt.Printf("  built:       %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	extraRootsPath.Store(filepath.Join(defaultDataDir(), "certs", "roots.pem"))
	if pool, from, err := rootPool(); err == nil {
		fmt.Printf("  CA roots:    %s\n", describeRoots(pool, from))
	} else {
		fmt.Printf("  CA roots:    none\n")
	}
	if systemHasResolvConf() {
		fmt.Printf("  DNS:         system\n")
	} else {
		fmt.Printf("  DNS:         custom resolver (no /etc/resolv.conf on system)\n")
	}
	fmt.Printf("  directory:   %s\n", defaultDataDir())
}

// cmdAuto is the start without arguments: init on the first run, then run.
// It has to work right away.
func cmdAuto(extra []string) error {
	dir := defaultDataDir()
	cfg := filepath.Join(dir, "config.json")
	if !fileExists(cfg) {
		fmt.Fprintf(os.Stderr, "first run: bootstrapping in %s\n", dir)
		if err := cmdInit([]string{"-dir", dir}); err != nil {
			return err
		}
	}
	return cmdRun(append([]string{"-config", cfg}, extra...))
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", defaultDataDir(), "data directory")
	domain := fs.String("domain", "", "primary domain (enables Let's Encrypt ACME certificate)")
	email := fs.String("email", "", "email for Let's Encrypt")
	force := fs.Bool("force", false, "overwrite existing config.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(dataDir, "config.json")
	if fileExists(cfgPath) && !*force {
		return fmt.Errorf("%s already exists (overwrite with -force)", cfgPath)
	}

	stamp := time.Now().Format("20060102-150405")
	siteDir := filepath.Join(dataDir, "sites", "default")
	release := filepath.Join(siteDir, "releases", stamp)
	for _, d := range []string{dataDir, filepath.Join(dataDir, "logs"), filepath.Join(dataDir, "certs"), release} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	if err := os.WriteFile(filepath.Join(release, "index.html"), []byte(demoIndexHTML), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(release, "404.html"), []byte(demo404HTML), 0o644); err != nil {
		return err
	}
	current := filepath.Join(siteDir, "current")
	_ = os.Remove(current)
	if err := os.Symlink(release, current); err != nil {
		return err
	}

	cfg := defaultConfig(dataDir)
	site := demoSite(dataDir)
	if *domain != "" {
		site.Domains = []string{*domain, "www." + *domain, "localhost"}
		site.TLS.ACME = true
		cfg.ACME.Enabled = true
		cfg.ACME.Email = *email
		cfg.ACME.AgreeTOS = true
	}
	cfg.Sites = []*SiteConfig{site}

	// Examples of the other site types are disabled and serve as templates.
	cfg.Sites = append(cfg.Sites,
		&SiteConfig{
			Name: "app-proxy", Domains: []string{"app.localhost"}, Disabled: true, Type: "proxy",
			Upstreams: []string{"http://127.0.0.1:3000"}, Balance: "roundrobin",
			HealthCheck: HealthConfig{Enabled: true, Path: "/", IntervalSec: 10, TimeoutSec: 3, FailAfter: 3, RiseAfter: 2},
			ProxyConfig: ProxyConfig{PreserveHost: true, Retries: 2, DialTimeoutSec: 10},
			TLS:         TLSConfig{Enabled: true, MinVersion: "1.2"},
		},
		&SiteConfig{
			Name: "php-site", Domains: []string{"php.localhost"}, Disabled: true, Type: "fastcgi",
			Root:    filepath.Join(dataDir, "sites", "php-site", "current"),
			FastCGI: FastCGIConfig{Address: "unix:/run/php/php-fpm.sock", IndexFile: "index.php", SplitPath: ".php", TimeoutSec: 60},
			TLS:     TLSConfig{Enabled: true, MinVersion: "1.2"},
			Deploy:  DeployConfig{Enabled: true, KeepReleases: 5},
		},
		&SiteConfig{
			Name: "spa", Domains: []string{"spa.localhost"}, Disabled: true, Type: "spa",
			Root: filepath.Join(dataDir, "sites", "spa", "current"), Index: []string{"index.html"},
			TLS:    TLSConfig{Enabled: true, MinVersion: "1.2"},
			Deploy: DeployConfig{Enabled: true, KeepReleases: 5},
		},
	)
	// Validate through the regular loader, but save the config as written:
	// the normalized form carries a copy of "defaults" in every site, and
	// with those copies on disk later edits of "defaults" changed nothing.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if _, err := parseConfig(raw, cfgPath); err != nil {
		return err
	}
	if err := saveConfig(cfg, cfgPath); err != nil {
		return err
	}

	lg := newLogger("info", os.Stdout)
	if _, err := newCertManager(filepath.Join(dataDir, "certs"), lg); err != nil {
		return err
	}

	fmt.Printf("\n  Done. Data directory: %s\n", dataDir)
	fmt.Printf("  Config       : %s\n", cfgPath)
	fmt.Printf("  Demo site    : %s\n", current)
	fmt.Printf("  Admin token  : %s\n", cfg.Admin.Token)
	fmt.Printf("  Local CA     : %s\n\n", filepath.Join(dataDir, "certs", "ca.crt"))
	fmt.Printf("  Start: webhost run -config %s\n\n", cfgPath)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !fileExists(*cfgPath) {
		return fmt.Errorf("config %s not found — run: webhost init", *cfgPath)
	}
	srv, err := newServer(*cfgPath)
	if err != nil {
		return err
	}
	return srv.Run()
}

// CLI commands that talk to the Admin API

func adminEndpoint(cfgPath, urlFlag, tokenFlag string) (string, string, error) {
	base, token := urlFlag, tokenFlag
	if base == "" || token == "" {
		if cfg, err := loadConfig(cfgPath); err == nil {
			if base == "" {
				host := cfg.Admin.Listen
				if strings.HasPrefix(host, ":") {
					host = "127.0.0.1" + host
				}
				base = "http://" + host
			}
			if token == "" {
				token = cfg.Admin.Token
			}
		} else if base == "" {
			return "", "", fmt.Errorf("failed to read %s: %w (pass -url and -token)", cfgPath, err)
		}
	}
	if token == "" {
		return "", "", errors.New("admin token not set (-token or config.json)")
	}
	return strings.TrimSuffix(base, "/"), token, nil
}

func adminRequest(method, url, token string, body io.Reader, contentType string) ([]byte, int, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return data, resp.StatusCode, err
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json")
	urlFlag := fs.String("url", "", "Admin API address")
	token := fs.String("token", "", "admin token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	base, tok, err := adminEndpoint(*cfgPath, *urlFlag, *token)
	if err != nil {
		return err
	}
	data, code, err := adminRequest(http.MethodGet, base+"/api/v1/status", tok, nil, "")
	if err != nil {
		return fmt.Errorf("server is not responding at %s: %w", base, err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(data)))
	}
	fmt.Println(string(data))
	return nil
}

// adminCmd is the common part of the CLI commands that work through the Admin API.
type adminCmd struct {
	fs                   *flag.FlagSet
	cfgPath, urlF, token *string
}

func newAdminCmd(name string) *adminCmd {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return &adminCmd{
		fs:      fs,
		cfgPath: fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json"),
		urlF:    fs.String("url", "", "Admin API address"),
		token:   fs.String("token", "", "admin token"),
	}
}

// parse accepts flags anywhere: "webhost restore ARCHIVE -sites".
func (c *adminCmd) parse(args []string) ([]string, error) {
	var pos []string
	for {
		if err := c.fs.Parse(args); err != nil {
			return nil, err
		}
		if c.fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, c.fs.Arg(0))
		args = c.fs.Args()[1:]
	}
}

// call queries the Admin API and prints the answer.
func (c *adminCmd) call(method, apiPath string) error {
	return c.callWith(method, apiPath, nil, "")
}

// callWith is call with a request body.
func (c *adminCmd) callWith(method, apiPath string, body io.Reader, contentType string) error {
	base, tok, err := adminEndpoint(*c.cfgPath, *c.urlF, *c.token)
	if err != nil {
		return err
	}
	data, code, err := adminRequest(method, base+apiPath, tok, body, contentType)
	if err != nil {
		return fmt.Errorf("server is not responding at %s: %w", base, err)
	}
	if code < 200 || code > 299 {
		return fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(data)))
	}
	fmt.Println(strings.TrimSpace(string(data)))
	return nil
}

func cmdBackup(args []string) error {
	c := newAdminCmd("backup")
	pos, err := c.parse(args)
	if err != nil {
		return err
	}
	switch {
	case len(pos) == 0 || (len(pos) == 1 && pos[0] == "create"):
		return c.call(http.MethodPost, "/api/v1/backups")
	case len(pos) == 1 && pos[0] == "list":
		return c.call(http.MethodGet, "/api/v1/backups")
	}
	return errors.New("usage: webhost backup [create | list]")
}

func cmdRestore(args []string) error {
	c := newAdminCmd("restore")
	sites := c.fs.Bool("sites", false, "also restore site contents")
	pos, err := c.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: webhost restore ARCHIVE [-sites]   (backup names: webhost backup list)")
	}
	p := "/api/v1/backups/" + url.PathEscape(filepath.Base(pos[0])) + "/restore"
	if *sites {
		p += "?sites=1"
	}
	return c.call(http.MethodPost, p)
}

func cmdCron(args []string) error {
	c := newAdminCmd("cron")
	pos, err := c.parse(args)
	if err != nil {
		return err
	}
	switch {
	case len(pos) == 0 || (len(pos) == 1 && pos[0] == "list"):
		return c.call(http.MethodGet, "/api/v1/cron")
	case len(pos) == 2 && pos[0] == "run":
		return c.call(http.MethodPost, "/api/v1/cron/"+url.PathEscape(pos[1])+"/run")
	}
	return errors.New("usage: webhost cron [list | run JOB]")
}

func cmdMail(args []string) error {
	if len(args) > 0 && args[0] == "send" {
		return cmdMailSend(args[1:])
	}
	c := newAdminCmd("mail")
	limit := c.fs.Int("limit", 100, "how many messages to show")
	pos, err := c.parse(args)
	if err != nil {
		return err
	}
	if len(pos) > 1 || (len(pos) == 1 && pos[0] != "queue") {
		return errors.New("usage: webhost mail [queue] [-limit N] | webhost mail send -to ADDR -subject TEXT -text TEXT")
	}
	return c.call(http.MethodGet, "/api/v1/mail/queue?limit="+strconv.Itoa(*limit))
}

// cmdMailSend queues a message through the running server.
func cmdMailSend(args []string) error {
	c := newAdminCmd("mail send")
	to := c.fs.String("to", "", "recipients, comma-separated")
	subject := c.fs.String("subject", "", "subject")
	from := c.fs.String("from", "", "sender (default: mail.from)")
	text := c.fs.String("text", "", `plain-text body ("-" reads standard input)`)
	textFile := c.fs.String("text-file", "", "file with the plain-text body")
	htmlFile := c.fs.String("html-file", "", "file with the HTML body")
	pos, err := c.parse(args)
	if err != nil {
		return err
	}
	if len(pos) > 0 || strings.TrimSpace(*to) == "" {
		return errors.New("usage: webhost mail send -to ADDR[,ADDR] -subject TEXT (-text TEXT | -text-file FILE) [-html-file FILE] [-from ADDR]")
	}
	msg := map[string]interface{}{"subject": *subject, "from": *from}
	var rcpts []string
	for _, a := range strings.Split(*to, ",") {
		if a = strings.TrimSpace(a); a != "" {
			rcpts = append(rcpts, a)
		}
	}
	msg["to"] = rcpts
	body := *text
	switch {
	case *textFile != "":
		b, err := os.ReadFile(*textFile)
		if err != nil {
			return err
		}
		body = string(b)
	case body == "-":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20))
		if err != nil {
			return err
		}
		body = string(b)
	}
	if body != "" {
		msg["text"] = body
	}
	if *htmlFile != "" {
		b, err := os.ReadFile(*htmlFile)
		if err != nil {
			return err
		}
		msg["html"] = string(b)
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return c.callWith(http.MethodPost, "/api/v1/mail/send", bytes.NewReader(payload), "application/json")
}

func cmdPS(args []string) error {
	c := newAdminCmd("ps")
	pos, err := c.parse(args)
	if err != nil {
		return err
	}
	switch {
	case len(pos) == 0 || (len(pos) == 1 && pos[0] == "list"):
		return c.call(http.MethodGet, "/api/v1/processes")
	case len(pos) == 2 && pos[0] == "restart":
		return c.call(http.MethodPost, "/api/v1/processes/"+url.PathEscape(pos[1])+"/restart")
	}
	return errors.New("usage: webhost ps [list | restart NAME]")
}

func cmdReload(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json")
	urlFlag := fs.String("url", "", "Admin API address")
	token := fs.String("token", "", "admin token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	base, tok, err := adminEndpoint(*cfgPath, *urlFlag, *token)
	if err != nil {
		return err
	}
	data, code, err := adminRequest(http.MethodPost, base+"/api/v1/reload", tok, nil, "")
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(data)))
	}
	fmt.Println("configuration reloaded")
	return nil
}

// tarGzDir packs the directory into tar.gz (paths do not include the directory itself).
func tarGzDir(dir string, w io.Writer) error {
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

func cmdDeploy(args []string) error {
	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json")
	urlFlag := fs.String("url", "", "Admin API address")
	token := fs.String("token", "", "admin token")
	rest, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(rest) < 2 {
		return errors.New("usage: webhost deploy SITE PATH")
	}
	site, src := rest[0], rest[1]
	base, tok, err := adminEndpoint(*cfgPath, *urlFlag, *token)
	if err != nil {
		return err
	}

	var body io.Reader
	if dirExists(src) {
		tmp, err := os.CreateTemp("", "webhost-deploy-*.tar.gz")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		if err := tarGzDir(src, tmp); err != nil {
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if st, err := tmp.Stat(); err == nil {
			fmt.Printf("packed %s from %s\n", humanBytes(st.Size()), src)
		}
		body = tmp
	} else if fileExists(src) {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		body = f
	} else {
		return fmt.Errorf("directory or archive not found: %s", src)
	}

	data, code, err := adminRequest(http.MethodPost, base+"/api/v1/sites/"+url.PathEscape(site)+"/deploy", tok, body, "application/gzip")
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(data)))
	}
	fmt.Println(string(data))
	return nil
}

// parseInterleaved parses flags placed before, between or after positional args.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos, tail []string
	for i, a := range args {
		if a == "--" { // everything after "--" is positional
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return append(pos, tail...), nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json")
	urlFlag := fs.String("url", "", "Admin API address")
	token := fs.String("token", "", "admin token")
	release := fs.String("release", "", "specific release")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: webhost rollback SITE [-release NAME]")
	}
	base, tok, err := adminEndpoint(*cfgPath, *urlFlag, *token)
	if err != nil {
		return err
	}
	u := base + "/api/v1/sites/" + url.PathEscape(pos[0]) + "/rollback"
	if *release != "" {
		u += "?release=" + url.QueryEscape(*release)
	}
	data, code, err := adminRequest(http.MethodPost, u, tok, nil, "")
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(data)))
	}
	fmt.Println(string(data))
	return nil
}

func cmdHash(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: webhost hash PASSWORD")
	}
	fmt.Println(hashPassword(args[0]))
	return nil
}

func cmdCA(args []string) error {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := filepath.Dir(*cfgPath)
	if cfg, err := loadConfig(*cfgPath); err == nil {
		dataDir = cfg.DataDir
	}
	ca := filepath.Join(dataDir, "certs", "ca.crt")
	if !fileExists(ca) {
		return fmt.Errorf("CA not found: %s (run webhost init)", ca)
	}
	fmt.Printf(`Local CA: %s

To make the browser trust local HTTPS certificates:

  Debian/Ubuntu:
    sudo cp %s /usr/local/share/ca-certificates/webhost-local-ca.crt
    sudo update-ca-certificates

  Fedora/RHEL:
    sudo cp %s /etc/pki/ca-trust/source/anchors/webhost-local-ca.crt
    sudo update-ca-trust

  Firefox/Chrome (user profile) — import the file manually
  under Settings → Privacy and security → Certificates → Authorities.
`, ca, ca, ca)
	return nil
}

// ============================================================================
// Systemd, OpenRC, BSD rc.d, launchd, schtasks
//
// The init system is detected automatically, or set explicitly with the -type flag.
// ============================================================================

// initSystem is how the OS starts services at boot.
type initSystem string

const (
	initSystemd  initSystem = "systemd"
	initOpenRC   initSystem = "openrc"
	initRunit    initSystem = "runit"
	initBSDRC    initSystem = "rc.d"
	initLaunchd  initSystem = "launchd"
	initSchtasks initSystem = "schtasks"
	initNone     initSystem = "none"
)

// detectInitSystem determines how services are managed on this machine.
func detectInitSystem() initSystem {
	switch runtime.GOOS {
	case "windows":
		return initSchtasks
	case "darwin":
		return initLaunchd
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		return initBSDRC
	case "linux":
		if dirExists("/run/systemd/system") {
			return initSystemd
		}
		if fileExists("/sbin/openrc-run") || fileExists("/usr/bin/openrc-run") || dirExists("/etc/conf.d") {
			return initOpenRC
		}
		if dirExists("/etc/sv") || fileExists("/usr/bin/sv") {
			return initRunit
		}
		// systemd may be installed without being the current PID 1.
		if fileExists("/usr/bin/systemctl") || fileExists("/bin/systemctl") {
			return initSystemd
		}
		return initNone
	}
	return initNone
}

// serviceUnit is the generated service definition and where to put it.
type serviceUnit struct {
	kind    initSystem
	path    string // where to write the file (empty for schtasks)
	mode    os.FileMode
	content string   // file content
	enable  []string // commands that enable and start it
	disable []string // commands that stop and disable it
	hint    string   // what to tell the user
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	dir := fs.String("dir", "", "data directory (if no -config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *cfgPath
	if path == "" {
		data := *dir
		if data == "" {
			data = defaultDataDir()
		}
		path = filepath.Join(data, "config.json")
	}
	fmt.Printf("webhost doctor %s\n", version)
	fmt.Printf("  go:          %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	ok := true
	check := func(name string, cond bool, detail string) {
		mark := "OK"
		if !cond {
			mark = "FAIL"
			ok = false
		}
		fmt.Printf("  %-14s %s  %s\n", name+":", mark, detail)
	}
	if st, err := os.Stat(path); err != nil {
		check("config", false, path+" — "+err.Error())
	} else {
		check("config", true, fmt.Sprintf("%s (%d B)", path, st.Size()))
		cfg, err := loadConfig(path)
		if err != nil {
			check("parse", false, err.Error())
		} else {
			check("parse", true, fmt.Sprintf("%d site(s)", len(cfg.Sites)))
			if err := validateTrustedProxies(&cfg.Listen); err != nil {
				check("proxies", false, err.Error())
			} else {
				check("proxies", true, "trusted_proxies looks OK")
			}
			if cfg.Admin.Enabled {
				if isAllInterfacesListen(cfg.Admin.Listen) {
					check("admin.bind", false, cfg.Admin.Listen+" — all interfaces")
				} else {
					check("admin.bind", true, cfg.Admin.Listen)
				}
				check("admin.token", len(cfg.Admin.Token) >= 16, fmt.Sprintf("length %d", len(cfg.Admin.Token)))
			} else {
				check("admin", true, "disabled")
			}
			for _, s := range cfg.Sites {
				if s.Root == "" {
					continue
				}
				if dirExists(s.Root) {
					check("site:"+s.Name, true, s.Root)
				} else if s.Disabled {
					fmt.Printf("  %-14s WARN %s missing (site disabled)\n", "site:"+s.Name+":", s.Root)
				} else {
					check("site:"+s.Name, false, s.Root+" missing (run will serve a stub)")
				}
			}
			if cfg.Listen.HTTP != "" {
				check("listen.http", true, cfg.Listen.HTTP)
			}
			if cfg.Listen.HTTPS != "" {
				check("listen.https", true, cfg.Listen.HTTPS)
			}
			ca := filepath.Join(cfg.DataDir, "certs", "ca.crt")
			check("local CA", fileExists(ca), ca)
			extraRootsPath.Store(filepath.Join(cfg.DataDir, "certs", "roots.pem"))
		}
	}
	if pool, from, err := rootPool(); err == nil {
		check("CA roots", true, describeRoots(pool, from))
	} else {
		check("CA roots", false, err.Error())
	}
	check("resolv.conf", systemHasResolvConf(), "/etc/resolv.conf")
	if !ok {
		return fmt.Errorf("doctor: problems found — fix the config before starting")
	}
	fmt.Println("  summary:     looks ready for run")
	return nil
}

func cmdService(args []string) error {
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json")
	install := fs.Bool("install", false, "write service file and enable autostart")
	uninstall := fs.Bool("uninstall", false, "disable autostart and remove service file")
	user := fs.String("user", "", "user the service runs as (default: current user)")
	kindFlag := fs.String("type", "", "init system: systemd|openrc|runit|rc.d|launchd|schtasks")
	if err := fs.Parse(args); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	absCfg, err := filepath.Abs(*cfgPath)
	if err != nil {
		return err
	}
	dataDir := filepath.Dir(absCfg)

	runAs := *user
	if runAs == "" {
		if isRootUser() {
			runAs = "root"
		} else if u := os.Getenv("USER"); u != "" {
			runAs = u
		} else if u := os.Getenv("USERNAME"); u != "" {
			runAs = u
		} else {
			runAs = "root"
		}
	}

	kind := initSystem(*kindFlag)
	if kind == "" {
		kind = detectInitSystem()
	}
	if kind == initNone {
		return fmt.Errorf("could not detect init system on %s; "+
			"specify it explicitly: -type systemd|openrc|runit|rc.d|launchd|schtasks", runtime.GOOS)
	}

	unit, err := buildServiceUnit(kind, exe, absCfg, dataDir, runAs)
	if err != nil {
		return err
	}

	switch {
	case *uninstall:
		return uninstallService(unit)
	case *install:
		if err := checkServiceConfig(absCfg, exe); err != nil {
			return err
		}
		return installService(unit)
	default:
		fmt.Fprintf(os.Stderr, "init system: %s\n", unit.kind)
		if unit.path != "" {
			fmt.Fprintf(os.Stderr, "service file:         %s\n\n", unit.path)
			fmt.Print(unit.content)
		} else {
			fmt.Fprintf(os.Stderr, "\ninstall command:\n  %s\n", strings.Join(unit.enable, " "))
		}
		fmt.Fprintf(os.Stderr, "\n# install:  %s service -install -config %s\n", exe, absCfg)
		fmt.Fprintf(os.Stderr, "# remove:   %s service -uninstall -config %s\n", exe, absCfg)
		return nil
	}
}

// checkServiceConfig refuses to install a service whose config is missing or
// broken: such a service only fails at every boot. Under sudo the default
// path is the system one (/srv/webhost/...), not the invoking user's config.
func checkServiceConfig(cfgPath, exe string) error {
	if _, err := os.Stat(cfgPath); err != nil {
		return fmt.Errorf("config %s not found: create it with \"%s init -dir %s\" or pass -config FILE",
			cfgPath, exe, filepath.Dir(cfgPath))
	}
	if _, err := loadConfig(cfgPath); err != nil {
		return fmt.Errorf("config %s: %w", cfgPath, err)
	}
	return nil
}

func buildServiceUnit(kind initSystem, exe, cfg, dataDir, user string) (*serviceUnit, error) {
	switch kind {
	case initSystemd:
		return &serviceUnit{
			kind: kind,
			path: "/etc/systemd/system/" + appName + ".service",
			mode: 0o644,
			content: fmt.Sprintf(`[Unit]
Description=%[1]s — universal site hosting server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%[2]s
ExecStart=%[3]s run -config %[4]s
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=false
ReadWritePaths=%[5]s
WorkingDirectory=%[5]s

[Install]
WantedBy=multi-user.target
`, appName, user, exe, cfg, dataDir),
			enable:  []string{"systemctl", "daemon-reload"},
			disable: []string{"systemctl", "disable", "--now", appName},
			hint:    "systemctl status " + appName,
		}, nil

	case initOpenRC:
		return &serviceUnit{
			kind: kind,
			path: "/etc/init.d/" + appName,
			mode: 0o755,
			content: fmt.Sprintf(`#!/sbin/openrc-run

name="%[1]s"
description="Universal site hosting server"
command="%[2]s"
command_args="run -config %[3]s"
command_user="%[4]s"
command_background="yes"
pidfile="/run/%[1]s.pid"
directory="%[5]s"
output_log="/var/log/%[1]s.log"
error_log="/var/log/%[1]s.err"

depend() {
    need net
    after firewall
}

reload() {
    ebegin "Reloading $name"
    start-stop-daemon --signal HUP --pidfile "$pidfile"
    eend $?
}
`, appName, exe, cfg, user, dataDir),
			enable:  []string{"rc-update", "add", appName, "default"},
			disable: []string{"rc-update", "del", appName, "default"},
			hint:    "rc-service " + appName + " start",
		}, nil

	case initRunit:
		return &serviceUnit{
			kind: kind,
			path: "/etc/sv/" + appName + "/run",
			mode: 0o755,
			content: fmt.Sprintf(`#!/bin/sh
exec 2>&1
cd %[4]s
exec chpst -u %[3]s %[1]s run -config %[2]s
`, exe, cfg, user, dataDir),
			enable:  []string{"ln", "-sf", "/etc/sv/" + appName, "/var/service/" + appName},
			disable: []string{"rm", "-f", "/var/service/" + appName},
			hint:    "sv status " + appName,
		}, nil

	case initBSDRC:
		return &serviceUnit{
			kind: kind,
			path: "/usr/local/etc/rc.d/" + appName,
			mode: 0o755,
			content: fmt.Sprintf(`#!/bin/sh
#
# PROVIDE: %[1]s
# REQUIRE: NETWORKING DAEMON
# KEYWORD: shutdown
#
# Enable autostart: sysrc %[1]s_enable=YES

. /etc/rc.subr

name="%[1]s"
rcvar="%[1]s_enable"

load_rc_config $name
: ${%[1]s_enable:="NO"}
: ${%[1]s_config:="%[3]s"}
: ${%[1]s_user:="%[4]s"}

pidfile="/var/run/${name}.pid"
procname="%[2]s"
command="/usr/sbin/daemon"
command_args="-P ${pidfile} -r -f -u ${%[1]s_user} %[2]s run -config ${%[1]s_config}"

extra_commands="reload"
reload_cmd="%[1]s_reload"

%[1]s_reload() {
    [ -f "$pidfile" ] && kill -HUP "$(cat $pidfile)"
}

run_rc_command "$1"
`, appName, exe, cfg, user),
			enable:  []string{"sysrc", appName + "_enable=YES"},
			disable: []string{"sysrc", appName + "_enable=NO"},
			hint:    "service " + appName + " start",
		}, nil

	case initLaunchd:
		plistDir := "/Library/LaunchDaemons"
		if !isRootUser() {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			plistDir = filepath.Join(home, "Library", "LaunchAgents")
		}
		label := "local." + appName
		plistPath := filepath.Join(plistDir, label+".plist")
		return &serviceUnit{
			kind: kind,
			path: plistPath,
			mode: 0o644,
			content: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>%[1]s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%[2]s</string>
    <string>run</string>
    <string>-config</string>
    <string>%[3]s</string>
  </array>
  <key>WorkingDirectory</key> <string>%[4]s</string>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>        <true/>
  <key>StandardOutPath</key>  <string>%[4]s/logs/launchd.out.log</string>
  <key>StandardErrorPath</key><string>%[4]s/logs/launchd.err.log</string>
</dict>
</plist>
`, label, exe, cfg, dataDir),
			enable:  []string{"launchctl", "load", "-w", plistPath},
			disable: []string{"launchctl", "unload", "-w", plistPath},
			hint:    "launchctl list | grep " + label,
		}, nil

	case initSchtasks:
		// A real Windows service must answer the Service Control Manager
		// (StartServiceCtrlDispatcher), and those calls exist only in
		// Windows-specific syscall code, which needs a second file with a
		// "go:build windows" constraint and cannot live in this single file.
		// So autostart is the Task Scheduler's job here: it starts at
		// boot, survives user logoff and runs as SYSTEM.
		return &serviceUnit{
			kind: kind,
			enable: []string{
				"schtasks", "/create", "/f",
				"/tn", appName,
				"/sc", "onstart",
				"/ru", "SYSTEM",
				"/rl", "HIGHEST",
				"/tr", fmt.Sprintf(`"%s" run -config "%s"`, exe, cfg),
			},
			disable: []string{"schtasks", "/delete", "/f", "/tn", appName},
			hint:    "schtasks /query /tn " + appName,
		}, nil
	}
	return nil, fmt.Errorf("unknown init system: %s", kind)
}

func installService(u *serviceUnit) error {
	if u.path != "" {
		if err := os.MkdirAll(filepath.Dir(u.path), 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", filepath.Dir(u.path), err)
		}
		if err := os.WriteFile(u.path, []byte(u.content), u.mode); err != nil {
			return fmt.Errorf("writing %s: %w (administrator privileges required)", u.path, err)
		}
		fmt.Printf("service file written: %s\n", u.path)
	}
	if len(u.enable) > 0 {
		if err := runServiceCmd(u.enable); err != nil {
			return err
		}
	}
	// systemd enables autostart after daemon-reload.
	if u.kind == initSystemd {
		if err := runServiceCmd([]string{"systemctl", "enable", "--now", appName}); err != nil {
			return err
		}
	}
	fmt.Printf("\nautostart enabled (%s)\ncheck: %s\n", u.kind, u.hint)
	return nil
}

func uninstallService(u *serviceUnit) error {
	if len(u.disable) > 0 {
		if err := runServiceCmd(u.disable); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
	if u.path != "" {
		if err := os.Remove(u.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", u.path, err)
		}
		fmt.Printf("service file removed: %s\n", u.path)
	}
	if u.kind == initSystemd {
		_ = runServiceCmd([]string{"systemctl", "daemon-reload"})
	}
	fmt.Printf("autostart disabled (%s)\n", u.kind)
	return nil
}

func runServiceCmd(argv []string) error {
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("command %s not found: run manually: %s", argv[0], strings.Join(argv, " "))
	}
	cmd := exec.Command(bin, argv[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return nil
}

const demoIndexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Site is live — webhost</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       font:16px/1.65 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       background:radial-gradient(1200px 600px at 50% -10%,#1e3a8a33,transparent),#0b1020;color:#e5e7eb}
  .card{max-width:760px;padding:40px;background:#111827cc;border:1px solid #1f2937;border-radius:16px;
        box-shadow:0 20px 60px #0008;backdrop-filter:blur(6px)}
  h1{margin:0 0 8px;font-size:28px}
  .badge{display:inline-block;padding:4px 10px;border-radius:999px;background:#065f46;color:#6ee7b7;font-size:12px;letter-spacing:.04em}
  p{color:#cbd5e1}
  code{background:#1f2937;padding:2px 7px;border-radius:6px;font-size:13px}
  ul{padding-left:18px;color:#cbd5e1}
  li{margin:6px 0}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:24px}
  .tile{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:14px}
  .tile b{display:block;color:#93c5fd;font-size:13px;margin-bottom:4px}
  .tile span{font-size:13px;color:#94a3b8}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">SERVER RUNNING</span>
    <h1>Hosting is ready</h1>
    <p>This page is served by <b>webhost</b> from the release directory. Replace it with your site:</p>
    <ul>
      <li>deploy a directory: <code>webhost deploy default ./dist</code></li>
      <li>roll back a release: <code>webhost rollback default</code></li>
      <li>reload config: <code>webhost reload</code></li>
      <li>status: <code>webhost status</code></li>
    </ul>
    <div class="grid">
      <div class="tile"><b>TLS</b><span>Local CA + Let's Encrypt (ACME http-01)</span></div>
      <div class="tile"><b>Site types</b><span>static · SPA · reverse proxy · PHP-FPM · redirect</span></div>
      <div class="tile"><b>Security</b><span>rate limit · ACL · basic-auth · security headers</span></div>
      <div class="tile"><b>Observability</b><span>Prometheus /metrics · access logs · admin panel</span></div>
    </div>
  </div>
</body>
</html>
`

const demo404HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>404 — page not found</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font:16px/1.6 system-ui,sans-serif;background:#0b1020;color:#e5e7eb}
h1{font-size:72px;margin:0;color:#60a5fa}p{color:#94a3b8}.c{text-align:center}</style></head>
<body><div class="c"><h1>404</h1><p>This page does not exist</p></div></body></html>
`

// ============================================================================
// Network basics for a bare system: root CAs and DNS
//
// A freshly installed system (minimal image, Alpine without ca-certificates,
// FROM scratch, a fresh BSD) may lack two things without which
// outbound HTTPS is impossible:
//
//   - the root certificate store (/etc/ssl/certs, /etc/pki/...);
//   - /etc/resolv.conf, i.e. DNS server addresses.
//
// Without the first, ACME (Let's Encrypt), proxying to https upstreams
// and sending mail over TLS do not work. Without the second, no name resolves.
// ============================================================================

// bakedRoots is a set of root certificates baked into the binary at build
// time: base64(gzip(PEM)). It is set by the linker; the build subcommand does it
// automatically, taking the bundle from the build machine:
//
//	go build -ldflags "-X main.bakedRoots=<base64>" main.go
//
// The certificates come from a real machine, not from the source code: a list
// hard-coded in the source would go stale, and stale roots mean failed or
// weakened authentication, which is worse than having no bundle at all.
var bakedRoots string

var (
	rootPoolOnce sync.Once
	rootPoolVal  *x509.CertPool
	rootPoolFrom string
	rootPoolErr  error
)

// extraRootsPath is where a user can put their own bundle
// (webhost roots -import FILE). Set when the config is loaded.
var extraRootsPath atomic.Value // string

// rootPool returns the roots for all outbound TLS: the system store when it
// has one, otherwise the roots baked in by the linker or found on disk.
// Roots imported with "webhost roots -import" are added in both cases.
func rootPool() (*x509.CertPool, string, error) {
	rootPoolOnce.Do(func() {
		if p, err := x509.SystemCertPool(); err == nil && p != nil && (len(p.Subjects()) > 0 || platformRootStore()) {
			from := "system"
			if extra, _ := extraRootsPath.Load().(string); extra != "" {
				if b, err := os.ReadFile(extra); err == nil && p.AppendCertsFromPEM(b) {
					from += ", " + extra
				}
			}
			rootPoolVal, rootPoolFrom = p, from
			return
		}
		pool := x509.NewCertPool()
		var sources []string

		if bakedRoots != "" {
			pem, err := decodeBakedRoots(bakedRoots)
			if err == nil && pool.AppendCertsFromPEM(pem) {
				sources = append(sources, "baked in at build time")
			}
		}
		if p, _ := extraRootsPath.Load().(string); p != "" {
			if b, err := os.ReadFile(p); err == nil && pool.AppendCertsFromPEM(b) {
				sources = append(sources, p)
			}
		}
		for _, p := range []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/cert.pem",
			"/usr/local/etc/ssl/cert.pem",
			"/etc/ssl/ca-bundle.pem",
		} {
			b, err := os.ReadFile(p)
			if err == nil && pool.AppendCertsFromPEM(b) {
				sources = append(sources, p)
				break
			}
		}
		if len(pool.Subjects()) == 0 {
			rootPoolErr = errors.New("no trusted root certificates: " +
				"place a bundle with \"webhost roots -import FILE.pem\" " +
				"or build the binary with the \"build\" subcommand on a machine that has certificates")
			return
		}
		rootPoolVal, rootPoolFrom = pool, strings.Join(sources, ", ")
	})
	return rootPoolVal, rootPoolFrom, rootPoolErr
}

// platformRootStore: on these systems Go verifies through the OS store, and a
// SystemCertPool lists no Subjects although it works. Treating it as empty
// threw the OS store away (Windows ended up with no roots at all).
func platformRootStore() bool {
	switch runtime.GOOS {
	case "windows", "darwin", "ios":
		return true
	}
	return false
}

// describeRoots is a human-readable summary of rootPool's result.
func describeRoots(pool *x509.CertPool, from string) string {
	n := len(pool.Subjects()) // only the certificates that Go itself holds
	if strings.HasPrefix(from, "system") && platformRootStore() {
		if n > 0 {
			return fmt.Sprintf("OS certificate store + %d imported (%s)", n, from)
		}
		return "OS certificate store"
	}
	return fmt.Sprintf("%d (%s)", n, from)
}

func decodeBakedRoots(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(io.LimitReader(gz, 8<<20))
}

// encodeBakedRoots is the reverse operation, used by the build subcommand.
func encodeBakedRoots(pemBytes []byte) (string, error) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(pemBytes); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// publicResolvers are the servers used to resolve names when the system
// has no /etc/resolv.conf. Cloudflare, Google and Quad9, two addresses each.
var publicResolvers = []string{
	"1.1.1.1:53", "1.0.0.1:53",
	"8.8.8.8:53", "8.8.4.4:53",
	"9.9.9.9:53", "149.112.112.112:53",
}

// systemHasResolvConf reports whether the OS can resolve names by itself.
func systemHasResolvConf() bool {
	if runtime.GOOS == "windows" {
		return true // the resolver is configured through the API; there is no such file
	}
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "nameserver" {
			return true
		}
	}
	return false
}

// fallbackResolver is a resolver that queries public DNS servers.
// Parsing the answers is left to the standard library (PreferGo); only the
// transport is replaced: a DNS parser here would be extra code and extra bugs.
func fallbackResolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		servers = publicResolvers
	}
	var seq uint32
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			// Every attempt starts with a different server, so one provider being
			// down does not turn into a timeout on every lookup.
			start := int(atomic.AddUint32(&seq, 1))
			var lastErr error
			for i := 0; i < len(servers); i++ {
				addr := servers[(start+i)%len(servers)]
				net2 := network
				if net2 == "tcp" || net2 == "tcp4" || net2 == "tcp6" {
					net2 = "tcp"
				} else {
					net2 = "udp"
				}
				c, err := d.DialContext(ctx, net2, addr)
				if err == nil {
					return c, nil
				}
				lastErr = err
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
			return nil, lastErr
		},
	}
}

// installFallbackResolver replaces the default resolver if the system
// has nothing configured. Called once at server start.
func installFallbackResolver(servers []string, lg *Logger) {
	if systemHasResolvConf() {
		return
	}
	net.DefaultResolver = fallbackResolver(servers)
	list := servers
	if len(list) == 0 {
		list = publicResolvers
	}
	if lg != nil {
		lg.Warnf("no /etc/resolv.conf on system — using custom resolver: %s", strings.Join(list, " "))
	}
}

// outboundTLSConfig is the TLS configuration for all outbound connections
// (ACME, https upstreams, SMTP, Go toolchain download).
func outboundTLSConfig(serverName string) (*tls.Config, error) {
	pool, _, err := rootPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// newOutboundClient returns an http.Client for outbound requests: with our
// root pool, our resolver and reasonable timeouts.
func newOutboundClient(timeout time.Duration) (*http.Client, error) {
	tlsCfg, err := outboundTLSConfig("")
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !systemHasResolvConf() {
		dialer.Resolver = fallbackResolver(nil)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Honor HTTPS_PROXY & co. like the default client did (ACME now
			// goes through this client too).
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       tlsCfg,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          32,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
		},
	}, nil
}

// ============================================================================
// Scheduler
//
// Cron inside the process: no external daemon is needed, jobs survive reloads and
// are described in the same config.json. The classic five-field syntax
// and shorthands are supported:
//
//	*/5 * * * *     every five minutes
//	0 4 * * *       at 4:00 every day
//	0 3 * * sun     on Sundays at 3:00
//	0 0 1 */3 *     once a quarter
//	@daily @hourly @weekly @monthly @yearly @reboot
//	@every 90s      at a fixed interval
// ============================================================================

// cronSchedule is a parsed schedule. The fields are stored as bitmasks:
// checking for a match is one shift and one AND.
type cronSchedule struct {
	minutes uint64 // bits 0..59
	hours   uint64 // bits 0..23
	dom     uint64 // bits 1..31
	months  uint64 // bits 1..12
	dow     uint64 // bits 0..6, Sunday = 0

	// In cron, day of month and day of week are combined with OR, but only if
	// both are explicit. If one of them is "*", only the other one applies.
	domStar bool
	dowStar bool

	every  time.Duration // for @every; zero for a normal schedule
	reboot bool          // for @reboot: one run at startup
}

func parseCronSpec(expr string) (*cronSchedule, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, errors.New("empty schedule")
	}
	if strings.HasPrefix(expr, "@") {
		return parseCronShorthand(expr)
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("expected 5 fields (minute hour day month weekday), got %d: %q", len(fields), expr)
	}
	s := &cronSchedule{}
	var err error
	if s.minutes, _, err = parseCronField(fields[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("minute field: %w", err)
	}
	if s.hours, _, err = parseCronField(fields[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("hour field: %w", err)
	}
	if s.dom, s.domStar, err = parseCronField(fields[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("day-of-month field: %w", err)
	}
	if s.months, _, err = parseCronField(fields[3], 1, 12, cronMonthNames); err != nil {
		return nil, fmt.Errorf("month field: %w", err)
	}
	if s.dow, s.dowStar, err = parseCronField(fields[4], 0, 7, cronDayNames); err != nil {
		return nil, fmt.Errorf("day-of-week field: %w", err)
	}
	// 7 and 0 are both Sundays.
	if s.dow&(1<<7) != 0 {
		s.dow |= 1
		s.dow &^= 1 << 7
	}
	return s, nil
}

func parseCronShorthand(expr string) (*cronSchedule, error) {
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "@every") {
		d, err := time.ParseDuration(strings.TrimSpace(strings.TrimPrefix(lower, "@every")))
		if err != nil {
			return nil, fmt.Errorf("@every: %w", err)
		}
		if d < time.Second {
			return nil, errors.New("@every: interval shorter than one second")
		}
		return &cronSchedule{every: d}, nil
	}
	switch lower {
	case "@reboot":
		return &cronSchedule{reboot: true}, nil
	case "@yearly", "@annually":
		return parseCronSpec("0 0 1 1 *")
	case "@monthly":
		return parseCronSpec("0 0 1 * *")
	case "@weekly":
		return parseCronSpec("0 0 * * 0")
	case "@daily", "@midnight":
		return parseCronSpec("0 0 * * *")
	case "@hourly":
		return parseCronSpec("0 * * * *")
	}
	return nil, fmt.Errorf("unknown shorthand: %s", expr)
}

var cronMonthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

var cronDayNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

// parseCronField parses a single field. It returns the mask and whether the
// field was "*", which the day-of-month/day-of-week rule needs.
func parseCronField(field string, min, max int, names map[string]int) (uint64, bool, error) {
	var mask uint64
	isStar := field == "*" || strings.HasPrefix(field, "*/")

	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return 0, false, errors.New("empty list element")
		}
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			var err error
			step, err = strconv.Atoi(part[i+1:])
			if err != nil || step < 1 {
				return 0, false, fmt.Errorf("invalid step in %q", part)
			}
			part = part[:i]
		}
		lo, hi := min, max
		if part != "*" {
			bounds := strings.SplitN(part, "-", 2)
			var err error
			if lo, err = cronValue(bounds[0], min, max, names); err != nil {
				return 0, false, err
			}
			if len(bounds) == 2 {
				if hi, err = cronValue(bounds[1], min, max, names); err != nil {
					return 0, false, err
				}
			} else if step == 1 {
				hi = lo
			}
		}
		if lo > hi {
			return 0, false, fmt.Errorf("reversed bounds: %d-%d", lo, hi)
		}
		for v := lo; v <= hi; v += step {
			mask |= 1 << uint(v)
		}
	}
	if mask == 0 {
		return 0, false, fmt.Errorf("field %q matches no values", field)
	}
	return mask, isStar, nil
}

func cronValue(s string, min, max int, names map[string]int) (int, error) {
	s = strings.TrimSpace(s)
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a number or name: %q", s)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("value %d out of range %d-%d", v, min, max)
	}
	return v, nil
}

// next returns the nearest run time strictly after from.
// It steps through days, and within a day through the hour and minute masks, so
// even "once a year" takes dozens of iterations, not a million.
func (c *cronSchedule) next(from time.Time) time.Time {
	if c.reboot {
		return time.Time{} // @reboot has no schedule
	}
	if c.every > 0 {
		return from.Add(c.every)
	}
	// Start with the next minute, zero seconds.
	t := from.Truncate(time.Minute).Add(time.Minute)

	// Limit of five years: protects against schedules like "30 February".
	limit := from.AddDate(5, 0, 0)
	for t.Before(limit) {
		if c.months&(1<<uint(int(t.Month()))) == 0 {
			// The month does not match: jump to the first day of the next one.
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location()).AddDate(0, 1, 0)
			continue
		}
		if !c.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
			continue
		}
		if c.hours&(1<<uint(t.Hour())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Add(time.Hour)
			continue
		}
		if c.minutes&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// dayMatches implements the cron rule for the day of the month and the day of the week.
func (c *cronSchedule) dayMatches(t time.Time) bool {
	domOK := c.dom&(1<<uint(t.Day())) != 0
	dowOK := c.dow&(1<<uint(int(t.Weekday()))) != 0
	switch {
	case c.domStar && c.dowStar:
		return true
	case c.domStar:
		return dowOK
	case c.dowStar:
		return domOK
	default:
		// Both are set explicitly: either one matches.
		return domOK || dowOK
	}
}

// cronJob is a job together with its run state.
type cronJob struct {
	cfg   CronJobConfig
	sched *cronSchedule

	mu       sync.Mutex
	next     time.Time
	lastRun  time.Time
	lastTook time.Duration
	lastErr  string
	runs     int64
	fails    int64
	running  bool
}

func (j *cronJob) snapshot() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	m := map[string]interface{}{
		"name":    j.cfg.Name,
		"spec":    j.cfg.Spec,
		"runs":    j.runs,
		"fails":   j.fails,
		"running": j.running,
	}
	if j.cfg.Task != "" {
		m["task"] = j.cfg.Task
	} else {
		m["command"] = j.cfg.Command
	}
	if !j.next.IsZero() {
		m["next"] = j.next.Format(time.RFC3339)
	}
	if !j.lastRun.IsZero() {
		m["last_run"] = j.lastRun.Format(time.RFC3339)
		m["last_took_ms"] = j.lastTook.Milliseconds()
	}
	if j.lastErr != "" {
		m["last_error"] = j.lastErr
	}
	return m
}

// scheduler runs the jobs.
type scheduler struct {
	srv  *Server
	lg   *Logger
	mu   sync.RWMutex
	jobs []*cronJob
	// wake interrupts run's sleep after load replaced the jobs: otherwise it
	// slept until the old nearest job, ignoring new and changed schedules.
	wake chan struct{}
}

func newScheduler(srv *Server) *scheduler {
	return &scheduler{srv: srv, lg: srv.log, wake: make(chan struct{}, 1)}
}

// isCurrent reports whether j still belongs to the loaded job list.
func (sc *scheduler) isCurrent(j *cronJob) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	for _, x := range sc.jobs {
		if x == j {
			return true
		}
	}
	return false
}

// load reads the jobs from the config. An invalid schedule is no reason
// to refuse to start the server: it is reported and the job is skipped.
func (sc *scheduler) load(cfg *Config) {
	var jobs []*cronJob
	now := time.Now()
	for i := range cfg.Cron {
		jc := cfg.Cron[i]
		if jc.Enabled != nil && !*jc.Enabled {
			continue
		}
		if jc.Name == "" {
			jc.Name = fmt.Sprintf("job-%d", i+1)
		}
		if jc.Task == "" && jc.Command == "" {
			sc.lg.Errorf("cron %s: neither task nor command set — skipped", jc.Name)
			continue
		}
		if jc.Task != "" && jc.Command != "" {
			sc.lg.Errorf("cron %s: task and command both set — skipped", jc.Name)
			continue
		}
		if jc.Task != "" && sc.builtinTask(jc.Task) == nil {
			sc.lg.Errorf("cron %s: unknown built-in task %q — skipped", jc.Name, jc.Task)
			continue
		}
		sch, err := parseCronSpec(jc.Spec)
		if err != nil {
			sc.lg.Errorf("cron %s: schedule %q: %v — skipped", jc.Name, jc.Spec, err)
			continue
		}
		j := &cronJob{cfg: jc, sched: sch}
		if !sch.reboot {
			j.next = sch.next(now)
		}
		jobs = append(jobs, j)
	}
	// Scheduled backups can be switched on with one flag, without writing the job by hand.
	// If a job with task=backup already exists in the config, it takes precedence.
	if cfg.Backup.Enabled {
		explicit := false
		for _, j := range jobs {
			if j.cfg.Task == "backup" {
				explicit = true
				break
			}
		}
		if !explicit {
			spec := cfg.Backup.Spec
			if spec == "" {
				spec = "@daily"
			}
			if sch, err := parseCronSpec(spec); err != nil {
				sc.lg.Errorf("backup: schedule %q: %v — scheduled backups disabled", spec, err)
			} else {
				j := &cronJob{cfg: CronJobConfig{Name: "backup", Spec: spec, Task: "backup"}, sched: sch}
				if !sch.reboot {
					j.next = sch.next(now)
				}
				jobs = append(jobs, j)
			}
		}
	}

	sc.mu.Lock()
	sc.jobs = jobs
	sc.mu.Unlock()
	select {
	case sc.wake <- struct{}{}:
	default: // a wake-up is already pending
	}
	if len(jobs) > 0 {
		sc.lg.Infof("scheduler: %d job(s)", len(jobs))
	}
}

// run is the main loop. It sleeps until the next job instead of polling,
// so with an empty schedule the process does nothing at all.
func (sc *scheduler) run(ctx context.Context) {
	// @reboot: right after startup.
	sc.mu.RLock()
	boot := make([]*cronJob, 0, 2)
	for _, j := range sc.jobs {
		if j.sched.reboot {
			boot = append(boot, j)
		}
	}
	sc.mu.RUnlock()
	for _, j := range boot {
		go sc.execute(ctx, j)
	}

	for {
		wait, job := sc.nearest()
		if job == nil {
			// No scheduled jobs: just wait for cancellation or a reload.
			select {
			case <-ctx.Done():
				return
			case <-sc.wake:
				continue
			case <-time.After(time.Minute):
				continue
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-sc.wake:
			// Jobs were reloaded: recompute the nearest one.
			timer.Stop()
			continue
		case <-timer.C:
		}
		if !sc.isCurrent(job) {
			continue // replaced by a reload while we slept
		}
		job.mu.Lock()
		job.next = job.sched.next(time.Now())
		job.mu.Unlock()
		go sc.execute(ctx, job)
	}
}

// nearest picks the job with the nearest run time.
func (sc *scheduler) nearest() (time.Duration, *cronJob) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	var best *cronJob
	var bestAt time.Time
	for _, j := range sc.jobs {
		j.mu.Lock()
		next := j.next
		j.mu.Unlock()
		if next.IsZero() {
			continue
		}
		if best == nil || next.Before(bestAt) {
			best, bestAt = j, next
		}
	}
	if best == nil {
		return 0, nil
	}
	wait := time.Until(bestAt)
	if wait < 0 {
		wait = 0
	}
	return wait, best
}

// execute runs the job without letting runs overlap.
func (sc *scheduler) execute(ctx context.Context, j *cronJob) {
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		sc.lg.Warnf("cron %s: previous run still in progress — skipping", j.cfg.Name)
		return
	}
	j.running = true
	j.lastRun = time.Now()
	j.mu.Unlock()

	start := time.Now()
	runCtx := ctx
	var cancel context.CancelFunc
	if j.cfg.TimeoutSec > 0 {
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(j.cfg.TimeoutSec)*time.Second)
		defer cancel()
	}

	var err error
	if j.cfg.Task != "" {
		if fn := sc.builtinTask(j.cfg.Task); fn != nil {
			err = fn(runCtx)
		} else {
			err = fmt.Errorf("unknown task %q", j.cfg.Task)
		}
	} else {
		err = sc.runCommand(runCtx, j.cfg)
	}

	took := time.Since(start)
	j.mu.Lock()
	j.running = false
	j.runs++
	j.lastTook = took
	if err != nil {
		j.fails++
		j.lastErr = err.Error()
	} else {
		j.lastErr = ""
	}
	j.mu.Unlock()

	if err != nil {
		sc.lg.Errorf("cron %s: %v (took %s)", j.cfg.Name, err, took.Round(time.Millisecond))
	} else {
		sc.lg.Infof("cron %s: completed in %s", j.cfg.Name, took.Round(time.Millisecond))
	}
}

func (sc *scheduler) runCommand(ctx context.Context, jc CronJobConfig) error {
	cmd := exec.CommandContext(ctx, jc.Command, jc.Args...)
	if jc.Dir != "" {
		cmd.Dir = jc.Dir
	}
	// A child that inherits stdout (sh -c "worker &") kept Wait blocked long
	// after timeout_sec killed the command itself, and every later run was
	// skipped as "still in progress". WaitDelay closes the pipes instead.
	cmd.WaitDelay = 5 * time.Second
	// Output is only logged (first 8 KiB): do not hold all of it in memory.
	out := &cappedBuffer{limit: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	if s := strings.TrimSpace(out.String()); s != "" {
		// The job's output matters for troubleshooting: it goes into the log in full,
		// up to a reasonable size.
		if len(s) > 8<<10 {
			s = s[:8<<10] + "… (truncated)"
		}
		sc.lg.Infof("cron %s output: %s", jc.Name, s)
	}
	return err
}

// cappedBuffer keeps the first limit bytes written and discards the rest.
type cappedBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// builtinTask returns the handler of a built-in task, or nil.
func (sc *scheduler) builtinTask(name string) func(context.Context) error {
	s := sc.srv
	switch name {
	case "backup":
		return func(context.Context) error {
			path, err := s.makeBackup()
			if err != nil {
				return err
			}
			sc.lg.Infof("backup: %s", path)
			return nil
		}
	case "db-compact":
		return func(context.Context) error { return s.db.Compact() }
	case "mail-flush":
		return func(ctx context.Context) error {
			if s.mail == nil {
				return errors.New("mail is not configured")
			}
			return s.mail.flush(ctx)
		}
	case "cert-renew":
		return func(context.Context) error {
			domains := s.acmeDomains()
			if len(domains) == 0 {
				return nil
			}
			for _, d := range domains {
				s.certs.ensureACME(d)
			}
			return nil
		}
	case "log-rotate":
		return func(context.Context) error {
			for _, c := range s.closers {
				if rw, ok := c.(*rotatingWriter); ok {
					rw.Rotate()
				}
			}
			return nil
		}
	case "prune-releases":
		return func(context.Context) error {
			cfg := s.getConfig()
			for _, site := range cfg.Sites {
				// Only release trees webhost itself manages. An empty root used to
				// resolve to the working directory (filepath.Abs("")), and any
				// "releases" folder next to a plain site root got pruned too.
				if site.Root == "" || !site.Deploy.Enabled {
					continue
				}
				root, err := filepath.Abs(site.Root)
				if err != nil || !releasesManaged(root) {
					continue
				}
				keep := site.Deploy.KeepReleases
				if keep <= 0 {
					keep = 5
				}
				pruneReleases(releasesDir(root), keep)
			}
			return nil
		}
	}
	return nil
}

// jobsSnapshot is the job status for the Admin API.
func (sc *scheduler) jobsSnapshot() []map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	out := make([]map[string]interface{}, 0, len(sc.jobs))
	for _, j := range sc.jobs {
		out = append(out, j.snapshot())
	}
	return out
}

// runNow runs a job by name immediately, outside its schedule.
func (sc *scheduler) runNow(ctx context.Context, name string) error {
	sc.mu.RLock()
	var found *cronJob
	for _, j := range sc.jobs {
		if j.cfg.Name == name {
			found = j
			break
		}
	}
	sc.mu.RUnlock()
	if found == nil {
		return fmt.Errorf("job not found: %s", name)
	}
	go sc.execute(ctx, found)
	return nil
}

// ============================================================================
// Outgoing mail
//
// A message is not sent "during the request": it is put into a queue in the
// embedded database and stays there until delivery is confirmed. If the SMTP
// relay is down, the network drops or the server restarts, the message is not lost.
//
// Two routes: through a relay (host:port + login) or directly to the MX of the
// recipient's domain. A DKIM signature (rsa-sha256, relaxed/relaxed) is added if
// a private key is configured; without it, mail almost certainly ends up in spam.
// ============================================================================

const mailColl = "mail_queue"

// outgoingMail is a queued message, stored in the database as a regular document.
type outgoingMail struct {
	ID        string            `json:"id"`
	From      string            `json:"from"`
	To        []string          `json:"to"`
	Subject   string            `json:"subject"`
	Text      string            `json:"text,omitempty"`
	HTML      string            `json:"html,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	NextTry   time.Time         `json:"next_try"`
	Attempts  int               `json:"attempts"`
	LastError string            `json:"last_error,omitempty"`
	// Delivered: domains the message has already been delivered to. Retries
	// skip them, otherwise some recipients would get duplicates.
	Delivered []string `json:"delivered,omitempty"`
	// State: queued | failed.
	State string `json:"state"`
}

// mailer keeps the outgoing queue and delivers it.
type mailer struct {
	srv *Server
	lg  *Logger

	mu  sync.RWMutex
	cfg MailConfig
	key *rsa.PrivateKey

	busy int32 // flush must not run concurrently with itself
}

func newMailer(srv *Server) *mailer {
	m := &mailer{srv: srv, lg: srv.log}
	m.reload(srv.cfg)
	return m
}

// reload applies the settings and fills in defaults.
func (m *mailer) reload(cfg *Config) {
	mc := cfg.Mail
	if mc.StartTLS == "" {
		mc.StartTLS = "auto"
	}
	mc.StartTLS = strings.ToLower(mc.StartTLS)
	if mc.TimeoutSec <= 0 {
		mc.TimeoutSec = 30
	}
	if mc.MaxRetries <= 0 {
		mc.MaxRetries = 8
	}
	if mc.RetrySec <= 0 {
		mc.RetrySec = 60
	}
	if mc.HELO == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			mc.HELO = h
		} else {
			mc.HELO = "localhost"
		}
	}

	var key *rsa.PrivateKey
	if mc.DKIMKeyFile != "" {
		k, err := loadRSAKey(mc.DKIMKeyFile)
		if err != nil {
			m.lg.Errorf("dkim: key %s: %v — signing disabled", mc.DKIMKeyFile, err)
		} else {
			key = k
		}
	}

	m.mu.Lock()
	m.cfg = mc
	m.key = key
	m.mu.Unlock()
}

func (m *mailer) config() MailConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *mailer) dkimKey() *rsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.key
}

// start launches background delivery of the queue.
func (m *mailer) start(ctx context.Context, cfg *Config) {
	m.reload(cfg)
	if !cfg.Mail.Enabled {
		return
	}
	mc := m.config()
	route := "direct to recipient MX"
	if mc.Relay != "" {
		route = "via relay " + mc.Relay
	}
	dkim := "without DKIM"
	if m.dkimKey() != nil {
		dkim = fmt.Sprintf("DKIM %s._domainkey.%s", mc.DKIMSelector, mc.DKIMDomain)
	}
	m.lg.Infof("mail: %s, %s", route, dkim)
	if n := m.queueLen(); n > 0 {
		m.lg.Infof("mail: %d message(s) in queue", n)
	}
	go m.loop(ctx)
}

// The loop flushes the queue every 30 seconds. The separate cron task
// mail-flush does the same on a schedule or on demand.
func (m *mailer) loop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.flush(ctx); err != nil {
				m.lg.Debugf("mail: queue flush: %v", err)
			}
		}
	}
}

// Send queues the message and tries to deliver it right away.
// It returns the message's ID in the queue.
func (m *mailer) Send(ctx context.Context, msg outgoingMail) (string, error) {
	mc := m.config()
	if !mc.Enabled {
		return "", errors.New("mail is disabled in configuration")
	}
	if m.srv.db == nil {
		return "", errors.New("DB unavailable — nowhere to store the mail queue")
	}
	if msg.From == "" {
		msg.From = mc.From
	}
	if addrOnly(msg.From) == "" {
		return "", errors.New("sender address not set (mail.from)")
	}
	clean := make([]string, 0, len(msg.To))
	for _, to := range msg.To {
		if a := addrOnly(to); a != "" {
			clean = append(clean, a)
		}
	}
	if len(clean) == 0 {
		return "", errors.New("no valid recipients")
	}
	msg.To = clean
	if msg.Text == "" && msg.HTML == "" {
		return "", errors.New("message has no body")
	}
	now := time.Now()
	msg.CreatedAt = now
	msg.NextTry = now
	msg.Attempts = 0
	msg.State = "queued"

	id, err := m.srv.db.Put(mailColl, msg.ID, msg)
	if err != nil {
		return "", err
	}
	go func() {
		// Try at once; the message is already safely queued, so an error
		// only needs to be logged.
		if err := m.flush(context.Background()); err != nil {
			m.lg.Debugf("mail: immediate send: %v", err)
		}
	}()
	return id, nil
}

// flush tries to deliver everything that is due.
func (m *mailer) flush(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&m.busy, 0, 1) {
		return nil // already running
	}
	defer atomic.StoreInt32(&m.busy, 0)

	db := m.srv.db
	if db == nil {
		return errors.New("DB unavailable")
	}
	mc := m.config()
	now := time.Now()

	var pending []outgoingMail
	for _, res := range db.Find(mailColl, dbQuery{}) {
		var msg outgoingMail
		if err := json.Unmarshal(res.Doc, &msg); err != nil {
			continue
		}
		msg.ID = res.ID
		if msg.State == "failed" || msg.NextTry.After(now) {
			continue
		}
		pending = append(pending, msg)
	}
	if len(pending) == 0 {
		return nil
	}

	sent, failed := 0, 0
	var lastErr error
	for i := range pending {
		// The queue survives a shutdown, so when the context is cancelled
		// stop right away instead of delaying the shutdown for minutes.
		if err := ctx.Err(); err != nil {
			return err
		}
		msg := pending[i]
		err := m.deliver(ctx, &msg)
		if err == nil {
			if derr := db.Delete(mailColl, msg.ID); derr != nil {
				m.lg.Errorf("mail: message %s delivered but not removed from queue: %v", msg.ID, derr)
			}
			sent++
			m.lg.Infof("mail: delivered %s → %s", msg.Subject, strings.Join(msg.To, ", "))
			continue
		}

		failed++
		lastErr = err
		msg.Attempts++
		msg.LastError = err.Error()
		// Exponential backoff, capped at six hours: growing further makes no
		// sense, and a message should not be stuck for a day.
		wait := time.Duration(mc.RetrySec) * time.Second * (1 << minInt(msg.Attempts-1, 8))
		if wait > 6*time.Hour {
			wait = 6 * time.Hour
		}
		msg.NextTry = time.Now().Add(wait)
		if msg.Attempts >= mc.MaxRetries {
			msg.State = "failed"
			m.lg.Errorf("mail: message %s failed after %d attempts: %v", msg.ID, msg.Attempts, err)
		} else {
			m.lg.Warnf("mail: attempt %d for %s failed: %v — retry in %s",
				msg.Attempts, msg.ID, err, wait)
		}
		if _, perr := db.Put(mailColl, msg.ID, msg); perr != nil {
			m.lg.Errorf("mail: failed to update message %s in queue: %v", msg.ID, perr)
		}
	}
	if failed > 0 {
		return fmt.Errorf("delivered %d, failed %d: %w", sent, failed, lastErr)
	}
	return nil
}

// deliver builds the message and hands it to the relay or to the recipients' MX servers.
func (m *mailer) deliver(ctx context.Context, msg *outgoingMail) error {
	mc := m.config()
	data, err := m.buildMessage(msg)
	if err != nil {
		return fmt.Errorf("building message: %w", err)
	}
	envFrom := addrOnly(msg.From)

	if mc.Relay != "" {
		addr := mc.Relay
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "587")
		}
		return m.sendVia(ctx, addr, envFrom, msg.To, data, mc.User, mc.Password, false, false)
	}

	// Direct delivery: recipients are grouped by domain, one SMTP session
	// per domain instead of one per address.
	byDomain := map[string][]string{}
	for _, to := range msg.To {
		at := strings.LastIndex(to, "@")
		if at < 0 {
			continue
		}
		d := strings.ToLower(to[at+1:])
		byDomain[d] = append(byDomain[d], to)
	}
	done := map[string]bool{}
	for _, d := range msg.Delivered {
		done[d] = true
	}

	var firstErr error
	for domain, rcpts := range byDomain {
		if done[domain] {
			continue
		}
		hosts, err := m.mxHosts(ctx, domain)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var lastErr error
		ok := false
		for _, h := range hosts {
			if err := m.sendMX(ctx, net.JoinHostPort(h, "25"), envFrom, rcpts, data); err != nil {
				lastErr = err
				continue
			}
			ok = true
			break
		}
		if ok {
			msg.Delivered = append(msg.Delivered, domain)
		} else if firstErr == nil {
			firstErr = fmt.Errorf("%s: %v", domain, lastErr)
		}
	}
	return firstErr
}

// sendMX delivers to one MX host with opportunistic TLS (RFC 7435): with
// starttls "auto" a server whose TLS is broken still gets the message, over
// a new plain connection, as it would from any other MTA.
func (m *mailer) sendMX(ctx context.Context, addr, from string, to []string, data []byte) error {
	err := m.sendVia(ctx, addr, from, to, data, "", "", true, false)
	var tlsErr *starttlsError
	if errors.As(err, &tlsErr) && m.config().StartTLS == "auto" {
		m.lg.Warnf("mail: %v — retrying %s without TLS", err, addr)
		err = m.sendVia(ctx, addr, from, to, data, "", "", true, true)
	}
	return err
}

// starttlsError: the STARTTLS handshake failed; the connection is unusable.
type starttlsError struct {
	addr string
	err  error
}

func (e *starttlsError) Error() string { return fmt.Sprintf("starttls with %s: %v", e.addr, e.err) }
func (e *starttlsError) Unwrap() error { return e.err }

// sendVia conducts one SMTP session. mx: direct delivery to a recipient's
// MX, where starttls "auto" encrypts without verifying the certificate —
// MX certificates rarely match their host names, and verification without
// a way to insist on TLS protects nothing (the relay keeps verifying, as
// the password travels there). plain: do not use STARTTLS at all.
func (m *mailer) sendVia(ctx context.Context, addr, from string, to []string, data []byte, user, pass string, mx, plain bool) error {
	mc := m.config()
	timeout := time.Duration(mc.TimeoutSec) * time.Second

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	// One deadline for the whole session: a hung server must not hold
	// a goroutine forever.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	host, _, _ := net.SplitHostPort(addr)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("greeting %s: %w", addr, err)
	}
	defer c.Close()

	if err := c.Hello(mc.HELO); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}

	tlsUsed := false
	if mc.StartTLS != "never" && !plain {
		if ok, _ := c.Extension("STARTTLS"); ok {
			tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12,
				InsecureSkipVerify: mc.InsecureSkipVerify || (mx && mc.StartTLS == "auto")}
			if pool, _, perr := rootPool(); perr == nil {
				tc.RootCAs = pool
			}
			if err := c.StartTLS(tc); err != nil {
				// The connection is in an unknown state after a failed
				// STARTTLS and cannot be used any further.
				return &starttlsError{addr: addr, err: err}
			}
			tlsUsed = true
		} else if mc.StartTLS == "always" {
			return fmt.Errorf("%s does not support STARTTLS, but always is required", addr)
		}
	}

	if user != "" {
		ok, mechs := c.Extension("AUTH")
		switch {
		case !ok:
			return fmt.Errorf("%s does not offer AUTH", addr)
		case tlsUsed && strings.Contains(mechs, "PLAIN"):
			if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
				return fmt.Errorf("auth plain: %w", err)
			}
		case strings.Contains(mechs, "CRAM-MD5"):
			if err := c.Auth(smtp.CRAMMD5Auth(user, pass)); err != nil {
				return fmt.Errorf("auth cram-md5: %w", err)
			}
		default:
			return errors.New("relay only accepts plaintext passwords: enable starttls or CRAM-MD5")
		}
	}

	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM %s: %w", from, err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return fmt.Errorf("sending body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finishing DATA: %w", err)
	}
	return c.Quit()
}

// mxHosts returns the domain's mail servers in order of preference. Without
// MX records, RFC 5321 says to deliver to the domain's own A/AAAA.
func (m *mailer) mxHosts(ctx context.Context, domain string) ([]string, error) {
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err == nil && len(mxs) > 0 {
		sort.SliceStable(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
		hosts := make([]string, 0, len(mxs))
		for _, mx := range mxs {
			if h := strings.TrimSuffix(mx.Host, "."); h != "" {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) > 0 {
			return hosts, nil
		}
	}
	if _, aerr := net.DefaultResolver.LookupHost(ctx, domain); aerr != nil {
		if err == nil {
			err = aerr
		}
		return nil, fmt.Errorf("no MX or A for %s: %v", domain, err)
	}
	return []string{domain}, nil
}

// buildMessage assembles an RFC 5322 message: headers, MIME parts, DKIM.
func (m *mailer) buildMessage(msg *outgoingMail) ([]byte, error) {
	mc := m.config()
	domain := mc.DKIMDomain
	if domain == "" {
		if at := strings.LastIndex(addrOnly(msg.From), "@"); at >= 0 {
			domain = addrOnly(msg.From)[at+1:]
		} else {
			domain = "localhost"
		}
	}

	var body []byte
	contentType := ""
	switch {
	case msg.HTML != "" && msg.Text != "":
		boundary := "wh-" + randomID()
		contentType = `multipart/alternative; boundary="` + boundary + `"`
		var b bytes.Buffer
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(base64Lines(msg.Text))
		b.WriteString("\r\n--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(base64Lines(msg.HTML))
		b.WriteString("\r\n--" + boundary + "--\r\n")
		body = b.Bytes()
	case msg.HTML != "":
		contentType = "text/html; charset=utf-8"
		body = []byte(base64Lines(msg.HTML))
	default:
		contentType = "text/plain; charset=utf-8"
		body = []byte(base64Lines(msg.Text))
	}

	hdrs := []mailHeader{
		{"From", mimeEncodeAddress(sanitizeHeader(msg.From))},
		{"To", strings.Join(msg.To, ", ")},
		{"Subject", mimeEncodeWord(sanitizeHeader(msg.Subject))},
		{"Date", time.Now().Format(time.RFC1123Z)},
		{"Message-ID", "<" + randomID() + "@" + domain + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", contentType},
	}
	if contentType != "" && !strings.HasPrefix(contentType, "multipart/") {
		hdrs = append(hdrs, mailHeader{"Content-Transfer-Encoding", "base64"})
	}
	for k, v := range msg.Headers {
		switch strings.ToLower(k) {
		case "from", "to", "subject", "date", "message-id", "mime-version", "content-type", "content-transfer-encoding", "dkim-signature":
			continue // these headers are built here
		}
		name := sanitizeHeader(k)
		if name == "" || strings.ContainsAny(name, ": \t") {
			continue // a colon or space in a header name is an injection attempt
		}
		hdrs = append(hdrs, mailHeader{name, sanitizeHeader(v)})
	}

	var out bytes.Buffer
	if sig, err := m.dkimSignature(hdrs, body); err != nil {
		return nil, err
	} else if sig != "" {
		out.WriteString(sig + "\r\n")
	}
	for _, h := range hdrs {
		out.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes(), nil
}

// mailHeader is a message header, kept in the order in which it is sent
// and signed.
type mailHeader struct {
	Name  string
	Value string
}

// dkimSignature returns the complete DKIM-Signature header line, or
// an empty string if signing is not configured.
func (m *mailer) dkimSignature(hdrs []mailHeader, body []byte) (string, error) {
	mc := m.config()
	key := m.dkimKey()
	if key == nil || mc.DKIMDomain == "" || mc.DKIMSelector == "" {
		return "", nil
	}

	bh := sha256.Sum256(dkimCanonBodyRelaxed(body))

	// Only headers that are actually present are signed.
	want := []string{"from", "to", "subject", "date", "message-id", "mime-version", "content-type"}
	var names []string
	var canon strings.Builder
	for _, want := range want {
		for _, h := range hdrs {
			if strings.EqualFold(h.Name, want) {
				canon.WriteString(dkimCanonHeaderRelaxed(h.Name, h.Value))
				canon.WriteString("\r\n")
				names = append(names, want)
				break
			}
		}
	}

	tag := fmt.Sprintf("v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%d; h=%s; bh=%s; b=",
		mc.DKIMDomain, mc.DKIMSelector, time.Now().Unix(),
		strings.Join(names, ":"), base64.StdEncoding.EncodeToString(bh[:]))

	// DKIM-Signature itself is signed with an empty b= and WITHOUT the final
	// CRLF, as RFC 6376 requires; otherwise the signature does not verify.
	canon.WriteString(dkimCanonHeaderRelaxed("DKIM-Signature", tag))

	sum := sha256.Sum256([]byte(canon.String()))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("dkim: signing: %w", err)
	}
	return "DKIM-Signature: " + tag + base64.StdEncoding.EncodeToString(sig), nil
}

// dkimCanonHeaderRelaxed is RFC 6376 relaxed header canonicalization:
// lower-case name, unfolded lines, runs of WSP reduced to one space.
func dkimCanonHeaderRelaxed(name, value string) string {
	v := strings.ReplaceAll(value, "\r\n", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	v = strings.ReplaceAll(v, "\t", " ")
	for strings.Contains(v, "  ") {
		v = strings.ReplaceAll(v, "  ", " ")
	}
	return strings.ToLower(strings.TrimSpace(name)) + ":" + strings.TrimSpace(v)
}

// dkimCanonBodyRelaxed is relaxed body canonicalization: trailing whitespace
// is removed, runs of WSP are reduced, empty lines at the end are dropped.
func dkimCanonBodyRelaxed(body []byte) []byte {
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	for i, ln := range lines {
		ln = strings.ReplaceAll(ln, "\t", " ")
		for strings.Contains(ln, "  ") {
			ln = strings.ReplaceAll(ln, "  ", " ")
		}
		lines[i] = strings.TrimRight(ln, " ")
	}
	end := len(lines)
	for end > 0 && lines[end-1] == "" {
		end--
	}
	if end == 0 {
		return nil
	}
	return []byte(strings.Join(lines[:end], "\r\n") + "\r\n")
}

// loadRSAKey reads a PEM private key (PKCS#1 or PKCS#8).
func loadRSAKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("file does not look like PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key type %T, but DKIM signing here requires RSA", parsed)
	}
	return k, nil
}

// queueLen returns how many messages are waiting to be sent.
func (m *mailer) queueLen() int {
	if m.srv.db == nil {
		return 0
	}
	return m.srv.db.Count(mailColl)
}

// queueSnapshot returns the queue for the Admin API (without message bodies).
func (m *mailer) queueSnapshot(limit int) []map[string]interface{} {
	if m.srv.db == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	res := m.srv.db.Find(mailColl, dbQuery{SortBy: "next_try", Limit: limit})
	out := make([]map[string]interface{}, 0, len(res))
	for _, r := range res {
		var msg outgoingMail
		if err := json.Unmarshal(r.Doc, &msg); err != nil {
			continue
		}
		item := map[string]interface{}{
			"id":       r.ID,
			"to":       msg.To,
			"subject":  msg.Subject,
			"state":    msg.State,
			"attempts": msg.Attempts,
			"created":  msg.CreatedAt.Format(time.RFC3339),
			"next_try": msg.NextTry.Format(time.RFC3339),
		}
		if msg.LastError != "" {
			item["last_error"] = msg.LastError
		}
		out = append(out, item)
	}
	return out
}

// addrOnly extracts the address from "Name <user@host>".
func addrOnly(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j > 0 {
			s = s[i+1 : i+j]
		}
	}
	s = strings.TrimSpace(s)
	// A space, line break or separator inside an address is an attempt
	// to add an extra command to the SMTP dialogue (MAIL FROM / RCPT TO).
	if !strings.Contains(s, "@") || strings.ContainsAny(s, " \t\r\n,;<>\"") {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] == 0x7f {
			return ""
		}
	}
	return s
}

// sanitizeHeader removes CR and LF from a header value. Without that, text
// from a feedback form ("Subject\r\nBcc: victim@example.com") could
// add its own headers and recipients.
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// mimeEncodeWord encodes a header value if it contains non-ASCII characters.
func mimeEncodeWord(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return mime.BEncoding.Encode("utf-8", s)
		}
	}
	return s
}

// mimeEncodeAddress encodes only the display name; the address itself is
// left unchanged: "User <ivan@example.com>".
func mimeEncodeAddress(s string) string {
	s = strings.TrimSpace(s)
	i := strings.LastIndex(s, "<")
	if i < 0 {
		return s
	}
	return strings.TrimSpace(mimeEncodeWord(strings.TrimSpace(s[:i]))) + " " + s[i:]
}

// base64Lines encodes the body in base64 with 76-character lines,
// as MIME requires.
func base64Lines(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	return b.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// BACKUPS
//
// A backup is a regular tar.gz that any archiver can read; unpacking it does
// not need webhost itself:
//
//	meta.json         manifest: when it was made and what is inside
//	config.json       configuration at the time of the backup
//	certs/...         local CA, certificates and keys
//	db/snapshot.bin   consistent snapshot of the embedded database
//	sites/<name>/...  site content (if include_sites)
//	extra/<name>/...  additional paths from the config
//
// Written to .part and renamed at the end: a backup interrupted halfway
// never looks complete.
// ============================================================================

// backupManifest describes a backup's contents in human-readable form.
type backupManifest struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Host      string    `json:"host"`
	OS        string    `json:"os"`
	DataDir   string    `json:"data_dir"`
	Config    string    `json:"config"`
	Sites     []string  `json:"sites,omitempty"`
	WithSites bool      `json:"with_sites"`
	Extra     []string  `json:"extra,omitempty"`
}

// backupDir returns where backups are stored.
func (s *Server) backupDir() string {
	cfg := s.getConfig()
	if cfg.Backup.Dir != "" {
		return cfg.Backup.Dir
	}
	return filepath.Join(cfg.DataDir, "backups")
}

// makeBackup creates a full backup and returns the path to the archive.
func (s *Server) makeBackup() (string, error) {
	cfg := s.getConfig()
	dir := s.backupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	now := time.Now()
	stamp := now.Format("20060102-150405")
	final := filepath.Join(dir, "backup-"+stamp+".tar.gz")
	// "_NN" sorts after ".tar.gz", so the rotation order is kept.
	for i := 2; fileExists(final) && i <= 99; i++ {
		final = filepath.Join(dir, fmt.Sprintf("backup-%s_%02d.tar.gz", stamp, i))
	}
	part := final + ".part"

	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	done := false
	defer func() {
		if !done {
			f.Close()
			os.Remove(part)
		}
	}()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	man := backupManifest{
		Version:   version,
		CreatedAt: now,
		OS:        runtime.GOOS + "/" + runtime.GOARCH,
		DataDir:   cfg.DataDir,
		Config:    s.cfgPath,
		WithSites: cfg.Backup.IncludeSites,
		Extra:     cfg.Backup.Extra,
	}
	man.Host, _ = os.Hostname()
	for _, site := range cfg.Sites {
		man.Sites = append(man.Sites, site.Name)
	}
	meta, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return "", err
	}
	if err := tarAddBytes(tw, "meta.json", meta, now); err != nil {
		return "", err
	}
	if fileExists(s.cfgPath) {
		if err := tarAddFile(tw, "config.json", s.cfgPath); err != nil {
			return "", err
		}
	}
	if certDir := filepath.Join(cfg.DataDir, "certs"); dirExists(certDir) {
		if err := tarAddTree(tw, "certs", certDir); err != nil {
			return "", err
		}
	}

	// The DB snapshot goes through a temporary file: tar must know the size in
	// advance, and a second in-memory copy of the whole database is best avoided.
	if s.db != nil {
		snap, err := os.CreateTemp(dir, "snapshot-*.tmp")
		if err != nil {
			return "", err
		}
		tmpName := snap.Name()
		werr := s.db.Snapshot(snap)
		if cerr := snap.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = tarAddFile(tw, "db/snapshot.bin", tmpName)
		}
		os.Remove(tmpName)
		if werr != nil {
			return "", fmt.Errorf("DB snapshot: %w", werr)
		}
	}

	if cfg.Backup.IncludeSites {
		for _, site := range cfg.Sites {
			if site.Root == "" || site.Type == "proxy" || site.Type == "redirect" {
				continue
			}
			root, err := evalRootAbs(site.Root)
			if err != nil || !dirExists(root) {
				continue
			}
			if pathInside(root, dir) {
				s.log.Warnf("backup: site %s skipped: its root %s contains the backup directory", site.Name, root)
				continue
			}
			if err := tarAddTree(tw, "sites/"+site.Name, root); err != nil {
				return "", err
			}
		}
	}
	dirReal, _ := evalRootAbs(dir)
	for _, p := range cfg.Backup.Extra {
		abs, err := evalRootAbs(p)
		if err != nil {
			continue
		}
		if pathInside(abs, dir) || pathInside(abs, dirReal) {
			// Archiving the backups directory re-packs every previous backup
			// (and the growing .part): size doubles with each run.
			s.log.Warnf("backup: extra path %s skipped: it contains the backup directory", abs)
			continue
		}
		switch {
		case dirExists(abs):
			if err := tarAddTree(tw, "extra/"+filepath.Base(abs), abs); err != nil {
				return "", err
			}
		case fileExists(abs):
			if err := tarAddFile(tw, "extra/"+filepath.Base(abs), abs); err != nil {
				return "", err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(part, final); err != nil {
		return "", err
	}
	done = true

	keep := cfg.Backup.Keep
	if keep <= 0 {
		keep = 7
	}
	pruneBackups(dir, keep, s.log)
	return final, nil
}

// tarAddBytes archives a file already in memory.
func tarAddBytes(tw *tar.Writer, name string, data []byte, mtime time.Time) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(data)),
		ModTime:  mtime,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// tarAddFile archives a file from disk under the given name.
func tarAddFile(tw *tar.Writer, name, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	hdr.Format = tar.FormatPAX
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	n, err := io.CopyN(tw, f, hdr.Size)
	if err == io.EOF && n < hdr.Size {
		// The file shrank between Stat and reading. Pad with zeros, otherwise
		// tar.Writer rightly treats the archive as corrupt.
		_, err = tw.Write(make([]byte, hdr.Size-n))
	}
	if err == io.EOF {
		err = nil
	}
	return err
}

// tarAddTree recursively adds the directory to the archive under prefix.
// A single unreadable file does not ruin the whole backup: it is skipped.
func tarAddTree(tw *tar.Writer, prefix, dir string) error {
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return nil
		}
		name := prefix + "/" + filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		switch {
		case d.IsDir():
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return nil
			}
			hdr.Name = name + "/"
			hdr.Format = tar.FormatPAX
			return tw.WriteHeader(hdr)
		case info.Mode()&os.ModeSymlink != 0:
			target, lerr := os.Readlink(p)
			if lerr != nil {
				return nil
			}
			hdr, err := tar.FileInfoHeader(info, target)
			if err != nil {
				return nil
			}
			hdr.Name = name
			hdr.Format = tar.FormatPAX
			return tw.WriteHeader(hdr)
		case info.Mode().IsRegular():
			if err := tarAddFile(tw, name, p); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
		}
		return nil
	})
}

// pruneBackups keeps the most recent backups. Names contain the date, so
// lexicographic order matches chronological order.
func pruneBackups(dir string, keep int, lg *Logger) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, "backup-") || !strings.HasSuffix(n, ".tar.gz") {
			continue
		}
		names = append(names, n)
	}
	if len(names) <= keep {
		return
	}
	sort.Strings(names)
	for _, n := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, n)); err == nil && lg != nil {
			lg.Infof("backup removed by rotation: %s", n)
		}
	}
}

// listBackups lists backups for the Admin API and the CLI.
func listBackups(dir string) []map[string]interface{} {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(ents))
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, "backup-") || !strings.HasSuffix(n, ".tar.gz") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"name":     n,
			"path":     filepath.Join(dir, n),
			"size":     info.Size(),
			"modified": info.ModTime().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["name"].(string) > out[j]["name"].(string)
	})
	return out
}

// safeJoin joins base and a relative path from the archive without letting it
// escape base ("./../etc/passwd" and absolute paths are rejected).
func safeJoin(base, rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("suspicious path in archive: %s", rel)
	}
	full := filepath.Join(base, clean)
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if fullAbs != baseAbs && !strings.HasPrefix(fullAbs, baseAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("suspicious path in archive: %s", rel)
	}
	return full, nil
}

// restoreBackup restores a backup in place. Config and DB are replaced;
// the previous config is kept next to it with a .bak suffix. Sites only
// with withSites: overwriting live content should be a separate decision.
//
// It returns a report of what was restored where.
func (s *Server) restoreBackup(archive string, withSites bool) (map[string]interface{}, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	cfg := s.getConfig()
	siteRoots := map[string]string{}
	for _, site := range cfg.Sites {
		if site.Root == "" {
			continue
		}
		if root, err := filepath.Abs(site.Root); err == nil {
			siteRoots[site.Name] = root
		}
	}
	certDir := filepath.Join(cfg.DataDir, "certs")

	report := map[string]interface{}{}
	var skipped []string
	files := 0

	// Site contents are unpacked into a fresh directory per site and switched
	// in only after the whole archive was read: writing over the live root
	// left files created after the backup in place, and a failure half-way
	// left the site mixed.
	staged := map[string]*stagedRestore{}
	committed := false
	defer func() {
		if !committed {
			for _, st := range staged {
				_ = os.RemoveAll(st.dir)
			}
		}
	}()

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		name := filepath.ToSlash(filepath.Clean("/" + hdr.Name))[1:]
		if name == "" {
			continue
		}
		if hdr.Typeflag == tar.TypeDir && !strings.HasPrefix(name, "sites/") {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeSymlink {
			skipped = append(skipped, name)
			continue
		}
		if hdr.Typeflag == tar.TypeSymlink && !strings.HasPrefix(name, "sites/") {
			// A symlink entry has no content: writing it as a file produced an
			// empty file. Outside site contents there is nothing to link.
			skipped = append(skipped, name)
			continue
		}
		switch {
		case name == "meta.json":
			var man backupManifest
			if data, err := io.ReadAll(io.LimitReader(tr, 1<<20)); err == nil {
				_ = json.Unmarshal(data, &man)
				report["created_at"] = man.CreatedAt.Format(time.RFC3339)
				report["from_host"] = man.Host
				report["from_version"] = man.Version
			}

		case name == "config.json":
			if fileExists(s.cfgPath) {
				_ = copyFile(s.cfgPath, s.cfgPath+".bak", 0o600)
			}
			if err := writeStreamAtomic(s.cfgPath, tr, 0o600); err != nil {
				return report, fmt.Errorf("config: %w", err)
			}
			report["config"] = s.cfgPath
			files++

		case name == "db/snapshot.bin":
			if s.db == nil {
				skipped = append(skipped, name)
				continue
			}
			if err := s.db.Restore(tr); err != nil {
				return report, fmt.Errorf("DB: %w", err)
			}
			report["database"] = "restored"
			files++

		case strings.HasPrefix(name, "certs/"):
			dst, err := safeJoin(certDir, strings.TrimPrefix(name, "certs/"))
			if err != nil {
				skipped = append(skipped, name)
				continue
			}
			if err := writeStreamAtomic(dst, tr, fs.FileMode(hdr.Mode)&0o777); err != nil {
				return report, err
			}
			files++

		case strings.HasPrefix(name, "sites/"):
			if !withSites {
				continue
			}
			rest := strings.TrimPrefix(name, "sites/")
			slash := strings.Index(rest, "/")
			if slash <= 0 {
				continue
			}
			siteName, rel := rest[:slash], rest[slash+1:]
			root, ok := siteRoots[siteName]
			if !ok {
				skipped = append(skipped, name)
				continue
			}
			st := staged[siteName]
			if st == nil {
				if st, err = newStagedRestore(root); err != nil {
					return report, fmt.Errorf("site %s: %w", siteName, err)
				}
				staged[siteName] = st
			}
			dst, err := safeJoin(st.dir, rel)
			if err != nil {
				skipped = append(skipped, name)
				continue
			}
			switch hdr.Typeflag {
			case tar.TypeDir:
				if err := os.MkdirAll(dst, fs.FileMode(hdr.Mode)&0o777|0o700); err != nil {
					return report, err
				}
			case tar.TypeSymlink:
				// Recreate links that stay inside the site; others are skipped.
				target := hdr.Linkname
				resolved := filepath.Clean(filepath.Join(filepath.Dir(dst), target))
				if target == "" || filepath.IsAbs(target) || !pathInside(st.dir, resolved) {
					skipped = append(skipped, name)
					continue
				}
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					return report, err
				}
				if err := os.Symlink(target, dst); err != nil {
					return report, err
				}
				files++
			default:
				if err := writeStreamAtomic(dst, tr, fs.FileMode(hdr.Mode)&0o777); err != nil {
					return report, err
				}
				files++
			}

		default:
			// extra/... and anything unknown: writing to arbitrary paths taken
			// from the archive is a bad idea, so unpacking such files is left
			// to manual work.
			skipped = append(skipped, name)
		}
	}

	report["files"] = files
	if len(skipped) > 0 {
		if len(skipped) > 20 {
			skipped = append(skipped[:20], fmt.Sprintf("… and %d more", len(skipped)-20))
		}
		report["skipped"] = skipped
	}
	if !withSites {
		report["note"] = "site contents were not restored (pass -sites)"
	}

	// The archive was read completely: switch the restored sites in.
	committed = true // from here on each commit cleans up after itself
	if len(staged) > 0 {
		names := make([]string, 0, len(staged))
		for n := range staged {
			names = append(names, n)
		}
		sort.Strings(names)
		restored := []string{}
		var failed []string
		for _, n := range names {
			if err := staged[n].commit(); err != nil {
				failed = append(failed, n+": "+err.Error())
				continue
			}
			restored = append(restored, n)
		}
		report["sites"] = restored
		if len(failed) > 0 {
			return report, fmt.Errorf("switching restored sites: %s", strings.Join(failed, "; "))
		}
	}
	return report, nil
}

// stagedRestore is one site's content being unpacked next to its live root.
type stagedRestore struct {
	root    string // site root from the config (absolute)
	target  string // what gets replaced: the resolved root for plain directories
	dir     string // directory being filled from the archive
	managed bool   // root is a release symlink (or copy) managed by webhost
}

func newStagedRestore(root string) (*stagedRestore, error) {
	st := &stagedRestore{root: root, target: root, managed: releasesManaged(root)}
	var parent, prefix string
	if st.managed {
		// A managed site gets the restored content as a new release.
		parent = releasesDir(root)
		prefix = time.Now().Format("20060102-150405") + "-restore-"
	} else {
		if real, err := filepath.EvalSymlinks(root); err == nil {
			st.target = real
		}
		parent = filepath.Dir(st.target)
		prefix = "." + filepath.Base(st.target) + ".restore-"
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return nil, err
	}
	// MkdirTemp creates 0700; keep the live root's mode (PHP-FPM and other
	// readers often run as a different user).
	mode := fs.FileMode(0o755)
	if fi, err := os.Stat(root); err == nil && fi.IsDir() {
		mode = fi.Mode().Perm() | 0o700
	}
	if err := os.Chmod(dir, mode); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	st.dir = dir
	return st, nil
}

// commit switches the restored content in. On failure the staged copy is
// removed and the live site is left as it was.
func (st *stagedRestore) commit() error {
	if st.managed {
		if err := swapRelease(st.root, st.dir); err != nil {
			_ = os.RemoveAll(st.dir)
			return err
		}
		return nil
	}
	old := ""
	if _, err := os.Lstat(st.target); err == nil {
		old = st.target + ".old-" + randomID()
		if err := os.Rename(st.target, old); err != nil {
			_ = os.RemoveAll(st.dir)
			return err
		}
	}
	if err := os.Rename(st.dir, st.target); err != nil {
		if old != "" {
			_ = os.Rename(old, st.target)
		}
		_ = os.RemoveAll(st.dir)
		return err
	}
	if old != "" {
		_ = os.RemoveAll(old)
	}
	return nil
}

// writeStreamAtomic writes a stream to a file via a temporary file and rename.
func writeStreamAtomic(dst string, r io.Reader, mode fs.FileMode) error {
	if mode == 0 {
		mode = 0o644
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".restore-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, err = io.Copy(tmp, r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmpName, mode)
	}
	if err == nil {
		// Windows rename does not work on top of an existing file.
		if runtime.GOOS == "windows" {
			os.Remove(dst)
		}
		err = os.Rename(tmpName, dst)
	}
	if err != nil {
		os.Remove(tmpName)
	}
	return err
}

// ============================================================================
// Supervisor of external processes
//
// PHP-FPM, a queue worker, anything else: the server starts the process, sends
// its output to the log, restarts it per policy with a doubling pause and
// stops it gracefully (signal, then kill after a timeout).
//
// The idea is the same as systemd, but without systemd: on Windows, in a
// FROM scratch container and on a BSD machine it behaves the same.
// ============================================================================

const (
	procRunning = "running"
	procBackoff = "backoff"
	procStopped = "stopped"
	procFailed  = "failed"
)

// managedProc is one process under supervision.
type managedProc struct {
	cfg  ProcessConfig
	hash string // config fingerprint: shows whether it changed

	mu        sync.Mutex
	state     string
	pid       int
	starts    int
	fails     int
	lastErr   string
	startedAt time.Time
	nextTry   time.Time
	cmd       *exec.Cmd

	cancel context.CancelFunc
	done   chan struct{} // closed when supervise has returned (process gone)
}

func (p *managedProc) setState(state, errMsg string) {
	p.mu.Lock()
	p.state = state
	if errMsg != "" {
		p.lastErr = errMsg
	}
	p.mu.Unlock()
}

func (p *managedProc) snapshot() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := map[string]interface{}{
		"name":    p.cfg.Name,
		"command": p.cfg.Command,
		"state":   p.state,
		"starts":  p.starts,
		"fails":   p.fails,
	}
	if p.pid > 0 && p.state == procRunning {
		m["pid"] = p.pid
		m["uptime_sec"] = int(time.Since(p.startedAt).Seconds())
	}
	if p.lastErr != "" {
		m["last_error"] = p.lastErr
	}
	if p.state == procBackoff && !p.nextTry.IsZero() {
		m["next_try"] = p.nextTry.Format(time.RFC3339)
	}
	return m
}

// supervisor manages a set of processes and their life cycle.
type supervisor struct {
	srv *Server
	lg  *Logger

	mu    sync.RWMutex
	procs map[string]*managedProc
	wg    sync.WaitGroup
}

func newSupervisor(srv *Server) *supervisor {
	return &supervisor{srv: srv, lg: srv.log, procs: map[string]*managedProc{}}
}

// procHash is a fingerprint of a process's config, used on reload to
// decide whether the process must be restarted.
func procHash(pc ProcessConfig) string {
	data, _ := json.Marshal(pc)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// start launches all processes from the config.
func (sup *supervisor) start(ctx context.Context, cfg *Config) {
	started := 0
	for i := range cfg.Processes {
		pc := cfg.Processes[i]
		if pc.Enabled != nil && !*pc.Enabled {
			continue
		}
		if pc.Name == "" {
			pc.Name = fmt.Sprintf("proc-%d", i+1)
		}
		if pc.Command == "" {
			sup.lg.Errorf("proc %s: command not set — skipped", pc.Name)
			continue
		}
		if sup.spawn(ctx, pc) {
			started++
		}
	}
	if started > 0 {
		sup.lg.Infof("supervisor: watching %d process(es)", started)
	}
}

// spawn registers the process and starts its supervising goroutine.
func (sup *supervisor) spawn(ctx context.Context, pc ProcessConfig) bool {
	sup.mu.Lock()
	if _, exists := sup.procs[pc.Name]; exists {
		sup.mu.Unlock()
		sup.lg.Errorf("proc %s: name already taken — skipped", pc.Name)
		return false
	}
	pctx, cancel := context.WithCancel(ctx)
	p := &managedProc{cfg: pc, hash: procHash(pc), state: procBackoff, cancel: cancel, done: make(chan struct{})}
	sup.procs[pc.Name] = p
	sup.mu.Unlock()

	sup.wg.Add(1)
	go sup.supervise(pctx, p)
	return true
}

// reload compares the config with what is running: changed and removed
// processes are stopped, new ones started; unchanged ones are left alone.
func (sup *supervisor) reload(ctx context.Context, cfg *Config) {
	want := map[string]ProcessConfig{}
	for i := range cfg.Processes {
		pc := cfg.Processes[i]
		if pc.Enabled != nil && !*pc.Enabled {
			continue
		}
		if pc.Name == "" {
			pc.Name = fmt.Sprintf("proc-%d", i+1)
		}
		if pc.Command == "" {
			continue
		}
		want[pc.Name] = pc
	}

	sup.mu.RLock()
	current := make(map[string]string, len(sup.procs))
	for name, p := range sup.procs {
		current[name] = p.hash
	}
	sup.mu.RUnlock()

	var stopping []*managedProc
	var respawn []ProcessConfig
	for name, h := range current {
		pc, keep := want[name]
		if keep && procHash(pc) == h {
			continue
		}
		if p := sup.stop(name); p != nil {
			stopping = append(stopping, p)
		}
		if keep {
			sup.lg.Infof("proc %s: configuration changed — restarting", name)
			respawn = append(respawn, pc)
		} else {
			sup.lg.Infof("proc %s: removed from configuration — stopped", name)
		}
	}
	// The old instances must be gone before the new ones start: both at once
	// fight over the same socket/port and run the same work twice.
	for _, p := range stopping {
		sup.waitStopped(p)
	}
	for _, pc := range respawn {
		sup.spawn(ctx, pc)
	}
	for name, pc := range want {
		if _, exists := current[name]; !exists {
			sup.spawn(ctx, pc)
		}
	}
}

// supervise runs the life cycle of a single process.
func (sup *supervisor) supervise(ctx context.Context, p *managedProc) {
	defer sup.wg.Done()
	defer close(p.done)

	base := time.Duration(p.cfg.BackoffSec) * time.Second
	if base <= 0 {
		base = time.Second
	}
	maxWait := time.Duration(p.cfg.BackoffMaxSec) * time.Second
	if maxWait < base {
		maxWait = 60 * time.Second
	}
	if maxWait < base {
		maxWait = base
	}
	policy := strings.ToLower(strings.TrimSpace(p.cfg.Restart))
	if policy == "" {
		policy = "always"
	}

	wait := base
	attempt := 0
	for {
		if ctx.Err() != nil {
			p.setState(procStopped, "")
			return
		}
		begin := time.Now()
		err := sup.runOnce(ctx, p)
		lived := time.Since(begin)

		if ctx.Err() != nil {
			p.setState(procStopped, "")
			return
		}
		attempt++
		if err != nil {
			p.mu.Lock()
			p.fails++
			p.lastErr = err.Error()
			p.mu.Unlock()
			sup.lg.Errorf("proc %s: exited with error: %v (ran for %s)", p.cfg.Name, err, lived.Round(time.Millisecond))
		} else {
			sup.lg.Warnf("proc %s: exited (ran for %s)", p.cfg.Name, lived.Round(time.Millisecond))
		}

		switch policy {
		case "never":
			p.setState(procStopped, "")
			return
		case "on-failure":
			if err == nil {
				p.setState(procStopped, "")
				return
			}
		}

		// A process that ran long enough counts as healthy: the pause and the
		// attempt counter are reset, otherwise rare crashes, once a day or so,
		// would eventually stretch the restart delay to hours.
		if lived > 60*time.Second {
			wait = base
			attempt = 0
		}
		if p.cfg.MaxRetries > 0 && attempt >= p.cfg.MaxRetries {
			p.setState(procFailed, fmt.Sprintf("gave up after %d attempts", attempt))
			sup.lg.Errorf("proc %s: %d consecutive failures — will not restart again", p.cfg.Name, attempt)
			return
		}

		p.mu.Lock()
		p.state = procBackoff
		p.nextTry = time.Now().Add(wait)
		p.mu.Unlock()
		sup.lg.Infof("proc %s: restarting in %s", p.cfg.Name, wait)

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			p.setState(procStopped, "")
			return
		case <-timer.C:
		}
		if wait *= 2; wait > maxWait {
			wait = maxWait
		}
	}
}

// runOnce starts the process and waits for it to end or for the context to be cancelled.
func (sup *supervisor) runOnce(ctx context.Context, p *managedProc) error {
	cmd := exec.Command(p.cfg.Command, p.cfg.Args...)
	if p.cfg.Dir != "" {
		cmd.Dir = p.cfg.Dir
	}
	if len(p.cfg.Env) > 0 {
		cmd.Env = append(os.Environ(), p.cfg.Env...)
	}
	// If the process leaves behind children that inherited its stdout,
	// cmd.Wait() would wait for EOF on the pipe forever, and a waiting goroutine
	// would leak with every restart. WaitDelay closes the pipes forcibly
	// five seconds after the process itself has died.
	cmd.WaitDelay = 5 * time.Second

	var logF *os.File
	if p.cfg.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(p.cfg.LogFile), 0o755); err == nil {
			f, err := os.OpenFile(p.cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
			if err == nil {
				logF = f
				cmd.Stdout, cmd.Stderr = f, f
			} else {
				sup.lg.Errorf("proc %s: log %s: %v — writing to main log", p.cfg.Name, p.cfg.LogFile, err)
			}
		}
	}
	var lw *procLogWriter
	if logF == nil {
		lw = &procLogWriter{lg: sup.lg, name: p.cfg.Name}
		cmd.Stdout, cmd.Stderr = lw, lw
	}
	defer func() {
		if logF != nil {
			logF.Close()
		}
		if lw != nil {
			lw.flush()
		}
	}()

	if err := cmd.Start(); err != nil {
		p.setState(procBackoff, err.Error())
		return fmt.Errorf("start: %w", err)
	}
	p.mu.Lock()
	p.cmd = cmd
	p.pid = cmd.Process.Pid
	p.starts++
	p.startedAt = time.Now()
	p.state = procRunning
	p.mu.Unlock()
	sup.lg.Infof("proc %s: started, pid %d", p.cfg.Name, cmd.Process.Pid)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		sup.terminate(p, cmd, done)
		return nil
	}
}

// terminate stops the process: first gracefully, then by force.
// Portability over elegance: os.Interrupt is not supported on Windows,
// so Kill is used there.
func (sup *supervisor) terminate(p *managedProc, cmd *exec.Cmd, done chan error) {
	timeout := time.Duration(p.cfg.StopTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if cmd.Process == nil {
		return
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		_ = cmd.Process.Kill()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		sup.lg.Infof("proc %s: stopped", p.cfg.Name)
	case <-timer.C:
		sup.lg.Warnf("proc %s: did not exit within %s — killing", p.cfg.Name, timeout)
		_ = cmd.Process.Kill()
		// Wait for a limited time: the child process may leave
		// grandchildren holding stdout open, and then Wait never returns.
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			sup.lg.Errorf("proc %s: failed to wait for exit", p.cfg.Name)
		}
	}
	p.setState(procStopped, "")
}

// stop stops one process and removes it from supervision. It only signals: use
// waitStopped before starting a replacement.
func (sup *supervisor) stop(name string) *managedProc {
	sup.mu.Lock()
	p, ok := sup.procs[name]
	if ok {
		delete(sup.procs, name)
	}
	sup.mu.Unlock()
	if !ok {
		return nil
	}
	p.cancel()
	return p
}

// waitStopped waits until p's process has exited, bounded by its stop timeout
// plus the kill grace period of terminate.
func (sup *supervisor) waitStopped(p *managedProc) {
	limit := time.Duration(p.cfg.StopTimeoutSec) * time.Second
	if limit <= 0 {
		limit = 10 * time.Second
	}
	limit += 10 * time.Second
	t := time.NewTimer(limit)
	defer t.Stop()
	select {
	case <-p.done:
	case <-t.C:
		sup.lg.Errorf("proc %s: still running after %s — starting the new instance anyway", p.cfg.Name, limit)
	}
}

// stopAll stops everything and waits for the supervising goroutines to finish.
func (sup *supervisor) stopAll() {
	sup.mu.Lock()
	procs := make([]*managedProc, 0, len(sup.procs))
	for _, p := range sup.procs {
		procs = append(procs, p)
	}
	sup.procs = map[string]*managedProc{}
	sup.mu.Unlock()
	for _, p := range procs {
		p.cancel()
	}
	sup.wg.Wait()
}

// restart restarts a process by name (for the Admin API).
func (sup *supervisor) restart(ctx context.Context, name string) error {
	sup.mu.RLock()
	p, ok := sup.procs[name]
	sup.mu.RUnlock()
	if !ok {
		return fmt.Errorf("process not found: %s", name)
	}
	pc := p.cfg
	if old := sup.stop(name); old != nil {
		// Starting the new instance while the old one was still shutting
		// down made them collide ("address already in use").
		sup.waitStopped(old)
	}
	if !sup.spawn(ctx, pc) {
		return fmt.Errorf("failed to restart %s", name)
	}
	return nil
}

// snapshot returns the state of the processes for the Admin API.
func (sup *supervisor) snapshot() []map[string]interface{} {
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	out := make([]map[string]interface{}, 0, len(sup.procs))
	for _, p := range sup.procs {
		out = append(out, p.snapshot())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["name"].(string) < out[j]["name"].(string)
	})
	return out
}

// procLogWriter turns the process output stream into log lines.
// An incomplete last line stays in the buffer until the next write.
type procLogWriter struct {
	lg   *Logger
	name string

	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *procLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			// The line is not finished: keep the rest in the buffer.
			w.buf.WriteString(line)
			break
		}
		w.lg.Infof("%s | %s", w.name, strings.TrimRight(line, "\r\n"))
	}
	// A process that never writes a newline must not eat all the memory.
	if w.buf.Len() > 64<<10 {
		w.lg.Infof("%s | %s", w.name, w.buf.String())
		w.buf.Reset()
	}
	return len(p), nil
}

func (w *procLogWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s := strings.TrimRight(w.buf.String(), "\r\n"); s != "" {
		w.lg.Infof("%s | %s", w.name, s)
	}
	w.buf.Reset()
}

// ============================================================================
// Embedded database
//
// A document store on the standard library: data lives in memory, changes are
// written to a journal (WAL) on disk. It works like a typical embedded database:
//
//	write   → frame in the WAL (+CRC32) → fsync per policy → apply in memory
//	start   → read the snapshot → replay the WAL → ready
//	growth  → compaction: snapshot + truncate the journal
//
// Properties:
//   - atomicity: a WAL frame is applied entirely or not at all;
//     a torn tail of the journal (power failure mid-write) is cut off by CRC;
//   - transactions: several operations in one frame;
//   - secondary indexes in memory, including unique ones;
//   - snapshot and restore as a single byte stream.
//
// Deliberately missing: SQL, on-disk range indexes and data sets that
// do not fit into memory. For the sites this server hosts that is
// enough, and the complexity is much lower.
// ============================================================================

const (
	dbWALName      = "wal.log"
	dbSnapshotName = "snapshot.json"
	dbMaxFrame     = 64 << 20 // largest journal frame
)

// dbSyncMode: when to flush the journal to disk.
type dbSyncMode string

const (
	// dbSyncAlways: fsync after every transaction. Nothing is lost even on
	// a power loss, but every write waits for the disk.
	dbSyncAlways dbSyncMode = "always"
	// dbSyncInterval: fsync once per second in the background. The last
	// second of writes may be lost; throughput is several times higher.
	dbSyncInterval dbSyncMode = "interval"
	// dbSyncNever: rely on the OS. Fast, survives a crash of the process,
	// but not of the machine.
	dbSyncNever dbSyncMode = "never"
)

// dbOp is one elementary operation in the journal.
type dbOp struct {
	Op   string          `json:"o"` // put | del
	Coll string          `json:"c"`
	ID   string          `json:"i"`
	Doc  json.RawMessage `json:"d,omitempty"`
	TS   int64           `json:"t"`
}

// dbFrame: a group of operations applied as a whole.
type dbFrame struct {
	Ops []dbOp `json:"ops"`
}

// dbIndex is a secondary index for one field of a document.
type dbIndex struct {
	field  string
	unique bool
	vals   map[string]map[string]bool // value -> set of document ids
}

func newDBIndex(field string, unique bool) *dbIndex {
	return &dbIndex{field: field, unique: unique, vals: map[string]map[string]bool{}}
}

func (ix *dbIndex) add(id string, doc json.RawMessage) error {
	v, ok := docField(doc, ix.field)
	if !ok {
		return nil // documents without this field are not indexed
	}
	set := ix.vals[v]
	if set == nil {
		set = map[string]bool{}
		ix.vals[v] = set
	}
	if ix.unique {
		for other := range set {
			if other != id {
				return fmt.Errorf("unique constraint violated %s=%q (held by document %s)", ix.field, v, other)
			}
		}
	}
	set[id] = true
	return nil
}

func (ix *dbIndex) remove(id string, doc json.RawMessage) {
	v, ok := docField(doc, ix.field)
	if !ok {
		return
	}
	if set := ix.vals[v]; set != nil {
		delete(set, id)
		if len(set) == 0 {
			delete(ix.vals, v)
		}
	}
}

func (ix *dbIndex) lookup(v string) []string {
	set := ix.vals[v]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// dbCollection is a named set of documents.
type dbCollection struct {
	name string
	docs map[string]json.RawMessage
	idx  map[string]*dbIndex
}

func newDBCollection(name string) *dbCollection {
	return &dbCollection{name: name, docs: map[string]json.RawMessage{}, idx: map[string]*dbIndex{}}
}

// DB is the storage itself.
type DB struct {
	walName    string // current journal; empty: the old name wal.log
	snapWAL    string // journal listed in the last read snapshot
	snapWALOut string // journal named in the snapshot being created
	mu         sync.RWMutex
	dir        string
	wal        *os.File
	lg         *Logger
	sync       dbSyncMode

	colls map[string]*dbCollection

	walBytes  int64
	unsynced  int64
	opsTotal  uint64
	closed    bool
	cancelBg  context.CancelFunc
	compactAt int64 // WAL size that triggers automatic compaction
}

// openDB opens or creates a database in the dir directory.
func openDB(dir string, mode dbSyncMode, lg *Logger) (*DB, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("database directory %s: %w", dir, err)
	}
	switch mode {
	case dbSyncAlways, dbSyncInterval, dbSyncNever:
	default:
		mode = dbSyncInterval
	}
	db := &DB{
		dir:       dir,
		lg:        lg,
		sync:      mode,
		colls:     map[string]*dbCollection{},
		compactAt: 32 << 20,
	}
	if err := db.loadSnapshot(); err != nil {
		return nil, err
	}
	replayed, truncated, err := db.replayWAL()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, db.walFile()), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("database journal: %w", err)
	}
	db.wal = f
	db.removeStaleWALs()
	if st, err := f.Stat(); err == nil {
		db.walBytes = st.Size()
	}
	if lg != nil {
		lg.Infof("database: %d collections, %d documents, replayed journal ops: %d",
			len(db.colls), db.countDocs(), replayed)
		if truncated > 0 {
			lg.Warnf("database: discarded corrupt journal tail (%d bytes) — "+
				"usually caused by a sudden power loss", truncated)
		}
	}
	if mode == dbSyncInterval {
		ctx, cancel := context.WithCancel(context.Background())
		db.cancelBg = cancel
		go db.syncLoop(ctx)
	}
	return db, nil
}

func (db *DB) countDocs() int {
	n := 0
	for _, c := range db.colls {
		n += len(c.docs)
	}
	return n
}

// syncLoop flushes the journal to disk once a second if there is anything to flush.
func (db *DB) syncLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			db.mu.Lock()
			if db.unsynced > 0 && db.wal != nil && !db.closed {
				if err := db.wal.Sync(); err != nil && db.lg != nil {
					db.lg.Errorf("database: journal fsync: %v", err)
				}
				db.unsynced = 0
			}
			db.mu.Unlock()
		}
	}
}

// loadSnapshot reads the last snapshot, if any.
func (db *DB) loadSnapshot() error {
	f, err := os.Open(filepath.Join(db.dir, dbSnapshotName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	if err := db.readSnapshotStream(bufio.NewReaderSize(f, 1<<16)); err != nil {
		return err
	}
	db.walName = db.snapWAL
	return nil
}

// walFile is the name of the current journal. The snapshot keeps the name of the
// journal that continues it, and every compaction opens a journal with a new name:
// a crash between writing the snapshot and switching the journal no longer leads
// to replaying operations already included in the snapshot.
func (db *DB) walFile() string {
	if db.walName == "" {
		return dbWALName
	}
	return db.walName
}

// removeStaleWALs removes logs that are not related to the current snapshot:
// leftovers of an interrupted compaction and the journal before it.
func (db *DB) removeStaleWALs() {
	entries, err := os.ReadDir(db.dir)
	if err != nil {
		return
	}
	cur := db.walFile()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || n == cur {
			continue
		}
		if n == dbWALName || (strings.HasPrefix(n, "wal-") && strings.HasSuffix(n, ".log")) {
			_ = os.Remove(filepath.Join(db.dir, n))
		}
	}
}

// syncDir flushes directory entries to disk after a rename or file creation
// (on Windows a directory cannot be opened, so this is skipped).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// snapshotFile is the snapshot format: collections, documents and index definitions.
type snapshotFile struct {
	WAL     string                                `json:"wal,omitempty"` // journal that continues this snapshot
	Version int                                   `json:"version"`
	Created string                                `json:"created"`
	Indexes map[string][]snapshotIndex            `json:"indexes,omitempty"`
	Data    map[string]map[string]json.RawMessage `json:"data"`
}

type snapshotIndex struct {
	Field  string `json:"field"`
	Unique bool   `json:"unique"`
}

func (db *DB) readSnapshotStream(r io.Reader) error {
	var snap snapshotFile
	if err := json.NewDecoder(r).Decode(&snap); err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("database snapshot corrupt: %w", err)
	}
	db.snapWAL = snap.WAL
	db.colls = map[string]*dbCollection{}
	for name, docs := range snap.Data {
		c := newDBCollection(name)
		for id, doc := range docs {
			c.docs[id] = doc
		}
		db.colls[name] = c
	}
	for name, idxs := range snap.Indexes {
		c := db.colls[name]
		if c == nil {
			c = newDBCollection(name)
			db.colls[name] = c
		}
		for _, si := range idxs {
			ix := newDBIndex(si.Field, si.Unique)
			for id, doc := range c.docs {
				// A uniqueness violation in the snapshot must not prevent startup:
				// the data is already written, and a person has to fix it.
				if err := ix.add(id, doc); err != nil && db.lg != nil {
					db.lg.Warnf("database: index %s.%s: %v", name, si.Field, err)
				}
			}
			c.idx[si.Field] = ix
		}
	}
	return nil
}

// replayWAL replays the journal over the snapshot.
// It returns the number of operations applied and the size of the discarded tail.
func (db *DB) replayWAL() (int, int64, error) {
	path := filepath.Join(db.dir, db.walFile())
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 1<<16)
	var (
		applied  int
		offset   int64
		hdr      [8]byte
		lastGood int64
	)
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			break // EOF or a break inside the header: the tail is cut off
		}
		length := binary.BigEndian.Uint32(hdr[0:4])
		want := binary.BigEndian.Uint32(hdr[4:8])
		if length == 0 || length > dbMaxFrame {
			break
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}
		if crc32.ChecksumIEEE(payload) != want {
			break // The frame was not written completely: nothing further can be read
		}
		var frame dbFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			break
		}
		for _, op := range frame.Ops {
			db.applyOp(op)
			applied++
		}
		offset += int64(len(hdr)) + int64(length)
		lastGood = offset
	}

	st, err := f.Stat()
	if err != nil {
		return applied, 0, err
	}
	truncated := st.Size() - lastGood
	if truncated > 0 {
		// Cut off the damaged tail, otherwise the next frame is written after the
		// garbage and the journal becomes unreadable for good.
		if err := os.Truncate(path, lastGood); err != nil {
			return applied, truncated, fmt.Errorf("truncating journal: %w", err)
		}
	}
	return applied, truncated, nil
}

// applyOp applies the operation in memory. Called with the lock held or
// at startup, when nothing runs concurrently.
func (db *DB) applyOp(op dbOp) {
	c := db.colls[op.Coll]
	if c == nil {
		if op.Op == "del" {
			return
		}
		c = newDBCollection(op.Coll)
		db.colls[op.Coll] = c
	}
	switch op.Op {
	case "put":
		if old, ok := c.docs[op.ID]; ok {
			for _, ix := range c.idx {
				ix.remove(op.ID, old)
			}
		}
		c.docs[op.ID] = op.Doc
		for _, ix := range c.idx {
			_ = ix.add(op.ID, op.Doc)
		}
	case "del":
		if old, ok := c.docs[op.ID]; ok {
			for _, ix := range c.idx {
				ix.remove(op.ID, old)
			}
			delete(c.docs, op.ID)
		}
	}
}

// writeFrame serializes the frame, computes the CRC and appends it to the journal.
// Called with the lock held.
func (db *DB) writeFrame(frame dbFrame) error {
	if db.closed {
		return errors.New("database is closed")
	}
	payload, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if len(payload) > dbMaxFrame {
		return fmt.Errorf("transaction too large: %s", humanBytes(int64(len(payload))))
	}
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(payload))

	buf := make([]byte, 0, len(hdr)+len(payload))
	buf = append(buf, hdr[:]...)
	buf = append(buf, payload...)
	if _, err := db.wal.Write(buf); err != nil {
		return fmt.Errorf("journal write: %w", err)
	}
	db.walBytes += int64(len(buf))
	db.unsynced += int64(len(buf))
	db.opsTotal += uint64(len(frame.Ops))

	if db.sync == dbSyncAlways {
		if err := db.wal.Sync(); err != nil {
			return fmt.Errorf("journal fsync: %w", err)
		}
		db.unsynced = 0
	}
	return nil
}

// dbTx is a transaction: operations are collected and applied in one frame.
type dbTx struct {
	db  *DB
	ops []dbOp
	err error
}

// Tx runs fn in a transaction. If fn returns an error, none of its
// operations reach the journal or memory.
func (db *DB) Tx(fn func(tx *dbTx) error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	tx := &dbTx{db: db}
	if err := fn(tx); err != nil {
		return err
	}
	if tx.err != nil {
		return tx.err
	}
	if len(tx.ops) == 0 {
		return nil
	}
	// First check the unique indexes against the whole set of operations:
	// a conflict found after writing to the journal could not be undone.
	if err := db.validateOps(tx.ops); err != nil {
		return err
	}
	if err := db.writeFrame(dbFrame{Ops: tx.ops}); err != nil {
		return err
	}
	for _, op := range tx.ops {
		db.applyOp(op)
	}
	db.maybeCompactLocked()
	return nil
}

// validateOps checks uniqueness constraints before writing.
func (db *DB) validateOps(ops []dbOp) error {
	type pending struct {
		coll, field, value, id string
	}
	var checks []pending
	for _, op := range ops {
		if op.Op != "put" {
			continue
		}
		c := db.colls[op.Coll]
		if c == nil {
			continue
		}
		for field, ix := range c.idx {
			if !ix.unique {
				continue
			}
			v, ok := docField(op.Doc, field)
			if !ok {
				continue
			}
			for other := range ix.vals[v] {
				if other != op.ID {
					return fmt.Errorf("%s: unique constraint violated %s=%q (held by %s)",
						op.Coll, field, v, other)
				}
			}
			checks = append(checks, pending{op.Coll, field, v, op.ID})
		}
	}
	// Conflicts within the transaction itself.
	seen := map[string]string{}
	for _, c := range checks {
		key := c.coll + "\x00" + c.field + "\x00" + c.value
		if prev, ok := seen[key]; ok && prev != c.id {
			return fmt.Errorf("%s: two documents with %s=%q in one transaction", c.coll, c.field, c.value)
		}
		seen[key] = c.id
	}
	return nil
}

// Put adds the document to the transaction. An empty id is generated automatically.
func (tx *dbTx) Put(coll, id string, v interface{}) string {
	if tx.err != nil {
		return id
	}
	if id == "" {
		id = randomID()
	}
	raw, err := json.Marshal(v)
	if err != nil {
		tx.err = fmt.Errorf("serializing document %s/%s: %w", coll, id, err)
		return id
	}
	tx.ops = append(tx.ops, dbOp{Op: "put", Coll: coll, ID: id, Doc: raw, TS: time.Now().UnixMilli()})
	return id
}

// Delete deletes the document as part of the transaction.
func (tx *dbTx) Delete(coll, id string) {
	if tx.err != nil {
		return
	}
	tx.ops = append(tx.ops, dbOp{Op: "del", Coll: coll, ID: id, TS: time.Now().UnixMilli()})
}

// Put is shorthand for a transaction with a single insert.
func (db *DB) Put(coll, id string, v interface{}) (string, error) {
	var out string
	err := db.Tx(func(tx *dbTx) error {
		out = tx.Put(coll, id, v)
		return nil
	})
	return out, err
}

// Delete is shorthand for a transaction with a single deletion.
func (db *DB) Delete(coll, id string) error {
	return db.Tx(func(tx *dbTx) error {
		tx.Delete(coll, id)
		return nil
	})
}

var errDBNotFound = errors.New("document not found")

// Get decodes the document into out.
func (db *DB) Get(coll, id string, out interface{}) error {
	raw, err := db.GetRaw(coll, id)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// GetRaw returns the document as is.
func (db *DB) GetRaw(coll, id string) (json.RawMessage, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	c := db.colls[coll]
	if c == nil {
		return nil, errDBNotFound
	}
	raw, ok := c.docs[id]
	if !ok {
		return nil, errDBNotFound
	}
	return raw, nil
}

// Exists reports whether the document exists.
func (db *DB) Exists(coll, id string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	c := db.colls[coll]
	return c != nil && c.docs[id] != nil
}

// Count returns how many documents the collection holds.
func (db *DB) Count(coll string) int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if c := db.colls[coll]; c != nil {
		return len(c.docs)
	}
	return 0
}

// EnsureIndex creates an index on the field, if it does not already exist, and fills it.
func (db *DB) EnsureIndex(coll, field string, unique bool) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	c := db.colls[coll]
	if c == nil {
		c = newDBCollection(coll)
		db.colls[coll] = c
	}
	if existing, ok := c.idx[field]; ok && existing.unique == unique {
		return nil
	}
	ix := newDBIndex(field, unique)
	ids := make([]string, 0, len(c.docs))
	for id := range c.docs {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic order – reproducible errors
	for _, id := range ids {
		if err := ix.add(id, c.docs[id]); err != nil {
			return fmt.Errorf("building index %s.%s: %w", coll, field, err)
		}
	}
	c.idx[field] = ix
	return nil
}

// dbQuery describes a query.
type dbQuery struct {
	// Eq: exact matches by field. If the field has an index, it is
	// used; otherwise every document is checked.
	Eq map[string]string
	// Match is an arbitrary predicate over a raw document.
	Match func(id string, doc json.RawMessage) bool
	// SortBy is the field to sort by; empty sorts by id.
	SortBy string
	// Desc reverses the order.
	Desc bool
	// Offset, Limit: paging. Limit 0 means no limit.
	Offset, Limit int
}

// dbResult is one record found.
type dbResult struct {
	ID  string
	Doc json.RawMessage
}

// Find runs the query.
func (db *DB) Find(coll string, q dbQuery) []dbResult {
	// Only collecting candidates happens under the lock. Filtering (including
	// Match, which may be slow) runs outside it, so a long query does not
	// hold up the whole database. A document is replaced as a whole when
	// changed, so the collected slices stay consistent.
	db.mu.RLock()
	c := db.colls[coll]
	if c == nil {
		db.mu.RUnlock()
		return nil
	}

	// Candidates: from the most selective index, otherwise the whole collection.
	var candidates []string
	best := -1
	for field, want := range q.Eq {
		ix := c.idx[field]
		if ix == nil {
			continue
		}
		ids := ix.lookup(want)
		if best < 0 || len(ids) < best {
			best, candidates = len(ids), ids
		}
	}
	if best < 0 {
		candidates = make([]string, 0, len(c.docs))
		for id := range c.docs {
			candidates = append(candidates, id)
		}
	}

	type candidate struct {
		id  string
		doc json.RawMessage
	}
	cands := make([]candidate, 0, len(candidates))
	for _, id := range candidates {
		if doc, ok := c.docs[id]; ok {
			cands = append(cands, candidate{id, doc})
		}
	}
	db.mu.RUnlock()

	out := make([]dbResult, 0, len(cands))
	for _, cd := range cands {
		id, doc := cd.id, cd.doc
		matched := true
		for field, want := range q.Eq {
			if v, ok := docField(doc, field); !ok || v != want {
				matched = false
				break
			}
		}
		if matched && q.Match != nil {
			matched = q.Match(id, doc)
		}
		if matched {
			out = append(out, dbResult{ID: id, Doc: doc})
		}
	}

	sortField := q.SortBy
	sort.SliceStable(out, func(i, j int) bool {
		var a, b string
		if sortField == "" {
			a, b = out[i].ID, out[j].ID
		} else {
			a, _ = docField(out[i].Doc, sortField)
			b, _ = docField(out[j].Doc, sortField)
			if a == b {
				a, b = out[i].ID, out[j].ID
			}
		}
		if q.Desc {
			return a > b
		}
		return a < b
	})

	if q.Offset > 0 {
		if q.Offset >= len(out) {
			return nil
		}
		out = out[q.Offset:]
	}
	if q.Limit > 0 && q.Limit < len(out) {
		out = out[:q.Limit]
	}
	return out
}

// FindOne returns the first matching document.
func (db *DB) FindOne(coll string, q dbQuery) (dbResult, bool) {
	q.Limit = 1
	res := db.Find(coll, q)
	if len(res) == 0 {
		return dbResult{}, false
	}
	return res[0], true
}

// docField extracts a document field's value as a string. Nested paths with
// dots are supported: "author.email". Numbers and bools are converted to strings
// so that they can be searched and sorted.
func docField(doc json.RawMessage, path string) (string, bool) {
	if len(doc) == 0 || path == "" {
		return "", false
	}
	var cur interface{}
	if err := json.Unmarshal(doc, &cur); err != nil {
		return "", false
	}
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		cur, ok = m[part]
		if !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		// Whole numbers are printed without an exponent so that string sorting
		// makes sense for typical values (timestamps, counters).
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10), true
		}
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case nil:
		return "", false
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}

// maybeCompactLocked starts compaction once the journal exceeds the threshold.
func (db *DB) maybeCompactLocked() {
	if db.compactAt <= 0 || db.walBytes < db.compactAt {
		return
	}
	if err := db.compactLocked(); err != nil && db.lg != nil {
		db.lg.Errorf("database: compaction: %v", err)
	}
}

// Compact shrinks the journal: it writes a snapshot of the current state and starts a new WAL.
func (db *DB) Compact() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.compactLocked()
}

func (db *DB) compactLocked() error {
	if db.closed {
		return errors.New("database is closed")
	}
	// The new journal is created first, and the snapshot refers to it by name.
	// The commit point is the rename of the snapshot: from then on the new
	// journal is used and the old one is no longer replayed.
	newWAL := "wal-" + randomID() + ".log"
	nf, err := os.OpenFile(filepath.Join(db.dir, newWAL), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("new journal: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = nf.Close()
			_ = os.Remove(filepath.Join(db.dir, newWAL))
		}
	}()
	if err := nf.Sync(); err != nil {
		return err
	}
	db.snapWALOut = newWAL
	defer func() { db.snapWALOut = "" }()

	snapPath := filepath.Join(db.dir, dbSnapshotName)
	tmp := snapPath + ".tmp-" + randomID()
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 1<<16)
	if err := db.writeSnapshotLocked(bw); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	// The snapshot must be on disk before the journal is reset, otherwise
	// a crash between the two steps loses data.
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, snapPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	committed = true
	syncDir(db.dir)

	if db.wal != nil {
		_ = db.wal.Close()
	}
	_ = os.Remove(filepath.Join(db.dir, db.walFile()))
	db.wal = nf
	db.walName = newWAL
	db.walBytes = 0
	db.unsynced = 0
	if db.lg != nil {
		db.lg.Infof("database: compaction done, documents: %d", db.countDocs())
	}
	return nil
}

func (db *DB) writeSnapshotLocked(w io.Writer) error {
	walOut := db.snapWALOut
	if walOut == "" {
		// Snapshot for a backup: no existing journal belongs to it.
		walOut = "wal-" + randomID() + ".log"
	}
	snap := snapshotFile{
		WAL:     walOut,
		Version: 1,
		Created: time.Now().UTC().Format(time.RFC3339),
		Indexes: map[string][]snapshotIndex{},
		Data:    map[string]map[string]json.RawMessage{},
	}
	for name, c := range db.colls {
		docs := make(map[string]json.RawMessage, len(c.docs))
		for id, d := range c.docs {
			docs[id] = d
		}
		snap.Data[name] = docs
		if len(c.idx) > 0 {
			fields := make([]string, 0, len(c.idx))
			for f := range c.idx {
				fields = append(fields, f)
			}
			sort.Strings(fields)
			for _, f := range fields {
				snap.Indexes[name] = append(snap.Indexes[name],
					snapshotIndex{Field: f, Unique: c.idx[f].unique})
			}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")
	return enc.Encode(snap)
}

// Snapshot writes the whole database content to a stream, for backups.
func (db *DB) Snapshot(w io.Writer) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.writeSnapshotLocked(w)
}

// Restore replaces the database content with data from the stream. The previous
// data is wiped, so it is first saved to a file on disk.
func (db *DB) Restore(r io.Reader) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return errors.New("database is closed")
	}
	backup := filepath.Join(db.dir, fmt.Sprintf("before-restore-%s.json", time.Now().UTC().Format("20060102-150405")))
	if f, err := os.Create(backup); err == nil {
		bw := bufio.NewWriterSize(f, 1<<16)
		_ = db.writeSnapshotLocked(bw)
		_ = bw.Flush()
		_ = f.Close()
		if db.lg != nil {
			db.lg.Infof("database: previous state saved in %s", backup)
		}
	}
	if err := db.readSnapshotStream(r); err != nil {
		return err
	}
	return db.compactLocked()
}

// Stats is a summary for /metrics and the Admin API.
func (db *DB) Stats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()
	colls := map[string]int{}
	indexes := 0
	for name, c := range db.colls {
		colls[name] = len(c.docs)
		indexes += len(c.idx)
	}
	return map[string]interface{}{
		"collections":     colls,
		"documents_total": db.countDocs(),
		"indexes":         indexes,
		"wal_bytes":       db.walBytes,
		"ops_total":       db.opsTotal,
		"sync_mode":       string(db.sync),
		"dir":             db.dir,
	}
}

// Close flushes the journal and closes the files.
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return nil
	}
	db.closed = true
	if db.cancelBg != nil {
		db.cancelBg()
	}
	if db.wal == nil {
		return nil
	}
	if err := db.wal.Sync(); err != nil && db.lg != nil {
		db.lg.Errorf("database: final fsync: %v", err)
	}
	return db.wal.Close()
}

// ============================================================================
// Self-build: the build subcommand
//
// The file can build itself, even on a machine without a Go compiler:
// the toolchain is downloaded into a temporary directory, used and removed.
// Nothing is installed on the system and PATH does not change.
//
//	./main.go build                        build for the current machine
//	./main.go build -all                   build for all platforms into ./dist
//	./main.go build -os linux -arch arm64  build for one platform
// ============================================================================

// buildTarget is one cross-compilation target.
type buildTarget struct {
	GOOS   string
	GOARCH string
	GOARM  string // only for GOARCH=arm
	Note   string // who this binary is for
}

var buildTargets = []buildTarget{
	{GOOS: "linux", GOARCH: "amd64", Note: "Linux on Intel/AMD — typical servers and desktops"},
	{GOOS: "linux", GOARCH: "arm64", Note: "Linux on ARM64 — Raspberry Pi 4/5, Ampere, Graviton"},
	{GOOS: "linux", GOARCH: "arm", GOARM: "6", Note: "Linux on ARMv6 — older Raspberry Pi, Zero"},
	{GOOS: "linux", GOARCH: "386", Note: "Linux 32-bit"},
	{GOOS: "linux", GOARCH: "riscv64", Note: "Linux on RISC-V"},
	{GOOS: "darwin", GOARCH: "amd64", Note: "macOS on Intel"},
	{GOOS: "darwin", GOARCH: "arm64", Note: "macOS on Apple Silicon (M1–M4)"},
	{GOOS: "windows", GOARCH: "amd64", Note: "Windows on Intel/AMD"},
	{GOOS: "windows", GOARCH: "arm64", Note: "Windows on ARM"},
	{GOOS: "freebsd", GOARCH: "amd64", Note: "FreeBSD"},
	{GOOS: "openbsd", GOARCH: "amd64", Note: "OpenBSD"},
	{GOOS: "netbsd", GOARCH: "amd64", Note: "NetBSD"},
}

func (t buildTarget) outName() string {
	name := fmt.Sprintf("%s-%s-%s", appName, t.GOOS, t.GOARCH)
	if t.GOARM != "" {
		name += "v" + t.GOARM
	}
	if t.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// goToolchain is a found or downloaded compiler.
type goToolchain struct {
	bin     string // path to the go binary
	goroot  string // empty if the system is used
	tmpDir  string // non-empty: remove after the build
	version string
}

func (tc *goToolchain) cleanup() {
	if tc != nil && tc.tmpDir != "" {
		_ = os.RemoveAll(tc.tmpDir)
	}
}

// findSystemGo looks for an installed compiler: first in PATH, then in the
// standard places used by distributions and the official installer.
func findSystemGo() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	candidates := []string{
		"/usr/local/go/bin/go",
		"/usr/lib/go/bin/go",
		"/usr/lib/golang/bin/go",
		"/opt/go/bin/go",
		"/usr/local/bin/go",
		"/snap/bin/go",
		"/opt/homebrew/bin/go",
		`C:\Program Files\Go\bin\go.exe`,
		`C:\Go\bin\go.exe`,
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "go", "bin", "go"+suffix),
			filepath.Join(home, ".local", "go", "bin", "go"+suffix),
			filepath.Join(home, "sdk", "go", "bin", "go"+suffix),
		)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

// goVersionFallback is used when go.dev cannot say which version is current.
const goVersionFallback = "go1.25.1"

// Where official Go releases are listed and downloaded (variables for tests).
var (
	goReleaseIndexURL = "https://go.dev/dl/?mode=json"
	goVersionURL      = "https://go.dev/VERSION?m=text"
	goDownloadBaseURL = "https://dl.google.com/go/"
)

// goArchive is one official Go archive and its published SHA-256.
type goArchive struct {
	Version  string
	Filename string
	SHA256   string
}

// latestGoVersion asks go.dev for the current stable version.
func latestGoVersion(client *http.Client) string {
	b, err := fetchSmall(client, goVersionURL, 256)
	if err != nil {
		return goVersionFallback
	}
	line := strings.TrimSpace(strings.SplitN(b, "\n", 2)[0])
	if !strings.HasPrefix(line, "go1.") {
		return goVersionFallback
	}
	return line
}

// goArchiveFor finds the newest stable Go archive for goos/goarch and its
// SHA-256: from go.dev's release list, otherwise from the .sha256 file
// published next to the archive. Without a checksum nothing is downloaded.
func goArchiveFor(client *http.Client, goos, goarch string) (*goArchive, error) {
	a, ierr := goArchiveFromIndex(client, goos, goarch)
	if ierr == nil {
		return a, nil
	}
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	arch := goarch
	if goos == "linux" && goarch == "arm" {
		arch = "armv6l" // the name go.dev uses for 32-bit ARM
	}
	ver := latestGoVersion(client)
	name := fmt.Sprintf("%s.%s-%s.%s", ver, goos, arch, ext)
	b, err := fetchSmall(client, goDownloadBaseURL+name+".sha256", 256)
	if err != nil {
		return nil, fmt.Errorf("no checksum for %s (release list: %v; %s.sha256: %v)", name, ierr, name, err)
	}
	sum := ""
	if f := strings.Fields(b); len(f) > 0 {
		sum = strings.ToLower(f[0])
	}
	if !isHexSHA256(sum) {
		return nil, fmt.Errorf("no checksum for %s (release list: %v; %s.sha256 is not a SHA-256)", name, ierr, name)
	}
	return &goArchive{Version: ver, Filename: name, SHA256: sum}, nil
}

// goArchiveFromIndex picks the archive from go.dev/dl/?mode=json (newest first).
func goArchiveFromIndex(client *http.Client, goos, goarch string) (*goArchive, error) {
	b, err := fetchSmall(client, goReleaseIndexURL, 8<<20)
	if err != nil {
		return nil, err
	}
	var releases []struct {
		Version string `json:"version"`
		Stable  bool   `json:"stable"`
		Files   []struct {
			Filename string `json:"filename"`
			OS       string `json:"os"`
			Arch     string `json:"arch"`
			SHA256   string `json:"sha256"`
			Kind     string `json:"kind"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(b), &releases); err != nil {
		return nil, fmt.Errorf("release list: %w", err)
	}
	for _, rel := range releases {
		if !rel.Stable {
			continue
		}
		for _, f := range rel.Files {
			if f.Kind != "archive" || f.OS != goos || !(f.Arch == goarch || goarch == "arm" && f.Arch == "armv6l") {
				continue
			}
			sum := strings.ToLower(f.SHA256)
			if !isHexSHA256(sum) || f.Filename == "" || strings.ContainsAny(f.Filename, `/\`) {
				continue
			}
			return &goArchive{Version: rel.Version, Filename: f.Filename, SHA256: sum}, nil
		}
	}
	return nil, fmt.Errorf("no stable Go archive for %s/%s in the release list", goos, goarch)
}

// fetchSmall returns the body of a 200 response, at most max bytes.
func fetchSmall(client *http.Client, u string, max int64) (string, error) {
	resp, err := client.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max))
	return string(b), err
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// downloadVerified saves u to dst and checks its SHA-256 before anything
// reads the file; on a mismatch the file is removed.
func downloadVerified(client *http.Client, u, dst, wantSHA256 string, max int64) error {
	resp, err := client.Get(u)
	if err != nil {
		return fmt.Errorf("download %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: response %s", u, resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if err := f.Close(); cerr == nil {
		cerr = err
	}
	switch {
	case cerr != nil:
		err = fmt.Errorf("download %s: %w", u, cerr)
	case n > max:
		err = fmt.Errorf("download %s: larger than %d bytes", u, max)
	default:
		if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(wantSHA256) {
			err = fmt.Errorf("download %s: SHA-256 %s, expected %s — file rejected", u, got, wantSHA256)
		}
	}
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}

// downloadGoToolchain downloads the official Go archive for this machine,
// verifies its SHA-256 and unpacks it into a temporary directory.
func downloadGoToolchain() (*goToolchain, error) {
	client, err := newOutboundClient(20 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("outbound HTTPS impossible: %w", err)
	}
	arc, err := goArchiveFor(client, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, fmt.Errorf("toolchain for %s/%s: %w", runtime.GOOS, runtime.GOARCH, err)
	}

	tmp, err := os.MkdirTemp("", appName+"-go-")
	if err != nil {
		return nil, err
	}
	tc := &goToolchain{tmpDir: tmp, version: arc.Version}

	const maxToolchain = 1 << 30 // 1 GB - with a large margin
	u := goDownloadBaseURL + arc.Filename
	archPath := filepath.Join(tmp, arc.Filename)
	fmt.Fprintf(os.Stderr, "  downloading %s (once, ~70–160 MB)\n", u)
	if err := downloadVerified(client, u, archPath, arc.SHA256, maxToolchain); err != nil {
		tc.cleanup()
		return nil, err
	}
	if strings.HasSuffix(arc.Filename, ".zip") {
		err = unpackZip(archPath, tmp, maxToolchain)
	} else {
		var f *os.File
		if f, err = os.Open(archPath); err == nil {
			_, err = unpackTarGz(f, tmp, maxToolchain)
			f.Close()
		}
	}
	if err != nil {
		tc.cleanup()
		return nil, fmt.Errorf("unpacking toolchain: %w", err)
	}
	_ = os.Remove(archPath)

	bin := filepath.Join(tmp, "go", "bin", "go")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		tc.cleanup()
		return nil, fmt.Errorf("unpacked archive has no %s", bin)
	}
	_ = os.Chmod(bin, 0o755)
	tc.bin = bin
	tc.goroot = filepath.Join(tmp, "go")
	return tc, nil
}

// unpackZip unpacks a zip archive without letting entries escape the directory.
func unpackZip(archive, dest string, maxBytes int64) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	var total int64
	files := 0
	for _, zf := range zr.File {
		clean := filepath.Clean(zf.Name)
		if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe path in archive: %s", zf.Name)
		}
		target := filepath.Join(destAbs, clean)
		if rel, err := filepath.Rel(destAbs, target); err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("unsafe path in archive: %s", zf.Name)
		}
		fi := zf.FileInfo()
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks in archive are forbidden: %s", zf.Name)
		}
		if fi.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if files >= 100000 {
			return errors.New("archive file count limit exceeded")
		}
		if err := ensureNoSymlinkComponents(destAbs, filepath.Dir(target)); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := ensureNoSymlinkComponents(destAbs, target); err != nil {
			return err
		}
		files++
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		mode := zf.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			rc.Close()
			return err
		}
		limit := maxBytes - total
		if limit <= 0 {
			out.Close()
			rc.Close()
			return errors.New("archive size limit exceeded")
		}
		n, err := io.Copy(out, io.LimitReader(rc, limit))
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

// ensureGoToolchain returns a compiler ready to use.
func ensureGoToolchain(allowDownload bool) (*goToolchain, error) {
	if bin := findSystemGo(); bin != "" {
		tc := &goToolchain{bin: bin, version: goToolVersion(bin)}
		fmt.Fprintf(os.Stderr, "  compiler: %s (%s)\n", bin, tc.version)
		return tc, nil
	}
	if !allowDownload {
		return nil, errors.New("Go compiler not found; drop -no-download to fetch a temporary copy")
	}
	fmt.Fprintln(os.Stderr, "  Go compiler not found on system — using a temporary copy")
	return downloadGoToolchain()
}

func goToolVersion(bin string) string {
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return "version unknown"
	}
	return strings.TrimSpace(string(out))
}

// hostRootsPEM collects the root certificate bundle of the build machine to
// bake it into the binary. It returns an empty slice if nothing is found.
func hostRootsPEM() []byte {
	for _, p := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/cert.pem",
		"/usr/local/etc/ssl/cert.pem",
		"/etc/ssl/ca-bundle.pem",
		"/opt/homebrew/etc/ca-certificates/cert.pem",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// Check that these are genuine certificates.
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(b) && len(pool.Subjects()) > 0 {
			return b
		}
	}
	return nil
}

// sourcePath determines where the source file is: first the path
// recorded by the compiler, then main.go next to the binary or in the
// working directory.
func sourcePath() string {
	if _, file, _, ok := runtime.Caller(0); ok && file != "" {
		if st, err := os.Stat(file); err == nil && !st.IsDir() {
			return file
		}
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	for _, d := range dirs {
		p := filepath.Join(d, "main.go")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	all := fs.Bool("all", false, "build for all supported platforms")
	outDir := fs.String("out", "dist", "directory for finished binaries")
	srcFlag := fs.String("src", "", "path to source (auto-detected by default)")
	goosFlag := fs.String("os", "", "target OS (linux, darwin, windows, freebsd, openbsd, netbsd)")
	goarchFlag := fs.String("arch", "", "target architecture (amd64, arm64, arm, 386, riscv64)")
	noDownload := fs.Bool("no-download", false, "do not download the compiler if it is missing")
	noRoots := fs.Bool("no-roots", false, "do not bake this machine's root certificates into the binary")
	keepDebug := fs.Bool("debug", false, "keep debug symbols (larger binary)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	src := *srcFlag
	if src == "" {
		src = sourcePath()
	}
	if src == "" {
		return errors.New("main.go source not found: pass it explicitly with -src")
	}
	src, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	if st, err := os.Stat(src); err != nil || st.IsDir() {
		return fmt.Errorf("source unavailable: %s", src)
	}

	targets := []buildTarget{}
	switch {
	case *all:
		targets = buildTargets
	case *goosFlag != "" || *goarchFlag != "":
		t := buildTarget{GOOS: *goosFlag, GOARCH: *goarchFlag, Note: "set manually"}
		if t.GOOS == "" {
			t.GOOS = runtime.GOOS
		}
		if t.GOARCH == "" {
			t.GOARCH = runtime.GOARCH
		}
		targets = append(targets, t)
	default:
		targets = append(targets, buildTarget{
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Note: "this machine",
		})
	}

	fmt.Fprintf(os.Stderr, "%s %s — build\n", appName, version)
	fmt.Fprintf(os.Stderr, "  source: %s\n", src)

	tc, err := ensureGoToolchain(!*noDownload)
	if err != nil {
		return err
	}
	defer tc.cleanup()

	ldflags := "-s -w"
	if *keepDebug {
		ldflags = ""
	}
	if !*noRoots {
		if pemBytes := hostRootsPEM(); len(pemBytes) > 0 {
			enc, err := encodeBakedRoots(pemBytes)
			if err == nil {
				pool := x509.NewCertPool()
				pool.AppendCertsFromPEM(pemBytes)
				fmt.Fprintf(os.Stderr, "  baking this machine's root certificates: %d certs, %s compressed\n",
					len(pool.Subjects()), humanBytes(int64(len(enc))))
				bakedRootsSrc = "package main\n\nfunc init() { bakedRoots = " + strconv.Quote(enc) + " }\n"
			}
		} else {
			fmt.Fprintln(os.Stderr, "  no root certificates found on this machine — "+
				"binary will build without them (outbound HTTPS will need \"webhost roots -import\")")
		}
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	// Cache and GOPATH in a temporary directory: HOME may not be set at all,
	// and the system cache may not be writable.
	work, err := os.MkdirTemp("", appName+"-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	fmt.Fprintf(os.Stderr, "\n  targets (%d):\n", len(targets))
	var failed []string
	for _, t := range targets {
		out := filepath.Join(*outDir, t.outName())
		label := t.GOOS + "/" + t.GOARCH
		if t.GOARM != "" {
			label += "v" + t.GOARM
		}
		fmt.Fprintf(os.Stderr, "    %-22s", label)

		stderr, err := runGoBuild(tc, t, ldflags, out, src, work)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR\n")
			if strings.TrimSpace(stderr) != "" {
				fmt.Fprintf(os.Stderr, "%s\n", indentLines(strings.TrimRight(stderr, "\n"), "      "))
			} else {
				fmt.Fprintf(os.Stderr, "      %v\n", err)
			}
			failed = append(failed, label)
			continue
		}
		size := int64(0)
		if st, err := os.Stat(out); err == nil {
			size = st.Size()
		}
		fmt.Fprintf(os.Stderr, "done  %-9s %s\n", humanBytes(size), t.Note)
	}

	if len(failed) > 0 {
		return fmt.Errorf("failed to build: %s", strings.Join(failed, ", "))
	}

	fmt.Fprintf(os.Stderr, "\n  binaries in %s\n", *outDir)
	if len(targets) == 1 && targets[0].GOOS == runtime.GOOS && targets[0].GOARCH == runtime.GOARCH {
		local := filepath.Join(*outDir, targets[0].outName())
		fmt.Fprintf(os.Stderr, "\nRun:\n  %s\n", local)
	} else {
		fmt.Fprintf(os.Stderr, "\nCopy the binary you need to the target machine and run it — "+
			"neither Go, internet, nor libc are required there.\n")
	}
	return nil
}

// bakedRootsSrc is generated Go source that sets bakedRoots (avoids E2BIG on
// Linux: a single argv element is limited to 128 KiB).
var bakedRootsSrc string

// runGoBuild runs the compiler for one target and returns its stderr:
// compilation errors should be shown as they are.
func runGoBuild(tc *goToolchain, t buildTarget, ldflags, out, src, work string) (string, error) {
	args := []string{"build", "-trimpath"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	files := []string{src}
	if bakedRootsSrc != "" {
		// "go build a.go b.go" requires both files in one directory.
		srcDir := filepath.Join(work, "src")
		if err := os.MkdirAll(srcDir, 0o755); err != nil {
			return "", err
		}
		mainCopy := filepath.Join(srcDir, "main.go")
		if err := copyFile(src, mainCopy, 0o644); err != nil {
			return "", err
		}
		gen := filepath.Join(srcDir, "zz_baked_roots.go")
		if err := os.WriteFile(gen, []byte(bakedRootsSrc), 0o644); err != nil {
			return "", err
		}
		files = []string{mainCopy, gen}
	}
	args = append(args, "-o", out)
	args = append(args, files...)

	cmd := exec.Command(tc.bin, args...)
	cmd.Dir = filepath.Dir(src)

	env := []string{
		"CGO_ENABLED=0",
		"GOOS=" + t.GOOS,
		"GOARCH=" + t.GOARCH,
		"GOCACHE=" + filepath.Join(work, "gocache"),
		"GOPATH=" + filepath.Join(work, "gopath"),
		"GOMODCACHE=" + filepath.Join(work, "gomodcache"),
		// Do not let the toolchain go online to fetch another version of itself.
		"GOTOOLCHAIN=local",
		// There are no dependencies outside the stdlib, so the build needs no network.
		"GOFLAGS=",
		"GOPROXY=off",
		"GOWORK=off",
		// The base instruction set is set explicitly, not left to chance.
		// GOAMD64=v1 is plain x86-64 without SSE4/AVX/AVX2: the binary
		// runs on any Intel or AMD CPU, including those from 2005.
		// Built with v3, it would die with SIGILL on a machine without AVX2.
		// The value is set here, not taken from the build machine's environment.
		"GOAMD64=v1",
		"GO386=sse2",
	}
	if t.GOARM != "" {
		env = append(env, "GOARM="+t.GOARM)
	}
	if tc.goroot != "" {
		env = append(env, "GOROOT="+tc.goroot)
	}
	// The toolchain itself needs only PATH and HOME (and their Windows
	// counterparts); nothing else is inherited, so GOFLAGS/GO111MODULE cannot change the result.
	for _, k := range []string{"PATH", "HOME", "USERPROFILE", "SystemRoot", "TMP", "TEMP", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	cmd.Env = env

	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	cmd.Stdout = io.Discard
	err := cmd.Run()
	return errBuf.String(), err
}

func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

// cmdRoots manages the trusted root certificates.
func cmdRoots(args []string) error {
	fs := flag.NewFlagSet("roots", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDataDir(), "config.json"), "path to config.json")
	importPath := fs.String("import", "", "copy a PEM bundle into the data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := filepath.Dir(*cfgPath)
	dst := filepath.Join(dataDir, "certs", "roots.pem")

	if *importPath != "" {
		b, err := os.ReadFile(*importPath)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) || len(pool.Subjects()) == 0 {
			return fmt.Errorf("no parseable PEM certificates in %s", *importPath)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return err
		}
		fmt.Printf("imported certificates: %d\nfile: %s\n", len(pool.Subjects()), dst)
		return nil
	}

	if b, err := os.ReadFile(dst); err == nil {
		extraRootsPath.Store(dst)
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(b)
		fmt.Printf("imported bundle: %s (%d certificates)\n", dst, len(pool.Subjects()))
	}
	if bakedRoots != "" {
		if pemBytes, err := decodeBakedRoots(bakedRoots); err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(pemBytes)
			fmt.Printf("baked in at build time: %d certificates\n", len(pool.Subjects()))
		}
	}
	pool, from, err := rootPool()
	if err != nil {
		fmt.Printf("summary: no trusted roots\n\n%v\n", err)
		return nil
	}
	fmt.Printf("summary: trusted roots: %s\n", describeRoots(pool, from))
	if !systemHasResolvConf() {
		fmt.Printf("DNS: no /etc/resolv.conf on system, custom resolver will be used (%s)\n",
			strings.Join(publicResolvers, " "))
	}
	return nil
}
