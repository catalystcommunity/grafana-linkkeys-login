// Package config loads and validates the grafana-linkkeys-login YAML
// configuration file.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Grafana organization roles that the auth proxy can assign.
const (
	RoleViewer = "Viewer"
	RoleEditor = "Editor"
	RoleAdmin  = "Admin"
)

// Values for Mode.
const (
	// ModeLocalRP uses a DNS-less local-RP identity. Each LinkKeys domain
	// admin approves its fingerprint.
	ModeLocalRP = "local-rp"
	// ModeRP uses a LinkKeys RP server. The proxy is an application of the
	// RP domain and authenticates to the RP server with an API key.
	ModeRP = "rp"
)

// Values for GrafanaUsername.
const (
	// UsernameSubject sends "<user-id>@<domain>". The user id never changes,
	// so a Grafana account always belongs to the same LinkKeys account.
	UsernameSubject = "subject"
	// UsernameHandle sends "<handle>@<domain>". This is easier to read, but
	// a domain can give a released handle to a different account.
	UsernameHandle = "handle"
)

// Duration is a time.Duration that decodes from a Go duration string such as
// "12h" or "30m".
type Duration time.Duration

// UnmarshalYAML decodes a duration string.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string such as \"12h\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Config is the complete configuration file.
type Config struct {
	// Listen is the address the proxy listens on.
	Listen string `yaml:"listen"`
	// PublicURL is the origin that browsers use to reach the proxy, for
	// example "https://grafana.example.lan". The LinkKeys callback URL is
	// built from it, and the callback is verified against it, so it must
	// match what the browser sees exactly. It must not have a path.
	PublicURL string `yaml:"public_url"`
	// Upstream is the Grafana base URL. Grafana must not be reachable by
	// anything except this proxy.
	Upstream string `yaml:"upstream"`
	// Mode is "local-rp" (default) or "rp".
	Mode string `yaml:"mode"`
	// IdentityFile holds this proxy's LinkKeys local-RP key material. Treat
	// it as a secret. Create it with the init-identity command. Local-RP
	// mode only.
	IdentityFile string `yaml:"identity_file"`
	// RP configures the RP server. RP mode only.
	RP RPConfig `yaml:"rp"`
	// AppName is the display name that init-identity writes into a new
	// identity. LinkKeys shows it on the consent screen as unverified text.
	AppName string `yaml:"app_name"`
	// DefaultDomain is added to a login that has no domain, so a user can
	// type "alice" instead of "alice@example.com".
	DefaultDomain string `yaml:"default_domain"`
	// GrafanaUsername selects the Grafana username format: "subject"
	// (default) or "handle".
	GrafanaUsername string `yaml:"grafana_username"`
	// TrustedProxies are the CIDR ranges of reverse proxies in front of this
	// proxy, for example Caddy on 127.0.0.1/32. The client address for rate
	// limits comes from X-Forwarded-For only when the connection comes from
	// one of these ranges. Empty means the connection address is used.
	TrustedProxies []string `yaml:"trusted_proxies"`

	trustedPrefixes []netip.Prefix

	Session SessionConfig `yaml:"session"`
	Access  AccessConfig  `yaml:"access"`
	Headers HeaderConfig  `yaml:"headers"`
}

// RPConfig is the connection to the LinkKeys RP server in RP mode.
type RPConfig struct {
	// Domain is the RP domain, for example "example.com". It is the
	// audience of every assertion.
	Domain string `yaml:"domain"`
	// Address is the RP server's CSIL-RPC TCP endpoint, "host:port". The
	// host is also the TLS server name.
	Address string `yaml:"address"`
	// DialAddress is an optional "host:port" to connect to instead of
	// Address, for example a gateway on the LAN. TLS still uses the host of
	// Address as the server name, and the fingerprints still apply.
	DialAddress string `yaml:"dial_address"`
	// Fingerprints are the SHA-256 hex fingerprints of the RP server's TLS
	// keys. They are the trust anchor; there is no certificate authority.
	// Use the fp= values of the _linkkeys.<domain> TXT record.
	Fingerprints []string `yaml:"fingerprints"`
	// APIKeyFile holds the RP API key. The file mode must be 0600.
	APIKeyFile string `yaml:"api_key_file"`
}

// SessionConfig controls proxy sessions.
type SessionConfig struct {
	// TTL is the fixed session lifetime. Default 12h.
	TTL Duration `yaml:"ttl"`
	// LoginTimeout is how long a started login stays valid. Default 5m.
	LoginTimeout Duration `yaml:"login_timeout"`
}

// AccessConfig is the allow list. A login that matches no rule is refused.
type AccessConfig struct {
	Users   []UserRule   `yaml:"users"`
	Domains []DomainRule `yaml:"domains"`
}

// UserRule allows one LinkKeys account.
type UserRule struct {
	// Identity is "<handle>@<domain>" or "<user-id>@<domain>".
	Identity string `yaml:"identity"`
	Role     string `yaml:"role"`
}

// DomainRule allows every account of one LinkKeys domain.
type DomainRule struct {
	Domain string `yaml:"domain"`
	Role   string `yaml:"role"`
}

// HeaderConfig names the headers that Grafana's [auth.proxy] reads. The
// proxy removes these headers from every incoming request.
type HeaderConfig struct {
	User  string `yaml:"user"`
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
	Role  string `yaml:"role"`
}

// Load reads, defaults, and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse defaults and validates configuration bytes.
func Parse(raw []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:3001"
	}
	if c.Upstream == "" {
		c.Upstream = "http://127.0.0.1:3000"
	}
	if c.AppName == "" {
		c.AppName = "Grafana"
	}
	if c.GrafanaUsername == "" {
		c.GrafanaUsername = UsernameSubject
	}
	if c.Mode == "" {
		c.Mode = ModeLocalRP
	}
	c.RP.Domain = strings.TrimSuffix(strings.ToLower(c.RP.Domain), ".")
	for i, fp := range c.RP.Fingerprints {
		c.RP.Fingerprints[i] = strings.ToLower(fp)
	}
	if c.Session.TTL == 0 {
		c.Session.TTL = Duration(12 * time.Hour)
	}
	if c.Session.LoginTimeout == 0 {
		c.Session.LoginTimeout = Duration(5 * time.Minute)
	}
	if c.Headers.User == "" {
		c.Headers.User = "X-WEBAUTH-USER"
	}
	if c.Headers.Name == "" {
		c.Headers.Name = "X-WEBAUTH-NAME"
	}
	if c.Headers.Email == "" {
		c.Headers.Email = "X-WEBAUTH-EMAIL"
	}
	if c.Headers.Role == "" {
		c.Headers.Role = "X-WEBAUTH-ROLE"
	}
}

func (c *Config) validate() error {
	var errs []error

	if c.PublicURL == "" {
		errs = append(errs, errors.New("public_url is required"))
	} else if u, err := url.Parse(c.PublicURL); err != nil {
		errs = append(errs, fmt.Errorf("public_url: %w", err))
	} else {
		if u.Scheme != "https" && u.Scheme != "http" {
			errs = append(errs, errors.New("public_url must use https or http"))
		}
		if u.Host == "" {
			errs = append(errs, errors.New("public_url must have a host"))
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			errs = append(errs, errors.New("public_url must be an origin only (no path, query, fragment, or user info)"))
		}
	}

	if u, err := url.Parse(c.Upstream); err != nil {
		errs = append(errs, fmt.Errorf("upstream: %w", err))
	} else if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, errors.New("upstream must be an http or https URL with a host"))
	}

	switch c.Mode {
	case ModeLocalRP:
		if c.IdentityFile == "" {
			errs = append(errs, errors.New("identity_file is required in local-rp mode"))
		}
	case ModeRP:
		errs = append(errs, c.validateRP()...)
	default:
		errs = append(errs, fmt.Errorf("mode must be %q or %q", ModeLocalRP, ModeRP))
	}

	if c.GrafanaUsername != UsernameSubject && c.GrafanaUsername != UsernameHandle {
		errs = append(errs, fmt.Errorf("grafana_username must be %q or %q", UsernameSubject, UsernameHandle))
	}

	c.trustedPrefixes = nil
	for i, p := range c.TrustedProxies {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("trusted_proxies[%d] must be a CIDR range such as 127.0.0.1/32: %w", i, err))
			continue
		}
		c.trustedPrefixes = append(c.trustedPrefixes, prefix.Masked())
	}

	if time.Duration(c.Session.TTL) < time.Minute {
		errs = append(errs, errors.New("session.ttl must be at least 1m"))
	}
	if lt := time.Duration(c.Session.LoginTimeout); lt < 30*time.Second || lt > 15*time.Minute {
		errs = append(errs, errors.New("session.login_timeout must be between 30s and 15m"))
	}

	if len(c.Access.Users) == 0 && len(c.Access.Domains) == 0 {
		errs = append(errs, errors.New("access must allow at least one user or domain; the proxy refuses every login without a rule"))
	}
	for i, u := range c.Access.Users {
		local, domain, ok := strings.Cut(u.Identity, "@")
		if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
			errs = append(errs, fmt.Errorf("access.users[%d].identity must be <handle>@<domain> or <user-id>@<domain>", i))
		}
		if !validRole(u.Role) {
			errs = append(errs, fmt.Errorf("access.users[%d].role must be Viewer, Editor, or Admin", i))
		}
	}
	for i, d := range c.Access.Domains {
		if d.Domain == "" || strings.Contains(d.Domain, "@") {
			errs = append(errs, fmt.Errorf("access.domains[%d].domain must be a domain name", i))
		}
		if !validRole(d.Role) {
			errs = append(errs, fmt.Errorf("access.domains[%d].role must be Viewer, Editor, or Admin", i))
		}
	}

	for name, h := range map[string]string{"user": c.Headers.User, "name": c.Headers.Name, "email": c.Headers.Email, "role": c.Headers.Role} {
		if strings.ContainsAny(h, " :\t\r\n") {
			errs = append(errs, fmt.Errorf("headers.%s is not a valid header name", name))
		}
	}

	return errors.Join(errs...)
}

var (
	domainPattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (c *Config) validateRP() []error {
	var errs []error
	if !domainPattern.MatchString(c.RP.Domain) {
		errs = append(errs, errors.New("rp.domain must be a DNS domain such as example.com"))
	}
	if u, err := url.Parse(c.PublicURL); err == nil && u.Host != "" && u.Scheme != "https" {
		errs = append(errs, errors.New("public_url must use https in rp mode"))
	}
	for name, addr := range map[string]string{"rp.address": c.RP.Address, "rp.dial_address": c.RP.DialAddress} {
		if addr == "" && name == "rp.dial_address" {
			continue
		}
		if host, port, err := net.SplitHostPort(addr); err != nil || host == "" || port == "" {
			errs = append(errs, fmt.Errorf("%s must be host:port", name))
		}
	}
	if len(c.RP.Fingerprints) == 0 {
		errs = append(errs, errors.New("rp.fingerprints must list at least one fingerprint"))
	}
	for i, fp := range c.RP.Fingerprints {
		if !fingerprintPattern.MatchString(fp) {
			errs = append(errs, fmt.Errorf("rp.fingerprints[%d] must be 64 hex characters", i))
		}
	}
	if c.RP.APIKeyFile == "" {
		errs = append(errs, errors.New("rp.api_key_file is required in rp mode"))
	}
	return errs
}

func validRole(r string) bool {
	return r == RoleViewer || r == RoleEditor || r == RoleAdmin
}

// PublicOrigin returns PublicURL without a trailing slash.
func (c *Config) PublicOrigin() string {
	return strings.TrimSuffix(c.PublicURL, "/")
}

// IsTrustedProxy reports whether addr is in TrustedProxies.
func (c *Config) IsTrustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range c.trustedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// SecureCookies reports whether cookies must carry the Secure attribute.
func (c *Config) SecureCookies() bool {
	return strings.HasPrefix(c.PublicURL, "https://")
}
