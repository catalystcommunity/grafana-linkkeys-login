// Package config loads and validates the grafana-linkkeys-login YAML
// configuration file.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
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
	// IdentityFile holds this proxy's LinkKeys local-RP key material. Treat
	// it as a secret. Create it with the init-identity command.
	IdentityFile string `yaml:"identity_file"`
	// AppName is the display name that init-identity writes into a new
	// identity. LinkKeys shows it on the consent screen as unverified text.
	AppName string `yaml:"app_name"`
	// DefaultDomain is added to a login that has no domain, so a user can
	// type "alice" instead of "alice@example.com".
	DefaultDomain string `yaml:"default_domain"`
	// GrafanaUsername selects the Grafana username format: "subject"
	// (default) or "handle".
	GrafanaUsername string `yaml:"grafana_username"`

	Session SessionConfig `yaml:"session"`
	Access  AccessConfig  `yaml:"access"`
	Headers HeaderConfig  `yaml:"headers"`
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

	if c.IdentityFile == "" {
		errs = append(errs, errors.New("identity_file is required"))
	}

	if c.GrafanaUsername != UsernameSubject && c.GrafanaUsername != UsernameHandle {
		errs = append(errs, fmt.Errorf("grafana_username must be %q or %q", UsernameSubject, UsernameHandle))
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

func validRole(r string) bool {
	return r == RoleViewer || r == RoleEditor || r == RoleAdmin
}

// PublicOrigin returns PublicURL without a trailing slash.
func (c *Config) PublicOrigin() string {
	return strings.TrimSuffix(c.PublicURL, "/")
}

// SecureCookies reports whether cookies must carry the Secure attribute.
func (c *Config) SecureCookies() bool {
	return strings.HasPrefix(c.PublicURL, "https://")
}
