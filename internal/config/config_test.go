package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

const minimal = `
public_url: https://grafana.example.lan
identity_file: /var/lib/grafana-linkkeys-login/identity
access:
  domains:
    - domain: example.com
      role: Viewer
`

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:3001" || cfg.Upstream != "http://127.0.0.1:3000" || cfg.GrafanaUsername != UsernameSubject {
		t.Fatalf("defaults = %+v", cfg)
	}
	if time.Duration(cfg.Session.TTL) != 12*time.Hour || time.Duration(cfg.Session.LoginTimeout) != 5*time.Minute {
		t.Fatalf("session defaults = %+v", cfg.Session)
	}
	if cfg.Headers.User != "X-WEBAUTH-USER" || cfg.Headers.Role != "X-WEBAUTH-ROLE" {
		t.Fatalf("header defaults = %+v", cfg.Headers)
	}
	if !cfg.SecureCookies() || cfg.PublicOrigin() != "https://grafana.example.lan" {
		t.Fatal("origin helpers wrong")
	}
}

func TestDurationsAndTrailingSlash(t *testing.T) {
	cfg, err := Parse([]byte(strings.Replace(minimal, "grafana.example.lan", "grafana.example.lan/", 1) + `
session:
  ttl: 8h
  login_timeout: 2m
`))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(cfg.Session.TTL) != 8*time.Hour || time.Duration(cfg.Session.LoginTimeout) != 2*time.Minute {
		t.Fatalf("session = %+v", cfg.Session)
	}
	if cfg.PublicOrigin() != "https://grafana.example.lan" {
		t.Fatalf("origin = %q", cfg.PublicOrigin())
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want string
	}{
		"no public_url":    {`identity_file: x` + "\naccess: {domains: [{domain: a.b, role: Viewer}]}", "public_url is required"},
		"public_url path":  {strings.Replace(minimal, "grafana.example.lan", "grafana.example.lan/grafana", 1), "origin only"},
		"public_url query": {strings.Replace(minimal, "grafana.example.lan", "grafana.example.lan?x=1", 1), "origin only"},
		"bad scheme":       {strings.Replace(minimal, "https://", "ftp://", 1), "https or http"},
		"no identity":      {strings.Replace(minimal, "identity_file: /var/lib/grafana-linkkeys-login/identity", "", 1), "identity_file is required"},
		"bad mode":         {minimal + "mode: oidc\n", "mode must be"},
		"no access rules":  {"public_url: https://g.lan\nidentity_file: x\n", "at least one user or domain"},
		"bad role":         {strings.Replace(minimal, "Viewer", "GrafanaAdmin", 1), "Viewer, Editor, or Admin"},
		"bad user":         {minimal + "  users:\n    - identity: alice\n      role: Viewer\n", "access.users[0].identity"},
		"bad username":     {minimal + "grafana_username: email\n", "grafana_username"},
		"short ttl":        {minimal + "session:\n  ttl: 10s\n", "session.ttl"},
		"long login":       {minimal + "session:\n  login_timeout: 1h\n", "login_timeout"},
		"bad duration":     {minimal + "session:\n  ttl: forever\n", "invalid duration"},
		"unknown field":    {minimal + "listen_addr: x\n", "listen_addr"},
		"bad header":       {minimal + "headers:\n  user: \"X-A: b\"\n", "headers.user"},
		"bad upstream":     {minimal + "upstream: grafana:3000\n", "upstream"},
		"bad proxy range":  {minimal + "trusted_proxies: [127.0.0.1]\n", "trusted_proxies[0]"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestTrustedProxies(t *testing.T) {
	cfg, err := Parse([]byte(minimal + "trusted_proxies: [127.0.0.1/32, \"::1/128\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{"127.0.0.1": true, "::1": true, "::ffff:127.0.0.1": true, "127.0.0.2": false, "10.0.0.1": false} {
		if got := cfg.IsTrustedProxy(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsTrustedProxy(%s) = %v, want %v", addr, got, want)
		}
	}
}

const rpMinimal = `
mode: rp
public_url: https://grafana.example.com
rp:
  domain: Example.COM.
  address: linkkeys.example.com:4987
  fingerprints: [F486F22974580F3ED16E32758A8742320BB4A0C69D7D4971DE82AD179D6043CD]
  api_key_file: /etc/grafana-linkkeys-login/rp-api-key
access:
  domains:
    - domain: example.com
      role: Viewer
`

func TestRPMode(t *testing.T) {
	cfg, err := Parse([]byte(rpMinimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeRP || cfg.RP.Domain != "example.com" || cfg.RP.Fingerprints[0] != "f486f22974580f3ed16e32758a8742320bb4a0c69d7d4971de82ad179d6043cd" {
		t.Fatalf("rp = %+v", cfg.RP)
	}
	if _, err := Parse([]byte(strings.Replace(rpMinimal, "grafana.example.com", "grafana.example.org", 1))); err != nil {
		t.Fatalf("public_url off the RP domain refused: %v", err)
	}
}

func TestRPModeValidation(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"http":            {"https://grafana", "http://grafana", "public_url must use https"},
		"bad domain":      {"Example.COM.", "example", "rp.domain"},
		"no port":         {"linkkeys.example.com:4987", "linkkeys.example.com", "rp.address"},
		"bad fingerprint": {"F486F22974580F3ED16E32758A8742320BB4A0C69D7D4971DE82AD179D6043CD", "abc", "rp.fingerprints[0]"},
		"no fingerprints": {"[F486F22974580F3ED16E32758A8742320BB4A0C69D7D4971DE82AD179D6043CD]", "[]", "at least one fingerprint"},
		"no key file":     {"api_key_file: /etc/grafana-linkkeys-login/rp-api-key", "", "rp.api_key_file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(rpMinimal, tc.from, tc.to, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	if _, err := Parse([]byte(rpMinimal + "  dial_address: nope\n")); err == nil {
		t.Fatal("bad dial_address accepted")
	}
}
