package access

import (
	"testing"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/config"
)

func TestDecide(t *testing.T) {
	p := NewPolicy(config.AccessConfig{
		Users: []config.UserRule{
			{Identity: "alice@example.com", Role: config.RoleAdmin},
			{Identity: "u-42@other.example", Role: config.RoleEditor},
		},
		Domains: []config.DomainRule{{Domain: "example.com", Role: config.RoleViewer}},
	})
	cases := []struct {
		name string
		id   Identity
		role string
		ok   bool
	}{
		{"user rule by handle", Identity{UserID: "u-1", Domain: "example.com", Handle: "alice"}, config.RoleAdmin, true},
		{"user rule ignores case", Identity{UserID: "u-1", Domain: "EXAMPLE.com", Handle: "Alice"}, config.RoleAdmin, true},
		{"user rule by subject", Identity{UserID: "u-42", Domain: "other.example"}, config.RoleEditor, true},
		{"domain rule", Identity{UserID: "u-2", Domain: "example.com", Handle: "bob"}, config.RoleViewer, true},
		{"other domain refused", Identity{UserID: "u-3", Domain: "evil.example", Handle: "alice"}, "", false},
		{"handle from other domain does not match", Identity{UserID: "u-4", Domain: "other.example", Handle: "alice"}, "", false},
		{"empty identity refused", Identity{}, "", false},
		{"missing user id refused", Identity{Domain: "example.com", Handle: "alice"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			role, ok := p.Decide(tc.id)
			if role != tc.role || ok != tc.ok {
				t.Fatalf("Decide = %q, %v; want %q, %v", role, ok, tc.role, tc.ok)
			}
		})
	}
}

func TestEmptyPolicyRefusesEveryone(t *testing.T) {
	p := NewPolicy(config.AccessConfig{})
	if _, ok := p.Decide(Identity{UserID: "u", Domain: "example.com"}); ok {
		t.Fatal("empty policy allowed a login")
	}
	if p.AllowsDomain("example.com") {
		t.Fatal("empty policy allowed a domain")
	}
}

func TestAllowsDomain(t *testing.T) {
	p := NewPolicy(config.AccessConfig{
		Users:   []config.UserRule{{Identity: "alice@users.example", Role: config.RoleAdmin}},
		Domains: []config.DomainRule{{Domain: "example.com", Role: config.RoleViewer}},
	})
	for domain, want := range map[string]bool{
		"example.com":   true,
		"EXAMPLE.COM":   true,
		"users.example": true,
		"evil.example":  false,
		"":              false,
	} {
		if got := p.AllowsDomain(domain); got != want {
			t.Errorf("AllowsDomain(%q) = %v, want %v", domain, got, want)
		}
	}
}
