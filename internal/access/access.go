// Package access decides whether a verified LinkKeys identity may use
// Grafana, and with which role.
package access

import (
	"strings"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/config"
)

// Identity is a LinkKeys identity that the login flow verified.
type Identity struct {
	UserID      string
	Domain      string
	Handle      string
	DisplayName string
	Email       string
}

// Subject returns "<user-id>@<domain>".
func (i Identity) Subject() string { return i.UserID + "@" + i.Domain }

// HandleLogin returns "<handle>@<domain>", or "" when the identity has no
// handle claim.
func (i Identity) HandleLogin() string {
	if i.Handle == "" {
		return ""
	}
	return i.Handle + "@" + i.Domain
}

// Policy is the allow list from the configuration.
type Policy struct {
	users   []config.UserRule
	domains []config.DomainRule
}

// NewPolicy builds a Policy from the configuration.
func NewPolicy(cfg config.AccessConfig) *Policy {
	return &Policy{users: cfg.Users, domains: cfg.Domains}
}

// AllowsDomain reports whether any rule can allow an account of domain.
// The server checks this before it starts a login, so that an
// unauthenticated client cannot make the proxy contact any other domain.
func (p *Policy) AllowsDomain(domain string) bool {
	if domain == "" {
		return false
	}
	for _, u := range p.users {
		if _, d, ok := strings.Cut(u.Identity, "@"); ok && strings.EqualFold(d, domain) {
			return true
		}
	}
	for _, d := range p.domains {
		if strings.EqualFold(d.Domain, domain) {
			return true
		}
	}
	return false
}

// Decide returns the Grafana role for id. ok is false when no rule allows
// id. User rules take precedence over domain rules. Matching ignores ASCII
// case.
func (p *Policy) Decide(id Identity) (role string, ok bool) {
	if id.UserID == "" || id.Domain == "" {
		return "", false
	}
	subject := id.Subject()
	handle := id.HandleLogin()
	for _, u := range p.users {
		if strings.EqualFold(u.Identity, subject) || (handle != "" && strings.EqualFold(u.Identity, handle)) {
			return u.Role, true
		}
	}
	for _, d := range p.domains {
		if strings.EqualFold(d.Domain, id.Domain) {
			return d.Role, true
		}
	}
	return "", false
}
