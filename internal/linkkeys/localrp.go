// Package linkkeys connects the proxy to LinkKeys: a local-RP identity, or
// an RP server.
package linkkeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/access"
)

// Backend runs the two halves of a LinkKeys login.
type Backend interface {
	// Begin starts a login for "[handle@]domain". It returns the URL to send
	// the browser to and opaque state to keep until the callback.
	Begin(ctx context.Context, selector, callbackURL string) (redirectURL string, pending []byte, err error)
	// Complete verifies the callback that arrived at arrivedURL.
	Complete(ctx context.Context, pending []byte, arrivedURL string) (access.Identity, error)
}

// LocalRP is a Backend that uses a DNS-less local-RP identity.
type LocalRP struct {
	identity *localrp.LocalRpKeyMaterial
	now      func() time.Time
}

// NewLocalRP returns a LocalRP for identity.
func NewLocalRP(identity *localrp.LocalRpKeyMaterial) *LocalRP {
	return &LocalRP{identity: identity, now: time.Now}
}

// Fingerprint is the value that a LinkKeys domain admin approves.
func (b *LocalRP) Fingerprint() string { return b.identity.Fingerprint }

// Begin implements Backend.
func (b *LocalRP) Begin(_ context.Context, selector, callbackURL string) (string, []byte, error) {
	redirect, pending, err := localrp.BeginLocalLogin(localrp.BeginLocalLoginConfig{
		KeyMaterial: b.identity,
		CallbackURL: callbackURL,
		UserDomain:  selector,
		Now:         b.now(),
	})
	if err != nil {
		return "", nil, fmt.Errorf("begin local-rp login: %w", err)
	}
	blob, err := json.Marshal(pending)
	if err != nil {
		return "", nil, fmt.Errorf("encode pending login: %w", err)
	}
	return redirect.RedirectURL, blob, nil
}

// Complete implements Backend.
func (b *LocalRP) Complete(_ context.Context, pendingBlob []byte, arrivedURL string) (access.Identity, error) {
	var pending localrp.PendingLogin
	if err := json.Unmarshal(pendingBlob, &pending); err != nil {
		return access.Identity{}, fmt.Errorf("decode pending login: %w", err)
	}
	u, err := url.Parse(arrivedURL)
	if err != nil {
		return access.Identity{}, fmt.Errorf("parse callback URL: %w", err)
	}
	token := u.Query().Get("encrypted_token")
	if token == "" {
		return access.Identity{}, errors.New("callback URL has no encrypted_token")
	}
	verified, err := localrp.CompleteLocalLogin(localrp.CompleteLocalLoginConfig{
		KeyMaterial:    b.identity,
		Pending:        &pending,
		EncryptedToken: token,
		ArrivedURL:     arrivedURL,
		Now:            b.now(),
	})
	if err != nil {
		return access.Identity{}, fmt.Errorf("complete local-rp login: %w", err)
	}
	return identityFromClaims(verified.UserID, verified.UserDomain, verified.Claims), nil
}

// identityFromClaims maps verified claims to an Identity. The SDK has
// already verified every claim signature.
func identityFromClaims(userID, domain string, claims []api.Claim) access.Identity {
	id := access.Identity{UserID: userID, Domain: domain}
	for _, c := range claims {
		switch c.ClaimType {
		case "handle":
			id.Handle = string(c.ClaimValue)
		case "display_name":
			id.DisplayName = string(c.ClaimValue)
		case "email":
			id.Email = string(c.ClaimValue)
		}
	}
	return id
}

// LoadIdentity reads key material that CreateIdentity wrote.
func LoadIdentity(path string) (*localrp.LocalRpKeyMaterial, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("identity file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("identity file %s is readable by group or others (mode %v); run chmod 600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity file: %w", err)
	}
	identity, err := localrp.LocalRpIdentityFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("identity file %s is not valid local-RP key material: %w", path, err)
	}
	return identity, nil
}

// CreateIdentity generates new key material and writes it to path with mode
// 0600. It refuses to replace an existing file, because a new identity needs
// a new approval at every LinkKeys domain.
func CreateIdentity(path, appName string, now time.Time) (*localrp.LocalRpKeyMaterial, error) {
	identity, err := localrp.GenerateLocalRpIdentity(localrp.GenerateLocalRpIdentityConfig{AppName: appName, Now: now})
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create identity file: %w", err)
	}
	if _, err := f.Write(localrp.LocalRpIdentityToBytes(identity)); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write identity file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("write identity file: %w", err)
	}
	return identity, nil
}

// ExpiryStatus reports how close identity is to expiry.
func ExpiryStatus(identity *localrp.LocalRpKeyMaterial, now time.Time) (level string, expiresAt time.Time, err error) {
	status, err := localrp.CheckExpirations(identity, now)
	if err != nil {
		return "", time.Time{}, err
	}
	return string(status.Level), status.ExpiresAt, nil
}

// Expired is the level ExpiryStatus returns for an expired identity.
const Expired = string(localrp.ExpirationExpired)
