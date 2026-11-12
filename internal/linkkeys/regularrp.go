package linkkeys

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	localapi "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
	regularrp "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go"
	rpapi "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/access"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/config"
)

const (
	// clockSkew is the tolerance for assertion issue times.
	clockSkew = time.Minute
	// maxEncryptedToken limits the callback token before it goes to the
	// RP server.
	maxEncryptedToken = 64 * 1024
	// maxSignerDomains limits the domains whose keys one login fetches.
	maxSignerDomains = 8
)

// requestedClaims is the claim request for every RP login. The handle is
// required because access rules can name "<handle>@<domain>". A claim that
// the proxy depends on must be required: LinkKeys silent consent never
// releases a new optional claim.
func requestedClaims() *rpapi.ClaimRequest {
	return &rpapi.ClaimRequest{
		Required: []rpapi.RequestedClaim{{ClaimType: "handle", Datatype: "text"}},
		Optional: []rpapi.RequestedClaim{
			{ClaimType: "display_name", Datatype: "text"},
			{ClaimType: "email", Datatype: "text"},
		},
	}
}

// RPOperations are the RP server calls that a login uses. The generated
// *rpapi.RpClient implements it; tests use a fake.
type RPOperations interface {
	SignRequest(ctx context.Context, req rpapi.RpSignRequest) (rpapi.RpSignResponse, error)
	DecryptToken(ctx context.Context, req rpapi.RpDecryptRequest) (rpapi.RpDecryptResponse, error)
	VerifyAssertion(ctx context.Context, req rpapi.RpVerifyRequest) (rpapi.RpVerifyResponse, error)
	UserinfoFetch(ctx context.Context, req rpapi.RpUserInfoRequest) (rpapi.UserInfo, error)
}

// DomainKeyFetcher returns the trusted signing keys of a domain, after DNS
// pinning and revocation checks.
type DomainKeyFetcher func(ctx context.Context, domain string) ([]localapi.DomainPublicKey, error)

// RegularRP is a Backend that uses a LinkKeys RP server. The proxy is an
// application of the RP domain.
type RegularRP struct {
	rpDomain  string
	rp        RPOperations
	dns       localrp.DnsResolver
	fetchKeys DomainKeyFetcher
	now       func() time.Time
	log       *slog.Logger
}

// rpPending is the state that a login keeps until its callback.
type rpPending struct {
	Nonce      string `json:"nonce"`
	UserDomain string `json:"user_domain"`
	APIBase    string `json:"api_base"`
}

// NewRegularRP connects to the RP server that cfg names. It reads the API
// key from cfg.APIKeyFile.
func NewRegularRP(cfg config.RPConfig, log *slog.Logger) (*RegularRP, error) {
	apiKey, err := LoadAPIKey(cfg.APIKeyFile)
	if err != nil {
		return nil, err
	}
	opts := regularrp.PinnedRpcTransportOptions{
		TCPAddress:   cfg.Address,
		Fingerprints: cfg.Fingerprints,
		APIKey:       apiKey,
	}
	if cfg.DialAddress != "" {
		dialAddr := cfg.DialAddress
		var d net.Dialer
		opts.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, dialAddr)
		}
	}
	transport, err := regularrp.NewPinnedRpcTransport(opts)
	if err != nil {
		return nil, fmt.Errorf("RP transport: %w", err)
	}
	dns := localrp.DefaultDNSResolver()
	client := rpapi.NewRpClient(transport)
	b := newRegularRP(cfg.Domain, client, dns, rpKeyFetcher(client, dns), time.Now)
	b.log = log
	return b, nil
}

// rpKeyFetcher gets domain keys through the RP server, so that the proxy
// connects only to its RP server. The RP server is not the trust anchor:
// the keys are pinned to the fp= values of the domain's own _linkkeys TXT
// record, and the proxy applies the revocation certificates itself.
func rpKeyFetcher(client *rpapi.RpClient, dns localrp.DnsResolver) DomainKeyFetcher {
	return func(ctx context.Context, domain string) ([]localapi.DomainPublicKey, error) {
		pins, err := dnsFingerprints(dns, domain)
		if err != nil {
			return nil, err
		}
		resp, err := client.ResolveDomainKeys(ctx, rpapi.RpResolveDomainKeysRequest{Domain: domain})
		if err != nil {
			return nil, fmt.Errorf("RP resolve-domain-keys: %w", err)
		}
		if !strings.EqualFold(resp.Domain, domain) {
			return nil, fmt.Errorf("RP returned keys for %q, want %q", resp.Domain, domain)
		}
		return trustKeys(domain, pins, resp.Keys, resp.Revocations)
	}
}

// dnsFingerprints returns the fp= values of _linkkeys.<domain>.
func dnsFingerprints(dns localrp.DnsResolver, domain string) ([]string, error) {
	txts, err := dns.TxtLookup(localrp.LinkKeysDNSName(domain))
	if err != nil {
		return nil, fmt.Errorf("DNS %s: %w", localrp.LinkKeysDNSName(domain), err)
	}
	var pins []string
	for _, txt := range txts {
		if rec, err := localrp.ParseLinkKeysTXT(txt); err == nil {
			pins = append(pins, rec.Fingerprints...)
		}
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("DNS %s has no fingerprints", localrp.LinkKeysDNSName(domain))
	}
	return pins, nil
}

// trustKeys keeps the keys that the DNS fingerprints pin (signing keys) or
// that a pinned signing key vouches for (encryption keys), then removes
// each key that a quorum-signed revocation certificate targets. It fails
// closed when no key is left.
func trustKeys(domain string, pins []string, keys []rpapi.DomainPublicKey, revocations []rpapi.RevocationCertificate) ([]localapi.DomainPublicKey, error) {
	// The two SDKs generate separate Go types from the same schema.
	// Convert through the wire encoding so that no field is lost.
	local := make([]localapi.DomainPublicKey, 0, len(keys))
	for _, k := range keys {
		lk, err := localapi.DecodeDomainPublicKey(rpapi.EncodeDomainPublicKey(k))
		if err != nil {
			return nil, fmt.Errorf("domain key of %s: %w", domain, err)
		}
		local = append(local, lk)
	}
	trusted := localrp.TrustKeys(local, pins)
	for _, r := range revocations {
		cert, err := localapi.DecodeRevocationCertificate(rpapi.EncodeRevocationCertificate(r))
		if err != nil {
			return nil, fmt.Errorf("revocation of %s: %w", domain, err)
		}
		if localrp.VerifyRevocationCertificate(cert, trusted, domain) == nil {
			kept := trusted[:0]
			for _, k := range trusted {
				if k.KeyId != cert.TargetKeyId {
					kept = append(kept, k)
				}
			}
			trusted = kept
		}
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("no trusted keys for %s", domain)
	}
	return trusted, nil
}

func newRegularRP(rpDomain string, rp RPOperations, dns localrp.DnsResolver, fetch DomainKeyFetcher, now func() time.Time) *RegularRP {
	return &RegularRP{rpDomain: rpDomain, rp: rp, dns: dns, fetchKeys: fetch, now: now, log: slog.Default()}
}

// LoadAPIKey reads an RP API key file. It refuses a file that group or
// others can read.
func LoadAPIKey(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("API key file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("API key file %s is readable by group or others (mode %v); run chmod 600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("API key file: %w", err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("API key file %s is empty", path)
	}
	return key, nil
}

// Begin implements Backend.
func (b *RegularRP) Begin(ctx context.Context, selector, callbackURL string) (string, []byte, error) {
	username, domain := splitSelector(selector)
	if domain == "" {
		return "", nil, errors.New("login has no domain")
	}
	nonce, err := randomHex(32)
	if err != nil {
		return "", nil, err
	}
	signed, err := b.rp.SignRequest(ctx, rpapi.RpSignRequest{
		CallbackUrl:     callbackURL,
		Nonce:           nonce,
		RequestedClaims: requestedClaims(),
	})
	if err != nil {
		return "", nil, fmt.Errorf("RP sign-request: %w", err)
	}
	// The browser host comes from _linkkeys_apis.<domain>. It is a service
	// location only; trust stays bound to the identity domain.
	base, err := localrp.ResolveBrowserBase(b.dns, domain)
	if err != nil {
		base = "https://" + domain
	}
	redirect, err := localrp.BuildBrowserEndpoint(base, localrp.BrowserRouteAuthorize, signed.SignedRequest)
	if err != nil {
		return "", nil, fmt.Errorf("build IDP URL: %w", err)
	}
	if username != "" {
		u, err := url.Parse(redirect)
		if err != nil {
			return "", nil, fmt.Errorf("build IDP URL: %w", err)
		}
		q := u.Query()
		q.Set("username", username)
		u.RawQuery = q.Encode()
		redirect = u.String()
	}
	blob, err := json.Marshal(rpPending{Nonce: nonce, UserDomain: domain, APIBase: base})
	if err != nil {
		return "", nil, fmt.Errorf("encode pending login: %w", err)
	}
	return redirect, blob, nil
}

// Complete implements Backend. It fails closed: every check below must
// pass, and every released claim must verify.
func (b *RegularRP) Complete(ctx context.Context, pendingBlob []byte, arrivedURL string) (access.Identity, error) {
	var pending rpPending
	if err := json.Unmarshal(pendingBlob, &pending); err != nil {
		return access.Identity{}, fmt.Errorf("decode pending login: %w", err)
	}
	if pending.Nonce == "" || pending.UserDomain == "" {
		return access.Identity{}, errors.New("pending login is incomplete")
	}
	u, err := url.Parse(arrivedURL)
	if err != nil {
		return access.Identity{}, fmt.Errorf("parse callback URL: %w", err)
	}
	token := u.Query().Get("encrypted_token")
	if token == "" || len(token) > maxEncryptedToken {
		return access.Identity{}, errors.New("callback URL has no usable encrypted_token")
	}

	decrypted, err := b.rp.DecryptToken(ctx, rpapi.RpDecryptRequest{EncryptedToken: token})
	if err != nil {
		return access.Identity{}, fmt.Errorf("RP decrypt-token: %w", err)
	}
	verified, err := b.rp.VerifyAssertion(ctx, rpapi.RpVerifyRequest{
		SignedAssertion: decrypted.SignedAssertion,
		ExpectedDomain:  pending.UserDomain,
	})
	if err != nil {
		return access.Identity{}, fmt.Errorf("RP verify-assertion: %w", err)
	}
	// A nil error means only that the call worked.
	if !verified.Verified {
		return access.Identity{}, errors.New("assertion not verified")
	}
	a := verified.Assertion
	if a.UserId == "" {
		return access.Identity{}, errors.New("assertion has no user id")
	}
	if !strings.EqualFold(a.Domain, pending.UserDomain) {
		return access.Identity{}, fmt.Errorf("assertion domain %q, want %q", a.Domain, pending.UserDomain)
	}
	if !strings.EqualFold(a.Audience, b.rpDomain) {
		return access.Identity{}, fmt.Errorf("assertion audience %q, want %q", a.Audience, b.rpDomain)
	}
	if subtle.ConstantTimeCompare([]byte(a.Nonce), []byte(pending.Nonce)) != 1 {
		return access.Identity{}, errors.New("assertion nonce mismatch")
	}
	if err := checkAssertionTimes(a.IssuedAt, a.ExpiresAt, b.now()); err != nil {
		return access.Identity{}, err
	}

	info, err := b.rp.UserinfoFetch(ctx, rpapi.RpUserInfoRequest{
		Token:   decrypted.SignedAssertion,
		ApiBase: pending.APIBase,
		Domain:  pending.UserDomain,
	})
	if err != nil {
		return access.Identity{}, fmt.Errorf("RP userinfo-fetch: %w", err)
	}
	if info.UserId != a.UserId || !strings.EqualFold(info.Domain, a.Domain) {
		return access.Identity{}, errors.New("user info does not match the assertion")
	}
	claims, err := b.verifyClaims(ctx, info.Claims, a)
	if err != nil {
		return access.Identity{}, err
	}

	id := identityFromClaims(a.UserId, strings.ToLower(a.Domain), claims)
	if id.DisplayName == "" {
		id.DisplayName = info.DisplayName
	}
	if id.DisplayName == "" && a.DisplayName != nil {
		id.DisplayName = *a.DisplayName
	}
	return id, nil
}

// verifyClaims checks that each claim is about the asserted user, that the
// user authorized its type, that every required claim is present, and that
// each claim's signatures verify against the signing domains' DNS-pinned
// keys. The RP server's userinfo-fetch does not verify claim signatures for
// the application.
func (b *RegularRP) verifyClaims(ctx context.Context, claims []rpapi.Claim, a rpapi.IdentityAssertion) ([]localapi.Claim, error) {
	authorized := make(map[string]bool, len(a.AuthorizedClaims))
	for _, t := range a.AuthorizedClaims {
		authorized[t] = true
	}
	present := make(map[string]bool, len(claims))
	keySets := []localrp.DomainKeySet{}
	out := make([]localapi.Claim, 0, len(claims))
	for _, c := range claims {
		if c.UserId != a.UserId {
			return nil, fmt.Errorf("claim %s is about another user", c.ClaimId)
		}
		if !authorized[c.ClaimType] {
			return nil, fmt.Errorf("claim type %q was not authorized", c.ClaimType)
		}
		// The two SDKs generate separate Go types from the same schema.
		// Convert through the wire encoding so that no field is lost.
		lc, err := localapi.DecodeClaim(rpapi.EncodeClaim(c))
		if err != nil {
			return nil, fmt.Errorf("claim %s: %w", c.ClaimId, err)
		}
		for _, sig := range lc.Signatures {
			if hasKeySet(keySets, sig.Domain) {
				continue
			}
			if len(keySets) >= maxSignerDomains {
				return nil, fmt.Errorf("claims name more than %d signing domains", maxSignerDomains)
			}
			keys, err := b.fetchKeys(ctx, sig.Domain)
			if err != nil {
				return nil, fmt.Errorf("domain keys for %s: %w", sig.Domain, err)
			}
			keySets = append(keySets, localrp.DomainKeySet{Domain: sig.Domain, Keys: keys})
		}
		if err := localrp.VerifyClaim(lc, a.Domain, keySets); err != nil {
			if isRequiredClaim(c.ClaimType) {
				return nil, fmt.Errorf("claim %s (%s): %w", c.ClaimId, c.ClaimType, err)
			}
			// An optional claim that does not verify is not used, and the
			// login continues without it.
			b.log.Warn("optional claim did not verify; it is not used",
				"claim_id", c.ClaimId, "claim_type", c.ClaimType, "signers", signerKeys(lc),
				"attested_at", lc.AttestedAt, "expires_at", derefOr(lc.ExpiresAt, "none"), "error", err)
			// For protocol debugging only: the claim value is user data.
			b.log.Debug("claim that did not verify", "claim_id", c.ClaimId, "claim_type", c.ClaimType,
				"user_id", lc.UserId, "subject_domain", a.Domain,
				"claim_value_b64", base64.StdEncoding.EncodeToString(lc.ClaimValue),
				"signatures", signatureDump(lc))
			continue
		}
		present[c.ClaimType] = true
		out = append(out, lc)
	}
	for _, r := range requestedClaims().Required {
		if !present[r.ClaimType] {
			return nil, fmt.Errorf("required claim %q is missing", r.ClaimType)
		}
	}
	return out, nil
}

func isRequiredClaim(claimType string) bool {
	for _, r := range requestedClaims().Required {
		if r.ClaimType == claimType {
			return true
		}
	}
	return false
}

// signatureDump returns "<domain>/<key id>/<base64 signature>" for each
// signature, for debug logs.
func signatureDump(c localapi.Claim) []string {
	out := make([]string, 0, len(c.Signatures))
	for _, sig := range c.Signatures {
		out = append(out, sig.Domain+"/"+sig.SignedByKeyId+"/"+base64.StdEncoding.EncodeToString(sig.Signature))
	}
	return out
}

// signerKeys returns "<domain>/<key id>" for each signature, for logs.
func signerKeys(c localapi.Claim) []string {
	out := make([]string, 0, len(c.Signatures))
	for _, sig := range c.Signatures {
		out = append(out, sig.Domain+"/"+sig.SignedByKeyId)
	}
	return out
}

func hasKeySet(sets []localrp.DomainKeySet, domain string) bool {
	for _, s := range sets {
		if s.Domain == domain {
			return true
		}
	}
	return false
}

func checkAssertionTimes(issued, expires string, now time.Time) error {
	iat, err1 := time.Parse(time.RFC3339Nano, issued)
	exp, err2 := time.Parse(time.RFC3339Nano, expires)
	if err1 != nil || err2 != nil {
		return errors.New("assertion has invalid times")
	}
	if iat.After(now.Add(clockSkew)) || exp.Before(now) || exp.Before(iat) {
		return errors.New("assertion is not valid now")
	}
	return nil
}

// splitSelector splits "[username@]domain" and lowercases the domain.
func splitSelector(selector string) (username, domain string) {
	if i := strings.LastIndex(selector, "@"); i >= 0 {
		return selector[:i], strings.ToLower(selector[i+1:])
	}
	return "", strings.ToLower(selector)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func derefOr(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}
