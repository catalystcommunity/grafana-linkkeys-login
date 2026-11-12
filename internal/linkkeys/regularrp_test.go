package linkkeys

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	localapi "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
	rpapi "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

const (
	testRPDomain   = "rp.example"
	testUserDomain = "users.example"
	testUserID     = "u-123"
	testKeyID      = "key-1"
)

var testSeed = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

func testDomainKey() localapi.DomainPublicKey {
	pub := ed25519.NewKeyFromSeed(testSeed[:]).Public().(ed25519.PublicKey)
	return localapi.DomainPublicKey{
		KeyId:       testKeyID,
		PublicKey:   []byte(pub),
		Fingerprint: localrp.Fingerprint([]byte(pub)),
		Algorithm:   "ed25519",
		KeyUsage:    "sign",
		CreatedAt:   time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano),
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
	}
}

// signedClaim returns a claim that testUserDomain signed, in the regular-RP
// wire type.
func signedClaim(t *testing.T, claimType, value, userID string) rpapi.Claim {
	t.Helper()
	lc := localrp.SignClaim(localrp.ClaimSpec{
		ClaimID:       "c-" + claimType,
		ClaimType:     claimType,
		ClaimValue:    []byte(value),
		UserID:        userID,
		SubjectDomain: testUserDomain,
		AttestedAt:    time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
	}, []localrp.ClaimSigner{{Domain: testUserDomain, KeyID: testKeyID, PrivateKeySeed: testSeed}})
	c, err := rpapi.DecodeClaim(localapi.EncodeClaim(lc))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type staticDNS struct{ txt map[string][]string }

func (d staticDNS) TxtLookup(name string) ([]string, error) {
	if v, ok := d.txt[name]; ok {
		return v, nil
	}
	return nil, errors.New("no record")
}

// fakeRP plays the RP server. Each test changes one field to break one
// check.
type fakeRP struct {
	signReq   rpapi.RpSignRequest
	verifyReq rpapi.RpVerifyRequest
	infoReq   rpapi.RpUserInfoRequest

	nonce     string // the nonce that the assertion carries; "" = echo
	verified  bool
	assertion rpapi.IdentityAssertion
	info      rpapi.UserInfo
	infoErr   error
}

func (f *fakeRP) SignRequest(_ context.Context, req rpapi.RpSignRequest) (rpapi.RpSignResponse, error) {
	f.signReq = req
	return rpapi.RpSignResponse{SignedRequest: "SIGNED"}, nil
}

func (f *fakeRP) DecryptToken(_ context.Context, req rpapi.RpDecryptRequest) (rpapi.RpDecryptResponse, error) {
	if req.EncryptedToken != "TOKEN" {
		return rpapi.RpDecryptResponse{}, errors.New("bad token")
	}
	return rpapi.RpDecryptResponse{SignedAssertion: "ASSERTION"}, nil
}

func (f *fakeRP) VerifyAssertion(_ context.Context, req rpapi.RpVerifyRequest) (rpapi.RpVerifyResponse, error) {
	f.verifyReq = req
	a := f.assertion
	if f.nonce == "" {
		a.Nonce = f.signReq.Nonce
	} else {
		a.Nonce = f.nonce
	}
	return rpapi.RpVerifyResponse{Verified: f.verified, Assertion: a}, nil
}

func (f *fakeRP) UserinfoFetch(_ context.Context, req rpapi.RpUserInfoRequest) (rpapi.UserInfo, error) {
	f.infoReq = req
	return f.info, f.infoErr
}

func goodFake(t *testing.T) *fakeRP {
	now := time.Now().UTC()
	return &fakeRP{
		verified: true,
		assertion: rpapi.IdentityAssertion{
			UserId:           testUserID,
			Domain:           testUserDomain,
			Audience:         testRPDomain,
			IssuedAt:         now.Add(-10 * time.Second).Format(time.RFC3339Nano),
			ExpiresAt:        now.Add(5 * time.Minute).Format(time.RFC3339Nano),
			AuthorizedClaims: []string{"handle", "display_name", "email"},
		},
		info: rpapi.UserInfo{
			UserId:      testUserID,
			Domain:      testUserDomain,
			DisplayName: "Alice From UserInfo",
			Claims: []rpapi.Claim{
				signedClaim(t, "handle", "alice", testUserID),
				signedClaim(t, "email", "alice@users.example", testUserID),
			},
		},
	}
}

func newTestRP(f *fakeRP) *RegularRP {
	dns := staticDNS{txt: map[string][]string{
		"_linkkeys_apis." + testUserDomain: {"v=lk1 tcp=lk.users.example https=lk.users.example/base"},
	}}
	fetch := func(_ context.Context, domain string) ([]localapi.DomainPublicKey, error) {
		if domain != testUserDomain {
			return nil, errors.New("unknown domain")
		}
		return []localapi.DomainPublicKey{testDomainKey()}, nil
	}
	return newRegularRP(testRPDomain, f, dns, fetch, time.Now)
}

func runLogin(t *testing.T, f *fakeRP) (string, error) {
	t.Helper()
	b := newTestRP(f)
	redirect, pending, err := b.Begin(context.Background(), "alice@Users.Example", "https://grafana.rp.example/linkkeys/callback")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	id, err := b.Complete(context.Background(), pending, "https://grafana.rp.example/linkkeys/callback?encrypted_token=TOKEN")
	if err != nil {
		return redirect, err
	}
	if id.UserID != testUserID || id.Domain != testUserDomain || id.Handle != "alice" || id.Email != "alice@users.example" || id.DisplayName != "Alice From UserInfo" {
		t.Fatalf("identity = %+v", id)
	}
	return redirect, nil
}

func TestRegularRPLogin(t *testing.T) {
	f := goodFake(t)
	redirect, err := runLogin(t, f)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "lk.users.example" || u.Path != "/base/auth/authorize" {
		t.Fatalf("redirect = %s", redirect)
	}
	if u.Query().Get("signed_request") != "SIGNED" || u.Query().Get("username") != "alice" {
		t.Fatalf("redirect query = %v", u.Query())
	}
	if f.signReq.CallbackUrl != "https://grafana.rp.example/linkkeys/callback" || len(f.signReq.Nonce) != 64 {
		t.Fatalf("sign request = %+v", f.signReq)
	}
	if f.signReq.RequestedClaims == nil || len(f.signReq.RequestedClaims.Required) != 1 || f.signReq.RequestedClaims.Required[0].ClaimType != "handle" {
		t.Fatalf("requested claims = %+v", f.signReq.RequestedClaims)
	}
	if f.verifyReq.ExpectedDomain != testUserDomain {
		t.Fatalf("expected domain = %q", f.verifyReq.ExpectedDomain)
	}
	if f.infoReq.ApiBase != "https://lk.users.example/base" || f.infoReq.Domain != testUserDomain || f.infoReq.Token != "ASSERTION" {
		t.Fatalf("userinfo request = %+v", f.infoReq)
	}
}

func TestRegularRPBrowserBaseFallback(t *testing.T) {
	b := newTestRP(goodFake(t))
	redirect, pending, err := b.Begin(context.Background(), "other.example", "https://grafana.rp.example/linkkeys/callback")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(redirect, "https://other.example/auth/authorize?") || strings.Contains(redirect, "username=") {
		t.Fatalf("redirect = %s", redirect)
	}
	var p rpPending
	if err := json.Unmarshal(pending, &p); err != nil || p.APIBase != "https://other.example" || p.UserDomain != "other.example" {
		t.Fatalf("pending = %+v, %v", p, err)
	}
}

func TestRegularRPRejects(t *testing.T) {
	cases := map[string]func(f *fakeRP){
		"not verified":          func(f *fakeRP) { f.verified = false },
		"wrong domain":          func(f *fakeRP) { f.assertion.Domain = "evil.example" },
		"wrong audience":        func(f *fakeRP) { f.assertion.Audience = "other-rp.example" },
		"wrong nonce":           func(f *fakeRP) { f.nonce = "replayed" },
		"no user id":            func(f *fakeRP) { f.assertion.UserId = ""; f.info.UserId = "" },
		"issued in the future":  func(f *fakeRP) { f.assertion.IssuedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano) },
		"expired":               func(f *fakeRP) { f.assertion.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano) },
		"bad time":              func(f *fakeRP) { f.assertion.IssuedAt = "yesterday" },
		"userinfo error":        func(f *fakeRP) { f.infoErr = errors.New("down") },
		"userinfo other user":   func(f *fakeRP) { f.info.UserId = "u-999" },
		"userinfo other domain": func(f *fakeRP) { f.info.Domain = "evil.example" },
		"claim about other user": func(f *fakeRP) {
			f.info.Claims[1] = signedClaim(t, "email", "x@users.example", "u-999")
		},
		"unauthorized claim type": func(f *fakeRP) { f.assertion.AuthorizedClaims = []string{"handle"} },
		"required claim missing":  func(f *fakeRP) { f.info.Claims = f.info.Claims[1:] },
		"tampered claim value":    func(f *fakeRP) { f.info.Claims[0].ClaimValue = []byte("admin") },
		"unsigned claim":          func(f *fakeRP) { f.info.Claims[0].Signatures = nil },
		"signer from unknown domain": func(f *fakeRP) {
			f.info.Claims[0].Signatures[0].Domain = "evil.example"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := goodFake(t)
			mutate(f)
			if _, err := runLogin(t, f); err == nil {
				t.Fatal("login succeeded")
			}
		})
	}
}

// An optional claim that does not verify is not used. The login continues
// with the claims that verify.
func TestRegularRPDropsUnverifiedOptionalClaim(t *testing.T) {
	cases := map[string]func(f *fakeRP){
		"tampered value": func(f *fakeRP) { f.info.Claims[1].ClaimValue = []byte("admin@users.example") },
		"unsigned":       func(f *fakeRP) { f.info.Claims[1].Signatures = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := goodFake(t)
			mutate(f)
			b := newTestRP(f)
			_, pending, err := b.Begin(context.Background(), "alice@users.example", "https://grafana.rp.example/linkkeys/callback")
			if err != nil {
				t.Fatal(err)
			}
			id, err := b.Complete(context.Background(), pending, "https://grafana.rp.example/linkkeys/callback?encrypted_token=TOKEN")
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if id.Handle != "alice" || id.Email != "" {
				t.Fatalf("identity = %+v, want handle alice and no email", id)
			}
		})
	}
}

func TestRegularRPRejectsBadCallback(t *testing.T) {
	b := newTestRP(goodFake(t))
	_, pending, err := b.Begin(context.Background(), "alice@users.example", "https://grafana.rp.example/linkkeys/callback")
	if err != nil {
		t.Fatal(err)
	}
	for _, arrived := range []string{
		"https://grafana.rp.example/linkkeys/callback",
		"https://grafana.rp.example/linkkeys/callback?encrypted_token=" + strings.Repeat("A", maxEncryptedToken+1),
		"https://grafana.rp.example/linkkeys/callback?encrypted_token=WRONG",
	} {
		if _, err := b.Complete(context.Background(), pending, arrived); err == nil {
			t.Errorf("callback %.80s accepted", arrived)
		}
	}
	if _, err := b.Complete(context.Background(), []byte(`{}`), "https://grafana.rp.example/linkkeys/callback?encrypted_token=TOKEN"); err == nil {
		t.Error("empty pending state accepted")
	}
}

func TestLoadAPIKey(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "key")
	if err := os.WriteFile(good, []byte("  secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadAPIKey(good); err != nil || k != "secret-key" {
		t.Fatalf("LoadAPIKey = %q, %v", k, err)
	}
	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAPIKey(open); err == nil {
		t.Fatal("readable key file accepted")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAPIKey(empty); err == nil {
		t.Fatal("empty key file accepted")
	}
}

func TestTrustKeys(t *testing.T) {
	key := testDomainKey()
	rk, err := rpapi.DecodeDomainPublicKey(localapi.EncodeDomainPublicKey(key))
	if err != nil {
		t.Fatal(err)
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	unpinned := rk
	unpinned.KeyId = "key-2"
	unpinned.PublicKey = []byte(other)
	unpinned.Fingerprint = key.Fingerprint // a lie; the fingerprint is recomputed

	trusted, err := trustKeys(testUserDomain, []string{key.Fingerprint}, []rpapi.DomainPublicKey{rk, unpinned}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) != 1 || trusted[0].KeyId != testKeyID {
		t.Fatalf("trusted = %+v", trusted)
	}
	if _, err := trustKeys(testUserDomain, []string{strings.Repeat("0", 64)}, []rpapi.DomainPublicKey{rk}, nil); err == nil {
		t.Fatal("keys accepted without a matching DNS fingerprint")
	}
}

func TestDNSFingerprints(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	dns := staticDNS{txt: map[string][]string{"_linkkeys." + testUserDomain: {"v=lk1 fp=" + fp}}}
	pins, err := dnsFingerprints(dns, testUserDomain)
	if err != nil || len(pins) != 1 || pins[0] != fp {
		t.Fatalf("pins = %v, %v", pins, err)
	}
	if _, err := dnsFingerprints(dns, "other.example"); err == nil {
		t.Fatal("missing record accepted")
	}
}
