package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/access"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/config"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/store"
)

const testOrigin = "https://grafana.example.lan"

// fakeBackend records what the server sends and returns a fixed identity.
type fakeBackend struct {
	mu          sync.Mutex
	identity    access.Identity
	beginErr    error
	completeErr error
	selectors   []string
	callbacks   []string
	arrived     []string
}

func (f *fakeBackend) Begin(_ context.Context, selector, callbackURL string) (string, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beginErr != nil {
		return "", nil, f.beginErr
	}
	f.selectors = append(f.selectors, selector)
	f.callbacks = append(f.callbacks, callbackURL)
	return "https://idp.example.com/local-rp/authorize?req=1", []byte(`{"pending":"` + selector + `"}`), nil
}

func (f *fakeBackend) Complete(_ context.Context, pending []byte, arrivedURL string) (access.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.arrived = append(f.arrived, arrivedURL)
	if f.completeErr != nil {
		return access.Identity{}, f.completeErr
	}
	if !strings.HasPrefix(string(pending), `{"pending":`) {
		return access.Identity{}, errors.New("unexpected pending state")
	}
	return f.identity, nil
}

type upstreamRecord struct {
	mu      sync.Mutex
	headers []http.Header
	hosts   []string
}

func (u *upstreamRecord) last() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.headers) == 0 {
		return nil
	}
	return u.headers[len(u.headers)-1]
}

type harness struct {
	srv      *Server
	backend  *fakeBackend
	upstream *upstreamRecord
	cfg      *config.Config
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	rec := &upstreamRecord{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.headers = append(rec.headers, r.Header.Clone())
		rec.hosts = append(rec.hosts, r.Host)
		rec.mu.Unlock()
		_, _ = io.WriteString(w, "grafana:"+r.URL.Path)
	}))
	t.Cleanup(up.Close)

	cfg, err := config.Parse([]byte(`
public_url: ` + testOrigin + `
upstream: ` + up.URL + `
identity_file: /unused
access:
  users:
    - identity: alice@example.com
      role: Admin
  domains:
    - domain: example.com
      role: Viewer
`))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if mutate != nil {
		mutate(cfg)
	}
	backend := &fakeBackend{identity: access.Identity{UserID: "u-1", Domain: "example.com", Handle: "alice", DisplayName: "Alice", Email: "alice@example.com"}}
	s, err := New(cfg, backend, store.New(100, time.Now), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	return &harness{srv: s, backend: backend, upstream: rec, cfg: cfg}
}

func (h *harness) do(r *http.Request) *http.Response {
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	return w.Result()
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func loginPost(login, next string) *http.Request {
	form := url.Values{"login": {login}, "next": {next}}
	r := httptest.NewRequest(http.MethodPost, testOrigin+PathLogin, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

// signIn runs a complete login and returns the session cookie.
func (h *harness) signIn(t *testing.T, next string) *http.Cookie {
	t.Helper()
	resp := h.do(loginPost("alice@example.com", next))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login post status = %d", resp.StatusCode)
	}
	attempt := cookieNamed(resp, "__Host-lk_attempt")
	if attempt == nil {
		t.Fatal("no attempt cookie")
	}
	cb := httptest.NewRequest(http.MethodGet, testOrigin+PathCallback+"?encrypted_token=abc", nil)
	cb.AddCookie(attempt)
	resp = h.do(cb)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status = %d", resp.StatusCode)
	}
	sess := cookieNamed(resp, "__Host-lk_session")
	if sess == nil || sess.Value == "" {
		t.Fatal("no session cookie")
	}
	return sess
}

func TestUnauthenticatedBrowserIsSentToLogin(t *testing.T) {
	h := newHarness(t, nil)
	r := httptest.NewRequest(http.MethodGet, testOrigin+"/d/abc?orgId=1", nil)
	r.Header.Set("Accept", "text/html")
	resp := h.do(r)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	want := PathLogin + "?next=" + url.QueryEscape("/d/abc?orgId=1")
	if got := resp.Header.Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	if h.upstream.last() != nil {
		t.Fatal("unauthenticated request reached Grafana")
	}
}

func TestUnauthenticatedAPIGets401(t *testing.T) {
	h := newHarness(t, nil)
	r := httptest.NewRequest(http.MethodGet, testOrigin+"/api/search", nil)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-WEBAUTH-USER", "admin")
	resp := h.do(r)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if h.upstream.last() != nil {
		t.Fatal("spoofed request reached Grafana")
	}
}

func TestLoginFlowSetsIdentityHeadersAndHidesCookies(t *testing.T) {
	h := newHarness(t, nil)
	sess := h.signIn(t, "/d/abc")

	if got := h.backend.callbacks[0]; got != testOrigin+PathCallback {
		t.Fatalf("callback URL = %q", got)
	}

	r := httptest.NewRequest(http.MethodGet, testOrigin+"/api/dashboards", nil)
	r.AddCookie(sess)
	r.AddCookie(&http.Cookie{Name: "grafana_session", Value: "keep"})
	r.Header.Set("X-WEBAUTH-USER", "mallory@evil.example")
	r.Header.Set("X-WEBAUTH-ROLE", "Admin")
	resp := h.do(r)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got := h.upstream.last()
	if v := got.Values("X-Webauth-User"); len(v) != 1 || v[0] != "u-1@example.com" {
		t.Fatalf("user header = %v", v)
	}
	if v := got.Get("X-Webauth-Role"); v != "Admin" {
		t.Fatalf("role header = %q", v)
	}
	if v := got.Get("X-Webauth-Name"); v != "Alice" {
		t.Fatalf("name header = %q", v)
	}
	if v := got.Get("X-Webauth-Email"); v != "alice@example.com" {
		t.Fatalf("email header = %q", v)
	}
	cookie := got.Get("Cookie")
	if strings.Contains(cookie, "lk_session") || strings.Contains(cookie, sess.Value) {
		t.Fatalf("session cookie leaked to Grafana: %q", cookie)
	}
	if !strings.Contains(cookie, "grafana_session=keep") {
		t.Fatalf("other cookies were dropped: %q", cookie)
	}
	if host := h.upstream.hosts[len(h.upstream.hosts)-1]; host != "grafana.example.lan" {
		t.Fatalf("upstream Host = %q", host)
	}
}

func TestHandleUsernameOption(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.GrafanaUsername = config.UsernameHandle })
	sess := h.signIn(t, "/")
	r := httptest.NewRequest(http.MethodGet, testOrigin+"/api/user", nil)
	r.AddCookie(sess)
	h.do(r)
	if v := h.upstream.last().Get("X-Webauth-User"); v != "alice@example.com" {
		t.Fatalf("user header = %q", v)
	}
}

func TestCallbackURLUsesConfiguredOriginNotHostHeader(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.do(loginPost("alice@example.com", "/"))
	attempt := cookieNamed(resp, "__Host-lk_attempt")
	cb := httptest.NewRequest(http.MethodGet, "http://evil.example"+PathCallback+"?encrypted_token=abc", nil)
	cb.Host = "evil.example"
	cb.AddCookie(attempt)
	h.do(cb)
	if got := h.backend.arrived[0]; got != testOrigin+PathCallback+"?encrypted_token=abc" {
		t.Fatalf("arrived URL = %q", got)
	}
}

func TestCallbackIsSingleUse(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.do(loginPost("alice@example.com", "/"))
	attempt := cookieNamed(resp, "__Host-lk_attempt")

	for i, want := range []int{http.StatusSeeOther, http.StatusBadRequest} {
		cb := httptest.NewRequest(http.MethodGet, testOrigin+PathCallback+"?encrypted_token=abc", nil)
		cb.AddCookie(attempt)
		if got := h.do(cb).StatusCode; got != want {
			t.Fatalf("callback %d status = %d, want %d", i, got, want)
		}
	}
}

func TestCallbackWithoutAttemptCookieIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.do(loginPost("alice@example.com", "/"))
	// Another browser (no attempt cookie) brings the callback: login CSRF.
	cb := httptest.NewRequest(http.MethodGet, testOrigin+PathCallback+"?encrypted_token=abc", nil)
	resp := h.do(cb)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if cookieNamed(resp, "__Host-lk_session") != nil {
		t.Fatal("session issued without attempt cookie")
	}
	if len(h.backend.arrived) != 0 {
		t.Fatal("backend was asked to verify an unbound callback")
	}
}

func TestVerificationFailureGivesNoSession(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.completeErr = errors.New("bad signature")
	resp := h.do(loginPost("alice@example.com", "/"))
	cb := httptest.NewRequest(http.MethodGet, testOrigin+PathCallback+"?encrypted_token=abc", nil)
	cb.AddCookie(cookieNamed(resp, "__Host-lk_attempt"))
	resp = h.do(cb)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if c := cookieNamed(resp, "__Host-lk_session"); c != nil && c.Value != "" {
		t.Fatal("session issued after failed verification")
	}
}

func TestIdentityOutsideAccessRulesIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.identity = access.Identity{UserID: "u-9", Domain: "other.example", Handle: "eve"}
	resp := h.do(loginPost("eve@other.example", "/"))
	cb := httptest.NewRequest(http.MethodGet, testOrigin+PathCallback+"?encrypted_token=abc", nil)
	cb.AddCookie(cookieNamed(resp, "__Host-lk_attempt"))
	resp = h.do(cb)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if c := cookieNamed(resp, "__Host-lk_session"); c != nil && c.Value != "" {
		t.Fatal("session issued to a refused identity")
	}
}

func TestCrossSiteLoginPostIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	r := loginPost("alice@example.com", "/")
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if got := h.do(r).StatusCode; got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}
	if len(h.backend.selectors) != 0 {
		t.Fatal("cross-site post started a login")
	}
}

func TestBadLoginInputIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	for _, login := range []string{"", "alice", "alice@", "@example.com", "a b@example.com", "alice@exa mple.com", "alice@@example.com"} {
		if got := h.do(loginPost(login, "/")).StatusCode; got != http.StatusBadRequest {
			t.Errorf("login %q status = %d, want 400", login, got)
		}
	}
	if len(h.backend.selectors) != 0 {
		t.Fatalf("backend called for bad input: %v", h.backend.selectors)
	}
}

func TestDefaultDomainIsAdded(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.DefaultDomain = "example.com" })
	h.do(loginPost("alice", "/"))
	if len(h.backend.selectors) != 1 || h.backend.selectors[0] != "alice@example.com" {
		t.Fatalf("selectors = %v", h.backend.selectors)
	}
}

func TestOpenRedirectIsBlocked(t *testing.T) {
	cases := map[string]string{
		"":                         "/",
		"/d/abc?x=1":               "/d/abc?x=1",
		"//evil.example/":          "/",
		"https://evil.example/":    "/",
		"/\\evil.example":          "/",
		"evil":                     "/",
		"/linkkeys/logout":         "/",
		"/ok\r\nSet-Cookie: x=y":   "/",
		"/explore?left=%7B%7D#top": "/explore?left=%7B%7D#top",
	}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}

	h := newHarness(t, nil)
	resp := h.do(loginPost("alice@example.com", "//evil.example/"))
	cb := httptest.NewRequest(http.MethodGet, testOrigin+PathCallback+"?encrypted_token=abc", nil)
	cb.AddCookie(cookieNamed(resp, "__Host-lk_attempt"))
	if got := h.do(cb).Header.Get("Location"); got != "/" {
		t.Fatalf("redirect after login = %q, want /", got)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	h := newHarness(t, nil)
	sess := h.signIn(t, "/")

	out := httptest.NewRequest(http.MethodGet, testOrigin+PathLogout, nil)
	out.AddCookie(sess)
	h.do(out)

	r := httptest.NewRequest(http.MethodGet, testOrigin+"/api/user", nil)
	r.AddCookie(sess)
	if got := h.do(r).StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("status after logout = %d, want 401", got)
	}
}

func TestCookieAttributes(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.do(loginPost("alice@example.com", "/"))
	c := cookieNamed(resp, "__Host-lk_attempt")
	if c == nil || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("attempt cookie attributes = %+v", c)
	}

	plain := newHarness(t, func(c *config.Config) { c.PublicURL = "http://grafana.lan" })
	r := loginPost("alice@example.com", "/")
	r.Header.Set("Origin", "http://grafana.lan")
	resp = plain.do(r)
	if c := cookieNamed(resp, "lk_attempt"); c == nil || c.Secure {
		t.Fatalf("http cookie = %+v", c)
	}
}

func TestBeginFailureShowsLoginAgain(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.beginErr = errors.New("dns lookup failed")
	resp := h.do(loginPost("alice@example.com", "/"))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if cookieNamed(resp, "__Host-lk_attempt") != nil {
		t.Fatal("attempt cookie set after begin failure")
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.do(httptest.NewRequest(http.MethodGet, testOrigin+PathHealth, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
