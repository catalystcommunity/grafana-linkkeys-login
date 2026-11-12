// Package server is the HTTP front end: the LinkKeys login pages and the
// authenticated reverse proxy to Grafana.
package server

import (
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/access"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/config"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/linkkeys"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/ratelimit"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/store"
)

// Paths that the proxy owns. Grafana does not use the /linkkeys/ prefix.
const (
	PathLogin    = "/linkkeys/login"
	PathCallback = "/linkkeys/callback"
	PathLogout   = "/linkkeys/logout"
	PathHealth   = "/linkkeys/healthz"
)

//go:embed templates/*.html
var templateFS embed.FS

var pages = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// A login is "[handle@]domain". This check only rejects clearly bad input
// early; the SDK does the full check.
var selectorPattern = regexp.MustCompile(`^([A-Za-z0-9._-]{1,128}@)?[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)

// Login start limits. Each start makes the proxy contact a LinkKeys domain
// and keeps a pending attempt in memory, so an unauthenticated client must
// not be able to start many.
const (
	clientBurst    = 10
	clientInterval = 30 * time.Second
	globalBurst    = 60
	globalInterval = time.Second
	maxClients     = 10000
)

// Server handles every request.
type Server struct {
	cfg     *config.Config
	backend linkkeys.Backend
	policy  *access.Policy
	store   *store.Store
	proxy   *httputil.ReverseProxy
	log     *slog.Logger

	clientLimit *ratelimit.Limiter
	globalLimit *ratelimit.Limiter

	sessionCookie string
	attemptCookie string
	authHeaders   []string
}

// New builds a Server.
func New(cfg *config.Config, backend linkkeys.Backend, st *store.Store, log *slog.Logger) (*Server, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:           cfg,
		backend:       backend,
		policy:        access.NewPolicy(cfg.Access),
		store:         st,
		log:           log,
		sessionCookie: "lk_session",
		attemptCookie: "lk_attempt",
		authHeaders:   []string{cfg.Headers.User, cfg.Headers.Name, cfg.Headers.Email, cfg.Headers.Role},
		clientLimit:   ratelimit.New(clientBurst, clientInterval, maxClients, nil),
		globalLimit:   ratelimit.New(globalBurst, globalInterval, 1, nil),
	}
	if cfg.SecureCookies() {
		// The __Host- prefix makes the browser refuse the cookie unless it
		// is Secure, has Path=/, and has no Domain.
		s.sessionCookie = "__Host-lk_session"
		s.attemptCookie = "__Host-lk_attempt"
	}
	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.SetXForwarded()
			// Keep the browser's Host, so that Grafana's origin check and
			// root_url handling see the public name.
			r.Out.Host = r.In.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream request failed", "path", r.URL.Path, "error", err)
			http.Error(w, "Grafana is not reachable", http.StatusBadGateway)
		},
	}
	return s, nil
}

// Sweep removes expired rate limit state. Call it periodically.
func (s *Server) Sweep() {
	s.clientLimit.Sweep()
	s.globalLimit.Sweep()
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Never trust identity headers from the client, on any path.
	for _, h := range s.authHeaders {
		r.Header.Del(h)
	}
	switch r.URL.Path {
	case PathHealth:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	case PathLogin:
		s.handleLogin(w, r)
	case PathCallback:
		s.handleCallback(w, r)
	case PathLogout:
		s.handleLogout(w, r)
	default:
		s.handleProxy(w, r)
	}
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessionFor(r)
	if !ok {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, PathLogin+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"LinkKeys login required"}` + "\n"))
		return
	}

	username := sess.Identity.Subject()
	if s.cfg.GrafanaUsername == config.UsernameHandle && sess.Identity.HandleLogin() != "" {
		username = sess.Identity.HandleLogin()
	}
	name := sess.Identity.DisplayName
	if name == "" {
		name = sess.Identity.HandleLogin()
	}
	r.Header.Set(s.cfg.Headers.User, username)
	r.Header.Set(s.cfg.Headers.Role, sess.Role)
	if name != "" {
		r.Header.Set(s.cfg.Headers.Name, name)
	}
	if sess.Identity.Email != "" {
		r.Header.Set(s.cfg.Headers.Email, sess.Identity.Email)
	}
	s.stripOwnCookies(r)
	s.proxy.ServeHTTP(w, r)
}

type loginPage struct {
	Next          string
	Error         string
	Placeholder   string
	DefaultDomain string
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.renderLogin(w, http.StatusOK, safeNext(r.URL.Query().Get("next")), "")
	case http.MethodPost:
		s.startLogin(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, next, errMsg string) {
	placeholder := "you@example.com"
	if s.cfg.DefaultDomain != "" {
		placeholder = "you@" + s.cfg.DefaultDomain
	}
	s.render(w, status, "login.html", loginPage{Next: next, Error: errMsg, Placeholder: placeholder, DefaultDomain: s.cfg.DefaultDomain})
}

func (s *Server) startLogin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "cross-site login request refused", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostForm.Get("next"))
	selector := strings.TrimSpace(r.PostForm.Get("login"))
	if s.cfg.DefaultDomain != "" && selector != "" && !strings.Contains(selector, "@") && !strings.Contains(selector, ".") {
		selector += "@" + s.cfg.DefaultDomain
	}
	if !selectorPattern.MatchString(selector) {
		s.renderLogin(w, http.StatusBadRequest, next, "Enter your LinkKeys login, for example alice@example.com.")
		return
	}
	domain := strings.ToLower(selector[strings.LastIndex(selector, "@")+1:])
	if !s.policy.AllowsDomain(domain) {
		s.renderLogin(w, http.StatusForbidden, next, "Accounts of that domain cannot sign in here.")
		return
	}
	client := s.clientIP(r)
	if !s.clientLimit.Allow(client) || !s.globalLimit.Allow("") {
		s.log.Warn("login start rate limited", "client", client)
		w.Header().Set("Retry-After", "30")
		s.renderLogin(w, http.StatusTooManyRequests, next, "Too many login attempts. Wait a short time and try again.")
		return
	}

	redirect, pending, err := s.backend.Begin(r.Context(), selector, s.cfg.PublicOrigin()+PathCallback)
	if err != nil {
		s.log.Warn("could not start login", "selector", selector, "error", err)
		s.renderLogin(w, http.StatusBadGateway, next, "Could not start the login with that domain. Check the login and try again.")
		return
	}
	ttl := time.Duration(s.cfg.Session.LoginTimeout)
	token, err := s.store.AddAttempt(pending, next, ttl)
	if err != nil {
		if errors.Is(err, store.ErrFull) {
			http.Error(w, "too many logins in progress; try again later", http.StatusServiceUnavailable)
			return
		}
		s.log.Error("could not save login attempt", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// SameSite=Lax: the IDP sends the browser back with a top-level GET,
	// and the cookie must come with it. This cookie binds the callback to
	// the browser that started the login, which prevents login CSRF.
	http.SetCookie(w, s.cookie(s.attemptCookie, token, int(ttl.Seconds())))
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

type messagePage struct {
	Title   string
	Message string
	Detail  string
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var token string
	if c, err := r.Cookie(s.attemptCookie); err == nil {
		token = c.Value
	}
	http.SetCookie(w, s.cookie(s.attemptCookie, "", -1))
	attempt, ok := s.store.TakeAttempt(token)
	if !ok {
		s.render(w, http.StatusBadRequest, "message.html", messagePage{
			Title:   "Login expired",
			Message: "This login is not valid in this browser any more. Start again.",
		})
		return
	}

	// Build the URL from the configured origin, not from the Host header.
	// The SDK compares it with the callback URL that the IDP signed.
	arrived := s.cfg.PublicOrigin() + r.URL.RequestURI()
	id, err := s.backend.Complete(r.Context(), attempt.Pending, arrived)
	if err != nil {
		s.log.Warn("login verification failed", "error", err)
		s.render(w, http.StatusForbidden, "message.html", messagePage{
			Title:   "Login failed",
			Message: "LinkKeys could not verify this login. Start again.",
		})
		return
	}

	role, allowed := s.policy.Decide(id)
	if !allowed {
		s.log.Warn("login refused by access rules", "subject", id.Subject(), "handle", id.HandleLogin())
		shown := id.HandleLogin()
		if shown == "" {
			shown = id.Subject()
		}
		s.render(w, http.StatusForbidden, "message.html", messagePage{
			Title:   "Access refused",
			Message: "Your LinkKeys login worked, but this Grafana does not allow your account.",
			Detail:  shown,
		})
		return
	}

	ttl := time.Duration(s.cfg.Session.TTL)
	sessionToken, err := s.store.AddSession(id, role, ttl)
	if err != nil {
		s.log.Error("could not save session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.log.Info("login", "subject", id.Subject(), "handle", id.HandleLogin(), "role", role)
	http.SetCookie(w, s.cookie(s.sessionCookie, sessionToken, int(ttl.Seconds())))
	http.Redirect(w, r, attempt.Next, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.sessionCookie); err == nil {
		s.store.RevokeSession(c.Value)
	}
	http.SetCookie(w, s.cookie(s.sessionCookie, "", -1))
	s.render(w, http.StatusOK, "message.html", messagePage{
		Title:   "Signed out",
		Message: "You are signed out of Grafana.",
	})
}

func (s *Server) sessionFor(r *http.Request) (store.Session, bool) {
	c, err := r.Cookie(s.sessionCookie)
	if err != nil {
		return store.Session{}, false
	}
	return s.store.Session(c.Value)
}

// stripOwnCookies removes the proxy's cookies, so that Grafana never sees a
// session token.
func (s *Server) stripOwnCookies(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == s.sessionCookie || c.Name == s.attemptCookie {
			continue
		}
		r.AddCookie(c)
	}
}

func (s *Server) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	}
}

// clientIP returns the client address for rate limits. X-Forwarded-For is
// used only when the connection comes from a trusted proxy. The result is
// the nearest address in that header that is not a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if !s.cfg.IsTrustedProxy(addr) {
		return addr.Unmap().String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// The chain is broken; do not trust anything further left.
			break
		}
		addr = hop
		if !s.cfg.IsTrustedProxy(hop) {
			break
		}
	}
	return addr.Unmap().String()
}

// sameOrigin refuses a form post that a browser reports as cross-site.
// Sec-Fetch-Site decides when it is present, because a page cannot set it.
// A browser sends "Origin: null" on a same-origin post when the referrer
// policy is no-referrer, as on these pages.
func (s *Server) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.cfg.PublicOrigin() {
		return false
	}
	return true
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("render page", "page", name, "error", err)
	}
}

// safeNext returns next when it is a path on this site, and "/" otherwise.
// This prevents an open redirect after login.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "/linkkeys/") {
		return "/"
	}
	return next
}
