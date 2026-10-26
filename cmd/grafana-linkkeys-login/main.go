// Command grafana-linkkeys-login is a reverse proxy that signs users in to
// Grafana with LinkKeys and passes the verified identity to Grafana's
// [auth.proxy].
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/config"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/linkkeys"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/server"
	"github.com/catalystcommunity/grafana-linkkeys-login/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `grafana-linkkeys-login: sign in to Grafana with LinkKeys.

Usage:
  grafana-linkkeys-login init-identity -config <file>   create the LinkKeys local-RP identity
  grafana-linkkeys-login fingerprint -config <file>     print the fingerprint to approve
  grafana-linkkeys-login serve -config <file>           run the proxy
  grafana-linkkeys-login version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(log, os.Args[2:])
	case "init-identity":
		err = initIdentity(os.Args[2:])
	case "fingerprint":
		err = fingerprint(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadConfig(name string, args []string) (*config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", "/etc/grafana-linkkeys-login/config.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func initIdentity(args []string) error {
	cfg, err := loadConfig("init-identity", args)
	if err != nil {
		return err
	}
	identity, err := linkkeys.CreateIdentity(cfg.IdentityFile, cfg.AppName, time.Now())
	if err != nil {
		return err
	}
	_, expires, err := linkkeys.ExpiryStatus(identity, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("Created %s (mode 0600). Keep it secret.\n\n", cfg.IdentityFile)
	fmt.Printf("Fingerprint: %s\n", identity.Fingerprint)
	fmt.Printf("Expires:     %s\n\n", expires.Format(time.RFC3339))
	fmt.Println("Each LinkKeys domain admin approves this fingerprint after the first login attempt:")
	fmt.Printf("  linkkeys local-rp approve %s\n", identity.Fingerprint)
	return nil
}

func fingerprint(args []string) error {
	cfg, err := loadConfig("fingerprint", args)
	if err != nil {
		return err
	}
	identity, err := linkkeys.LoadIdentity(cfg.IdentityFile)
	if err != nil {
		return err
	}
	fmt.Println(identity.Fingerprint)
	return nil
}

func serve(log *slog.Logger, args []string) error {
	cfg, err := loadConfig("serve", args)
	if err != nil {
		return err
	}
	identity, err := linkkeys.LoadIdentity(cfg.IdentityFile)
	if err != nil {
		return err
	}
	level, expires, err := linkkeys.ExpiryStatus(identity, time.Now())
	if err != nil {
		return err
	}
	if level == linkkeys.Expired {
		return fmt.Errorf("the local-RP identity expired at %s; create a new one and approve its fingerprint again", expires.Format(time.RFC3339))
	}
	if level != "" && level != "ok" {
		log.Warn("local-RP identity expires soon", "level", level, "expires_at", expires.Format(time.RFC3339))
	}
	if !cfg.SecureCookies() {
		log.Warn("public_url uses http; session cookies are sent without TLS")
	}

	st := store.New(10000, time.Now)
	backend := linkkeys.NewLocalRP(identity)
	handler, err := server.New(cfg, backend, st, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st.Sweep()
			}
		}
	}()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.Listen, "public_url", cfg.PublicOrigin(), "upstream", cfg.Upstream, "fingerprint", backend.Fingerprint(), "version", version)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
