package linkkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

func TestIdentityFromClaims(t *testing.T) {
	id := identityFromClaims("u-1", "example.com", []api.Claim{
		{ClaimType: "handle", ClaimValue: []byte("alice")},
		{ClaimType: "display_name", ClaimValue: []byte("Alice A.")},
		{ClaimType: "email", ClaimValue: []byte("alice@example.com")},
		{ClaimType: "other", ClaimValue: []byte("ignored")},
	})
	if id.UserID != "u-1" || id.Domain != "example.com" || id.Handle != "alice" || id.DisplayName != "Alice A." || id.Email != "alice@example.com" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestCreateAndLoadIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	created, err := CreateIdentity(path, "Test Grafana", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint != created.Fingerprint || len(created.Fingerprint) != 64 {
		t.Fatalf("fingerprints %q / %q", created.Fingerprint, loaded.Fingerprint)
	}
	level, _, err := ExpiryStatus(loaded, time.Now())
	if err != nil || level != "ok" {
		t.Fatalf("expiry = %q, %v", level, err)
	}

	if _, err := CreateIdentity(path, "Again", time.Now()); err == nil {
		t.Fatal("CreateIdentity replaced an existing file")
	}
}

func TestLoadIdentityRefusesOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	if _, err := CreateIdentity(path, "Test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadIdentityRefusesGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, []byte("not key material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Fatal("garbage accepted")
	}
}
