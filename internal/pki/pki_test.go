package pki

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseCert(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir, []Spec{{Name: "m1", Role: RoleMeta, Hosts: []string{"meta.internal", "10.0.0.5"}}}); err != nil {
		t.Fatal(err)
	}
	ca := readCert(t, filepath.Join(dir, "ca.pem"))
	m1 := readCert(t, filepath.Join(dir, "m1.pem"))

	if got := IdentityOf(m1); got != (Identity{Role: RoleMeta, ID: "m1"}) {
		t.Errorf("IdentityOf = %+v", got)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, host := range []string{"m1", "meta.internal", "10.0.0.5", "127.0.0.1"} {
		if _, err := m1.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("verify for %s: %v", host, err)
		}
	}
	if info, _ := os.Stat(filepath.Join(dir, "m1-key.pem")); info.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %v, want 0600", info.Mode().Perm())
	}

	// A second run reuses the CA and keeps existing certificates.
	if err := Generate(dir, []Spec{{Name: "m1", Role: RoleMeta}, {Name: "n1", Role: RoleNode}}); err != nil {
		t.Fatal(err)
	}
	if !readCert(t, filepath.Join(dir, "ca.pem")).Equal(ca) || !readCert(t, filepath.Join(dir, "m1.pem")).Equal(m1) {
		t.Error("rerun replaced the CA or an existing certificate")
	}
	if _, err := readCert(t, filepath.Join(dir, "n1.pem")).Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("new certificate not signed by the reused CA: %v", err)
	}
}

func TestGenerateRejectsUnknownRole(t *testing.T) {
	if err := Generate(t.TempDir(), []Spec{{Name: "x", Role: "root"}}); err == nil {
		t.Fatal("accepted an unknown role")
	}
}
