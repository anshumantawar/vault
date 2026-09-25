// Package pki issues Vault's internal certificates: one private CA, and one
// certificate per process whose CommonName is the process id and whose
// OrganizationalUnit is its role (meta, node or gateway). Every gRPC and Raft
// connection is mutual TLS against this CA, and the role in the peer's
// certificate is what authorization checks.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	RoleMeta    = "meta"
	RoleNode    = "node"
	RoleGateway = "gateway"
)

// Spec describes one process certificate.
type Spec struct {
	Name  string   // process id, e.g. "n1"; also a DNS SAN
	Role  string   // meta | node | gateway
	Hosts []string // extra DNS names or IPs the process is reached at
}

// Generate writes ca.pem/ca-key.pem (reusing them if present) and, for each
// spec, <name>.pem/<name>-key.pem, skipping certificates that already exist.
func Generate(dir string, specs []Spec) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ca, caKey, err := loadOrCreateCA(dir)
	if err != nil {
		return err
	}
	for _, s := range specs {
		if s.Role != RoleMeta && s.Role != RoleNode && s.Role != RoleGateway {
			return fmt.Errorf("%s: unknown role %q", s.Name, s.Role)
		}
		if _, err := os.Stat(filepath.Join(dir, s.Name+".pem")); err == nil {
			continue
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{CommonName: s.Name, OrganizationalUnit: []string{s.Role}, Organization: []string{"Vault"}},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		for _, h := range append([]string{s.Name, "localhost", "127.0.0.1", "::1"}, s.Hosts...) {
			if ip := net.ParseIP(h); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, h)
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err := writePair(dir, s.Name, der, key); err != nil {
			return err
		}
	}
	return nil
}

func loadOrCreateCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err == nil {
		keyPEM, err := os.ReadFile(filepath.Join(dir, "ca-key.pem"))
		if err != nil {
			return nil, nil, err
		}
		cert, err := parseCert(certPEM)
		if err != nil {
			return nil, nil, err
		}
		kb, _ := pem.Decode(keyPEM)
		if kb == nil {
			return nil, nil, errors.New("ca-key.pem: no PEM block")
		}
		key, err := x509.ParseECPrivateKey(kb.Bytes)
		return cert, key, err
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Vault internal CA", Organization: []string{"Vault"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	if err := writePair(dir, "ca", der, key); err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func writePair(dir, name string, der []byte, key *ecdsa.PrivateKey) error {
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+"-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func parseCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// Identity is who a verified certificate belongs to.
type Identity struct{ Role, ID string }

// IdentityOf reads the role and id from a certificate issued by Generate.
func IdentityOf(c *x509.Certificate) Identity {
	id := Identity{ID: c.Subject.CommonName}
	if len(c.Subject.OrganizationalUnit) > 0 {
		id.Role = c.Subject.OrganizationalUnit[0]
	}
	return id
}
