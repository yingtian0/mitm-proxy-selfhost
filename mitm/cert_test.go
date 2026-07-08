package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestGenerateServerCertificateForDNSName(t *testing.T) {
	caCert, caKey := newTestCA(t)

	cert, err := GenerateServerCertificate("example.com", caCert, caKey)
	if err != nil {
		t.Fatalf("GenerateServerCertificate() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if got, want := leaf.DNSNames, []string{"example.com"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("DNSNames = %v, want %v", got, want)
	}
	if len(leaf.IPAddresses) != 0 {
		t.Fatalf("IPAddresses = %v, want empty", leaf.IPAddresses)
	}
}

func TestGenerateServerCertificateForIPAddress(t *testing.T) {
	caCert, caKey := newTestCA(t)

	cert, err := GenerateServerCertificate("127.0.0.1", caCert, caKey)
	if err != nil {
		t.Fatalf("GenerateServerCertificate() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if got, want := leaf.IPAddresses, []net.IP{net.ParseIP("127.0.0.1")}; len(got) != 1 || !got[0].Equal(want[0]) {
		t.Fatalf("IPAddresses = %v, want %v", got, want)
	}
	if len(leaf.DNSNames) != 0 {
		t.Fatalf("DNSNames = %v, want empty", leaf.DNSNames)
	}
}

func newTestCA(t *testing.T) (*x509.Certificate, any) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return cert, key
}
