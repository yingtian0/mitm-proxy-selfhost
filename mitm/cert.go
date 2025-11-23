package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func GenerateServerCertificate(host string,caCert *x509.Certificate,caKey any)  *tls.Certificate {
	priv,_ := rsa.GenerateKey(rand.Reader,2048)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(1,0,0),
		DNSNames: []string{
			host,
		},
		Subject: pkix.Name{
			CommonName: host,
		},

		KeyUsage: x509.KeyUsageEncipherOnly | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der,_ := x509.CreateCertificate(rand.Reader,&tmpl,caCert,&priv.PublicKey,caKey)

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey: priv,
	}
}