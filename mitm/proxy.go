package mitm

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
)

type Proxy struct {
	caCert *x509.Certificate
	caKey *rsa.PrivateKey
}

func NewProxy(caCert *x509.Certificate,caKey *rsa.PrivateKey) (*Proxy,error) {
	newProxy :=  Proxy{
		caCert: caCert,
		caKey: caKey,
	}
	return &newProxy,nil
}


func (p *Proxy)HandleConnect(w http.ResponseWriter,r *http.Request) {
	serverConn,_ := net.Dial("tcp",r.Host)
	
	responseWriter := w.(http.Hijacker)
	clientConn,_,_ := responseWriter.Hijack()
	clientConn.Write([]byte{})

	cert := GenerateServerCertificate(r.Host,p.caCert,p.caKey)


	tlsClientConn:= tls.Server(clientConn,&tls.Config{
		Certificates: []tls.Certificate{*cert},
	})

	tlsClientConn.Handshake()

	tlsServerConn := tls.Server(serverConn,&tls.Config{
		ServerName: r.Host,
	})

	tlsServerConn.Handshake()

	go func () {

		defer serverConn.Close()
		defer clientConn.Close()
		io.Copy(tlsClientConn,tlsServerConn)
	}()
	io.Copy(tlsServerConn,tlsClientConn)
}