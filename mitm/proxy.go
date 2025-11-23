package mitm

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
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
	target := r.Host
	if !strings.Contains(target,":") {
		target = ":443" 
	}
	serverConn,err := net.DialTimeout("tcp",r.Host,10*time.Second)
	if err != nil {
		http.Error(w,"failted to connect target"+err.Error(),http.StatusServiceUnavailable)
		log.Println("failted to connect target:",err)
		return 
	}
	responseWriter,ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		serverConn.Close()
		return 
	}
	clientConn,_,err := responseWriter.Hijack()
	if err != nil {
		http.Error(w,"failted to hijack tcp socket"+err.Error(),http.StatusInternalServerError)
		serverConn.Close()
		return 
	}
	clientConn.Write([]byte{})
	cert := GenerateServerCertificate(r.Host,p.caCert,p.caKey)
	tlsClientConn:= tls.Server(clientConn,&tls.Config{
		Certificates: []tls.Certificate{*cert},
	})

	err = tlsClientConn.Handshake()
	if err != nil {
		log.Println("tlsClient handshake error:", err)
		serverConn.Close()
		clientConn.Close()
		return 
	}

	tlsServerConn := tls.Server(serverConn,&tls.Config{
		ServerName: r.Host,
	})

	err = tlsServerConn.Handshake()
	if err != nil {
		log.Println("tlsServer handshake error:", err)
		serverConn.Close()
		clientConn.Close()
		return 
	}
	go func () {
		defer serverConn.Close()
		defer clientConn.Close()
		if _,err := io.Copy(tlsClientConn,tlsServerConn);err != nil {
			log.Println("failted to TLSCopy Server to Client")
			return 
		}
	}()
	if _,err := io.Copy(tlsServerConn,tlsClientConn);err != nil {
		defer serverConn.Close()
		defer clientConn.Close()
	          log.Println("failted to TLSCopy Server to Client")
		return 
	}
}