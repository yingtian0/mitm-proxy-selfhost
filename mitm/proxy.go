package mitm

import (
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
	caKey  any
}

func NewProxy(caCert *x509.Certificate, caKey any) (*Proxy, error) {
	newProxy := Proxy{
		caCert: caCert,
		caKey:  caKey,
	}
	return &newProxy, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.HandleConnect(w,r)
	}
}

func (p *Proxy) HandleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":443" 
	}
	serverConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		http.Error(w, "failed to connect target: "+err.Error(), http.StatusServiceUnavailable)
		log.Println("failed to connect target:", err)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		serverConn.Close()
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "failed to hijack tcp socket: "+err.Error(), http.StatusInternalServerError)
		serverConn.Close()
		return
	}
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Println("failed to write 200 OK:", err)
		serverConn.Close()
		clientConn.Close()
		return
	}
	cert := GenerateServerCertificate(r.Host, p.caCert, p.caKey)
	tlsClientConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsClientConn.Handshake(); err != nil {
		log.Println("tlsClient handshake error:", err)
		serverConn.Close()
		clientConn.Close()
		return
	}
	hostName := r.Host
	if strings.Contains(hostName, ":") {
		hostName, _, _ = net.SplitHostPort(hostName)
	}
	tlsServerConn := tls.Client(serverConn, &tls.Config{
		ServerName: hostName, 
	})
	if err := tlsServerConn.Handshake(); err != nil {
		log.Println("tlsServer handshake error:", err)
		serverConn.Close()
		clientConn.Close()
		return
	}
	go func() {
		defer serverConn.Close()
		defer clientConn.Close()
		if _, err := io.Copy(tlsClientConn, tlsServerConn); err != nil {
			if err != io.EOF {
				log.Println("copy server->client error:", err)
			}
		}
	}()
	if _, err := io.Copy(tlsServerConn, tlsClientConn); err != nil {
		if err != io.EOF {
			log.Println("copy client->server error:", err)
		}
	}
	serverConn.Close()
	clientConn.Close()
}