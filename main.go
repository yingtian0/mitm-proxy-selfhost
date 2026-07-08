package main

import (
	"log"
	"net/http"

	"github.com/mitm-proxy-selfhost/config"
	"github.com/mitm-proxy-selfhost/mitm"
)

func main() {
	err := config.LoadEnv()
	if err != nil {
		log.Fatal("LoadEnv:", err)
	}
	caCertPath, err := config.GetEnv("CA_CERT_PATH")
	if err != nil {
		log.Fatal("CA_CERT_PATH", err)
	}
	caKeyPath, err := config.GetEnv("CA_KEY_PATH")
	if err != nil {
		log.Fatal("CA_KEY_PATH:", err)
	}
	caCert, caKey, err := config.LoadCACertAndCAKey(caCertPath, caKeyPath)
	if err != nil {
		log.Fatal("LoadCACertAndCAKey", err)
	}
	proxy, err := mitm.NewProxy(caCert, caKey)
	if err != nil {
		log.Fatal("NewProxy:", err)
	}
	addr := ":8001"
	httpServer := &http.Server{
		Addr:    addr,
		Handler: proxy,
	}
	log.Printf("start serve MITM Proxy on %s", addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("failed to serve:", err)
	}
}
