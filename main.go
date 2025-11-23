package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/mitm-proxy-selfhost/config"
	"github.com/mitm-proxy-selfhost/mitm"
)


func main() {
	err := config.LoadEnv()
	if err != nil {
		log.Fatal("LoadEnv:",err)
	}
	caCertPath,err := config.GetEnv("CA_CERT_PATH")
	if err != nil {
		log.Fatal("CA_CERT_PATH",err)
	}
	caKeyPath,err := config.GetEnv("CA_KEY_PATH")
	if err != nil {
		log.Fatal("CA_KEY_PATH:",err)
	}
	caCert,caKey,err := config.LoadCACertAndCAKey(caCertPath,caKeyPath)
	if err != nil {
		log.Fatal("LoadCACertAndCAKey",err)
	}
	proxy,err  := mitm.NewProxy(caCert,caKey)
	if err != nil {
		log.Fatal("NewProxy:",err)
	}

	http.HandleFunc("/",func (w http.ResponseWriter,r *http.Request) {
		if strings.ToUpper(r.Method) == "CONNECT" {
			proxy.HandleConnect(w,r)
			return 
		}
		http.Error(w,"this handler only support connect method",http.StatusMethodNotAllowed)
	})
	
	addr := ":8001"
	httpServer := &http.Server{
		Addr: addr,
	}
	log.Printf("start serve MITM Proxy")
         if err := httpServer.ListenAndServe();err != nil && err != http.ErrServerClosed{	
             log.Fatal("failted to serve:",err) 
         }
}