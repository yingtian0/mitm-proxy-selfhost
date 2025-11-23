package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func LoadCACertAndCAKey(caCertPath,caKeyPath string) (*x509.Certificate,any,error) {
	caCertFileBytes,err := os.ReadFile(caCertPath)
	if err != nil {
		return nil,nil,fmt.Errorf("readcaCertFile error: %v",err)
	}
	caCertBlock,_ := pem.Decode(caCertFileBytes)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block for CA cert")
	}
	caCert,err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil,nil,fmt.Errorf("failed to parse caCert: %v",err)
	}
	caKeyBytes,err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil,nil,fmt.Errorf("readcaKeyFile error: %v",err)
	}
	caKeyBlock,_ := pem.Decode(caKeyBytes)
	if caKeyBlock == nil {
		return nil,nil,fmt.Errorf("failed to decode PEM block for CA private Key")
	}
	caKey,err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil,nil,fmt.Errorf("failed to parse caKey: %v",err)
	}
	return caCert,caKey,nil
}

func LoadEnv() (error) {
          err := godotenv.Load(".env")
	if err != nil {
	    return fmt.Errorf("failed to load envfile:%v",err)
	}
	return nil
}

func GetEnv(key string) (string,error) {
	val, ok := os.LookupEnv(key)
	if (!ok || val == "") {
	    return "",fmt.Errorf("failed to load envfile:%v")
	}
	return val,nil
}