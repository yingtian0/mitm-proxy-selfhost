package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func LoadCACertAndCAKey(caCertPath, caKeyPath string) (*x509.Certificate, any, error) {
	caCertFileBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert file: %w", err)
	}
	caCertBlock, _ := pem.Decode(caCertFileBytes)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block for CA cert")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ca cert: %w", err)
	}
	caKeyBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca key file: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block for CA private key")
	}
	caKey, err := parsePrivateKey(caKeyBlock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ca key: %w", err)
	}
	return caCert, caKey, nil
}

func parsePrivateKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			return key, nil
		}
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("unsupported private key type %q", block.Type)
	}
}

func LoadEnv() error {
	err := godotenv.Load(".env")
	if err != nil {
		return fmt.Errorf("failed to load env file: %w", err)
	}
	return nil
}

func GetEnv(key string) (string, error) {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return "", fmt.Errorf("environment variable %s is not set", key)
	}
	return val, nil
}
