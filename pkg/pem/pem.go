package pem

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func GenPemRSAPrivate(key *rsa.PrivateKey, outfile string) error {
	var out *os.File
	var err error
	if outfile == "stdout" {
		out = os.Stdout
	} else {
		out, err = os.Create(outfile)
		if err != nil {
			return fmt.Errorf("pem.GenPemRSAPrivate error: %w", err)
		}
	}
	pemkey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	err = pem.Encode(out, pemkey)
	if err != nil {
		return fmt.Errorf("pem.GenPemRSAPrivate error: %w", err)
	}
	return nil
}

func GenPemRSAPublic(key *rsa.PublicKey, outfile string) error {
	var out *os.File
	var err error
	if outfile == "stdout" {
		out = os.Stdout
	} else {
		out, err = os.Create(outfile)
		if err != nil {
			return fmt.Errorf("pem.GenPemRSAPublic error: %w", err)
		}
	}
	pemkey := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	}
	err = pem.Encode(out, pemkey)
	if err != nil {
		return fmt.Errorf("pem.GenPemRSAPublic error: %w", err)
	}
	return nil
}
