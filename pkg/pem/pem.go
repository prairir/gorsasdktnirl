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

	pemBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("pem.GenPemRSAPublic error: %w", err)
	}
	pemkey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pemBytes,
	}
	err = pem.Encode(out, pemkey)
	if err != nil {
		return fmt.Errorf("pem.GenPemRSAPublic error: %w", err)
	}
	return nil
}

func readPem(infile string) (*pem.Block, error) {
	// read in the file
	data, err := os.ReadFile(infile)
	if err != nil {
		return nil, fmt.Errorf("pem.readPem error: %w", err)
	}

	// change data to pem block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem.readPem error: Unable to decode PEM")
	}
	return block, nil
}

func ParseRSAPublicKeyPem(infile string) (*rsa.PublicKey, error) {
	block, err := readPem(infile)
	// if err isnt nil
	// or if pem type isnt "RSA PUBLIC KEY"
	if err != nil {
		return nil, fmt.Errorf("pem.ParseRSAPublicKeyPem error: %w", err)
	} else if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("pem.ParseRSAPublicKeyPem error: not a RSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if block == nil {
		return nil, fmt.Errorf("pem.readPem error: %w", err)
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("pem.ParseRSAPublicKeyPem error: not a RSA public key")
	}
}

func ParseRSAPrivateKeyPem(infile string) (*rsa.PrivateKey, error) {
	block, err := readPem(infile)
	// if err isnt nil
	// or if pem type isnt "RSA PUBLIC KEY"
	if err != nil {
		return nil, fmt.Errorf("pem.ParseRSAPrivateKeyPem error: %w", err)
	} else if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("pem.ParseRSAPrivateKeyPem error: not a RSA private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pem.ParseRSAPrivaKeyPem error: %w", err)
	}

	return priv, nil

}
