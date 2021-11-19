package pem

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// pem.GenPemRSAPrivate: generate a pem private key with PKCS1 format and write to a file
// params: private key, file to write it to
// returns: error
func GenPemRSAPrivate(key *rsa.PrivateKey, outfile string) error {
	var out *os.File
	var err error
	// if the file is stdout, write to stdout
	// else create the file
	if outfile == "stdout" {
		out = os.Stdout
	} else {
		out, err = os.Create(outfile)
		if err != nil {
			return fmt.Errorf("pem.GenPemRSAPrivate error: %w", err)
		}
	}

	// make the rsa private key
	pemkey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	// encode it
	err = pem.Encode(out, pemkey)
	if err != nil {
		return fmt.Errorf("pem.GenPemRSAPrivate error: %w", err)
	}
	return nil
}

// pem.GenPemRSAPublic: generate a pem public key with PKIX format and write to a file
// params: public key, file to write it to
// returns: error
func GenPemRSAPublic(key *rsa.PublicKey, outfile string) error {
	var out *os.File
	var err error
	// if the file is stdout, write to stdout
	// else create the file
	if outfile == "stdout" {
		out = os.Stdout
	} else {
		out, err = os.Create(outfile)
		if err != nil {
			return fmt.Errorf("pem.GenPemRSAPublic error: %w", err)
		}
	}

	// make the pem from public key
	pemBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("pem.GenPemRSAPublic error: %w", err)
	}

	// make whole pem
	pemkey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pemBytes,
	}

	// encode into file
	err = pem.Encode(out, pemkey)
	if err != nil {
		return fmt.Errorf("pem.GenPemRSAPublic error: %w", err)
	}
	return nil
}

// rsa.readPem: read the pem file
// params: file to read from
// returns: pem block, error
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

// rsa.ParseRSAPublicKeyPem: parse pem and return rsa public key from it
// params: file to read from
// returns: public key, error
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

// rsa.ParseRSAPrivateKeyPem: parse pem and return rsa private key from it
// params: file to read from
// returns: private key, error
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
