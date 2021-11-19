package cmd

import (
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/prairir/gorsasdktnirl/pkg/pem"
	"github.com/prairir/gorsasdktnirl/pkg/rsa"
)

func Execute() {
	if len(os.Args) < 2 {
		fmt.Println("expected 'gen', 'encrypt', or 'decrypt' subcommands")
		os.Exit(1)
	}

	genCmd := flag.NewFlagSet("gen", flag.ExitOnError)
	size := genCmd.Int("size", 0, "size of key")
	outFilePriv := genCmd.String("outfile-priv", "stdout", "output file for private key PEM")
	outFilePub := genCmd.String("outfile-pub", "stdout", "output file for public key PEM")
	p := genCmd.Int64("p", 0, "prime number for RSA, If 0 or not a prime then will be randomly generated")
	q := genCmd.Int64("q", 0, "prime number for RSA, If 0 or not a prime then will be randomly generated")

	var infile string
	var keyfile string
	var outfile string

	encCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	encCmd.StringVar(&infile, "infile", "", "the contents of this file will be encrypted")
	encCmd.StringVar(&keyfile, "public-key", "", "RSA public key to encrypt message")
	encCmd.StringVar(&outfile, "outfile", "", "write the encrypted message to a file")

	decCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decCmd.StringVar(&keyfile, "private-key", "", "RSA private key to decrypt message")
	decCmd.StringVar(&outfile, "outfile", "", "write the decrypted message to a file")
	decCmd.StringVar(&infile, "infile", "", "the contents of this file will be decrypted")

	switch os.Args[1] {
	case "gen":
		genCmd.Parse(os.Args[2:])
		key, err := rsa.GenerateKeys(*size, big.NewInt(*p), big.NewInt(*q))
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}
		err = pem.GenPemRSAPrivate(key, *outFilePriv)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		err = pem.GenPemRSAPublic(&key.PublicKey, *outFilePub)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

	case "encrypt":
		encCmd.Parse(os.Args[2:])
		pub, err := pem.ParseRSAPublicKeyPem(keyfile)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		message, err := os.ReadFile(infile)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		encMessage, err := rsa.Encrypt(pub, message)
		if outfile != "" {
			os.WriteFile(outfile, encMessage, 0666)
		} else {
			fmt.Printf("%b\n", encMessage)
		}
	case "decrypt":
		decCmd.Parse(os.Args[2:])
		priv, err := pem.ParseRSAPrivateKeyPem(keyfile)
		if err != nil {
			fmt.Printf("FUCK\n%v\n", priv)
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		cipher, err := os.ReadFile(infile)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		message, err := rsa.Decrypt(priv, cipher)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		if outfile != "" {
			os.WriteFile(outfile, message, 0666)
		} else {
			fmt.Printf("%s\n", string(message))
		}

	default:
		fmt.Println("expected 'gen', 'encrypt', or 'decrypt' subcommands")
		os.Exit(1)
	}

}
