package cmd

import (
	"flag"
	"fmt"
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
	outFilePriv := genCmd.String("out-file-priv", "stdout", "output file for private key PEM")
	outFilePub := genCmd.String("out-file-pub", "stdout", "output file for public key PEM")

	encCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	var message string
	encCmd.StringVar(&message, "message", "", "message to encrypt")

	decCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decCmd.StringVar(&message, "message", "", "message to encrypt")

	switch os.Args[1] {
	case "gen":
		genCmd.Parse(os.Args[2:])
		key, err := rsa.GenerateKeys(*size)
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
		fmt.Println("encrypt")
		encCmd.Parse(os.Args[2:])
		fmt.Println(message)
	case "decrypt":
		fmt.Println("decrypt")
		decCmd.Parse(os.Args[2:])
		fmt.Println(message)
	default:
		fmt.Println("expected 'gen', 'encrypt', or 'decrypt' subcommands")
		os.Exit(1)
	}

}
