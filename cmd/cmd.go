package cmd

import (
	"flag"
	"fmt"
	"os"
)

func Execute() {
	if len(os.Args) < 2 {
		fmt.Println("expected 'gen', 'encrypt', or 'decrypt' subcommands")
		os.Exit(1)
	}

	genCmd := flag.NewFlagSet("gen", flag.ExitOnError)
	size := genCmd.Int("size", 0, "size of key")

	encCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	var message string
	encCmd.StringVar(&message, "message", "", "message to encrypt")

	decCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decCmd.StringVar(&message, "message", "", "message to encrypt")

	switch os.Args[1] {
	case "gen":
		fmt.Println("gen")
		genCmd.Parse(os.Args[2:])
		fmt.Println(*size)
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
