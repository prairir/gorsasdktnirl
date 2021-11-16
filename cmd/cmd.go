package cmd

import (
	//"flag"
	"fmt"
	"os"
)

func Execute() {
	/*
		genCmd := flag.NewFlagSet("gen", flag.ExitOnError)
		encCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
		decCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	*/

	if len(os.Args) < 2 {
		fmt.Println("expected 'gen', 'encrypt', or 'decrypt' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "gen":
		fmt.Println("gen")
	case "encrypt":
		fmt.Println("encrypt")
	case "decrypt":
		fmt.Println("decrypt")
	default:
		fmt.Println("expected 'gen', 'encrypt', or 'decrypt' subcommands")
		os.Exit(1)
	}

}
