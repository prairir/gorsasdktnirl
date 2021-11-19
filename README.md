# GORSASDKTNIRL

**DONT USE THIS**
Rolling your own crypto is bad and I did this for fun. Really, dont use this

## Naming

**GO** **R**ivest-**S**hamir-**A**dleman **S**oftware **D**evelopment **K**it **T**his **N**ame **I**s **R**eally **L**ong

Thats what the name stands for

*I know this isnt technically a software development kit*

### Why the name?
Because its stupid and fun. Dumb fun naming is a good time :)

## Build

This a is a typical golang project so you can just

``` sh
go build main.go
```

## Run

There is 3 subcommands

`gen`, `encrypt`, `decrypt` are the sub commands

### `gen`

This generates the RSA keys

``` sh
Usage of gen:
  -outfile-priv string
    	output file for private key PEM (default "stdout")
  -outfile-pub string
    	output file for public key PEM (default "stdout")
  -p int
    	prime number for RSA, If 0 or not a prime then will be randomly generated
  -q int
    	prime number for RSA, If 0 or not a prime then will be randomly generated
  -size int
    	size of key
```

`-size` is the only required field

You can run it like

### `encrypt`

This encrypts the contents of a file with the public key

``` sh
Usage of encrypt:
  -infile string
    	the contents of this file will be encrypted
  -outfile string
    	write the encrypted message to a file
  -public-key string
    	RSA public key to encrypt message
```

`-infile` and `-pulic-key` are required

### `decrypt`

This decrypts the contents of a file with the private key

``` sh
Usage of decrypt:
  -infile string
    	the contents of this file will be decrypted
  -outfile string
    	write the decrypted message to a file
  -private-key string
    	RSA private key to decrypt message
```

