package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa" // even though im importing it, im just using the struct
	"fmt"
	"math/big"
)

// rsa.GenerateKeys: generate RSA keys
// params: bit length of keys
// returns: public key, private key, error
func GenerateKeys(bitlen int, p *big.Int, q *big.Int) (*rsa.PrivateKey, error) {
	// if bitlen is 0, error
	if bitlen == 0 {
		return nil, fmt.Errorf("rsa.GenerateKeys error: bitlen must be over 0")
	}

	var err error

	retries := 0
	for ; ; retries++ {
		// if it takes more than 10 retries, error
		if retries == 10 {
			return nil, fmt.Errorf("rsa.GenerateKeys error: Too many retries")
		}

		// if p is 0 then randomize it
		// or it is not prime
		if p.Cmp(big.NewInt(0)) == 0 || !p.ProbablyPrime(10) {
			// make p a random prime number
			p, err = rand.Prime(rand.Reader, bitlen/2)
			if err != nil {
				return nil, fmt.Errorf("rsa.GenerateKeys error: %w", err)
			}
		}

		// if q is 0 then randomize it
		// or it is not prime
		if q.Cmp(big.NewInt(0)) == 0 || !q.ProbablyPrime(10) {
			// make p a random prime number
			q, err = rand.Prime(rand.Reader, bitlen/2)
			if err != nil {
				return nil, fmt.Errorf("rsa.GenerateKeys error: %w", err)
			}
		}

		// n is p * q
		n := new(big.Int).Set(p)
		n.Mul(n, q)

		// if they dont equal, regen
		if n.BitLen() != bitlen {
			continue
		}

		// subtract 1 from each p and q
		p.Sub(p, big.NewInt(1))
		q.Sub(q, big.NewInt(1))
		// eulers totient
		// because totient(n) = (p -1)(q -1) we can just set it to those values
		totient := new(big.Int).Set(p)
		totient.Mul(totient, q)

		// this e value does not hurt security but significantly increases efficiency
		e := big.NewInt(65537)

		d := new(big.Int).ModInverse(e, totient)
		// if d doesnt get value, try again
		if d == nil {
			continue
		}

		// because we subtracted them before
		// we need both p and q for the struct
		p.Add(p, big.NewInt(1))
		q.Add(q, big.NewInt(1))

		// this is the key as defined by golang crypto/rsa
		key := rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: 65537,
			},
			D:           d,
			Primes:      []*big.Int{p, q},
			Precomputed: rsa.PrecomputedValues{},
		}

		return &key, nil
	}
}

// rsa.Encrypt: encrypt a message with a public key
// This follows RFC2313
// params: public key, message
// returns: cipher or error
func Encrypt(pub *rsa.PublicKey, message []byte) ([]byte, error) {
	// the specification for this is in RFC2313

	// length of key
	// divide by 8 octets
	keyLength := (pub.N.BitLen() + 7) / 8
	// -11 for the octet length
	if len(message) > keyLength-11 {
		return nil, fmt.Errorf("rsa.Encrypt error: message too long")
	}

	// we have to format the message into an encryption block
	// it has to take the format
	// EB = 00 || BT || PS || 00 || D
	// EB is the encryption block
	// BT is block type
	// PS is padding string
	// D is data
	//
	// BT of 02 is reccomended by RFC2313 as it is the most secure for public key stuff

	// PS length is k - 3 - ||D||
	padStrLen := keyLength - len(message) - 3
	encBlock := make([]byte, keyLength)
	encBlock[1] = 0x02

	// Fill PS with random garbage
	// start at 2 because were skipping the first 2 sector
	for i := 2; i < 2+padStrLen; {
		_, err := rand.Read(encBlock[i : i+1]) // only read into the encBlock for the sector we want
		if err != nil {
			return nil, fmt.Errorf("rsa.Encrypt error: %w", err)
		}
		// as the block is filled with 0x00, we need to make sure the read was filled with something that isnt that
		// if it isnt filled with it, move onto the next sector
		if encBlock[i] != 0x00 {
			i++
		}
	}

	// put a 0x00 after the pad string
	encBlock[2+padStrLen] = 0x00

	// copy the message into the rest of the encrypt block
	copy(encBlock[3+padStrLen:], message)

	// the encrypt block is now finished being setup
	// message as big.Int
	m := new(big.Int).SetBytes(encBlock)

	// do the actual encryption stuff
	cipher := new(big.Int)
	cipher.Exp(m, big.NewInt(int64(pub.E)), pub.N)

	// we gotta pad the cipher with 0x00 to the left
	encMessage := make([]byte, keyLength) // this generates a []byte with 0x00 in each element
	copy(encMessage[(keyLength-len(cipher.Bytes())):], cipher.Bytes())
	return encMessage, nil
}

// rsa.Decrypt: Decrypt a cipher with a private key
// This follows RFC2313
// params: private key, cipher
// returns: message or error
func Decrypt(priv *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	// same thing as in rsa.Encrypt
	keyLength := (priv.N.BitLen() + 7) / 8
	if len(cipher) != keyLength {
		return nil, fmt.Errorf("rsa.Decrypt error: cipher length has to match private key length")
	}

	// make the cipher into big.Int
	c := new(big.Int).SetBytes(cipher)
	m := new(big.Int).Exp(c, priv.D, priv.N) // the actually decryption

	message := make([]byte, keyLength)
	copy(message[keyLength-len(m.Bytes()):], m.Bytes())

	if message[0] != 0x00 {
		return nil, fmt.Errorf("rsa.Decrypt error: message sector 1 needs to be 0x00")
	}
	if message[1] != 0x02 {
		return nil, fmt.Errorf("rsa.Decrypt error: message sector 2 needs to be 0x02")
	}

	// find the index of 0x00
	endPadding := bytes.IndexByte(message[2:], 0x00) + 2
	if endPadding < 2 {
		return nil, fmt.Errorf("rsa.Decrypt error: no end padding")
	}
	return message[endPadding+1:], nil
}
