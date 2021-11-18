package rsa

import (
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
			fmt.Println("generating p")
			// make p a random prime number
			p, err = rand.Prime(rand.Reader, bitlen/2)
			if err != nil {
				return nil, fmt.Errorf("rsa.GenerateKeys error: %w", err)
			}
		}

		// if q is 0 then randomize it
		// or it is not prime
		if q.Cmp(big.NewInt(0)) == 0 || !q.ProbablyPrime(10) {
			fmt.Println("generating q")
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
