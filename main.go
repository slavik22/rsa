package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

func main() {
	// Step 1: Key generation
	p, q := generatePrimes(1024)
	n := new(big.Int).Mul(p, q)
	m := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, m)

	publicKey := &rsaPublicKey{n, e}
	privateKey := &rsaPrivateKey{n, d}

	// Step 2: Encryption
	message := new(big.Int).SetBytes([]byte("Hello, RSA encryption!"))
	ciphertext := encrypt(message, publicKey)
	fmt.Println("Encrypted message:", ciphertext)

	// Step 3: Decryption
	decryptedMessage := decrypt(ciphertext, privateKey)
	fmt.Println("Decrypted message:", string(decryptedMessage.Bytes()))
}

type rsaPublicKey struct {
	N *big.Int
	E *big.Int
}

type rsaPrivateKey struct {
	N *big.Int
	D *big.Int
}

func encrypt(message *big.Int, publicKey *rsaPublicKey) *big.Int {
	return new(big.Int).Exp(message, publicKey.E, publicKey.N)
}

func decrypt(ciphertext *big.Int, privateKey *rsaPrivateKey) *big.Int {
	return new(big.Int).Exp(ciphertext, privateKey.D, privateKey.N)
}

func generatePrimes(bits int) (*big.Int, *big.Int) {
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		log.Fatal("Error generating prime:", err)
	}

	q, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		log.Fatal("Error generating prime:", err)
	}

	return p, q
}
