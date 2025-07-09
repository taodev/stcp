package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

func main() {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Private Key: %x\n", privateKey.Bytes())

	publicKey := privateKey.PublicKey()
	fmt.Printf("Public Key: %x\n", publicKey.Bytes())
}
