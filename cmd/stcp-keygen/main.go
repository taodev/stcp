package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Private Key:\n")
	fmt.Printf("hex: %x\n", privateKey.Bytes())
	fmt.Println("base64:", base64.RawStdEncoding.EncodeToString(privateKey.Bytes()))

	publicKey := privateKey.PublicKey()
	fmt.Printf("Public Key:\n")
	fmt.Printf("hex: %x\n", publicKey.Bytes())
	fmt.Println("base64:", base64.RawStdEncoding.EncodeToString(publicKey.Bytes()))
}
