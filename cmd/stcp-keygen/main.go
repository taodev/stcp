package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	keypath := flag.String("f", "id_stcp", "save path")
	key := flag.String("k", "", "private key")
	flag.Parse()

	curve := ecdh.X25519()

	var privateKey *ecdh.PrivateKey
	var err error

	if *key != "" {
		keyBytes, err := base64.RawURLEncoding.DecodeString(*key)
		if err != nil {
			fmt.Printf("decode private key error: %v", err)
			os.Exit(1)
		}
		privateKey, err = curve.NewPrivateKey(keyBytes)
		if err != nil {
			fmt.Printf("private key error: %v", err)
			os.Exit(1)
		}
	} else if _, err = os.Stat(*keypath); err != nil {
		privateKey, err = curve.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Printf("generate private key error: %v", err)
			os.Exit(1)
		}
		keyBase64 := base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
		if err = os.WriteFile(*keypath, []byte(keyBase64), 0600); err != nil {
			fmt.Printf("write private key file error: %v", err)
			os.Exit(1)
		}
	} else {
		keyString, err := os.ReadFile(*keypath)
		if err != nil {
			fmt.Printf("read private key file error: %v", err)
			os.Exit(1)
		}
		keyBase64, err := base64.RawURLEncoding.DecodeString(string(keyString))
		if err != nil {
			fmt.Printf("decode private key error: %v", err)
			os.Exit(1)
		}
		privateKey, err = curve.NewPrivateKey(keyBase64)
		if err != nil {
			fmt.Printf("read private key file error: %v", err)
			os.Exit(1)
		}
	}

	pub := privateKey.PublicKey()
	fmt.Println(base64.RawURLEncoding.EncodeToString(pub.Bytes()))
}
