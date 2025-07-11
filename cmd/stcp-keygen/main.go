package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/taodev/pkg/types"
	"github.com/taodev/stcp/key"
)

func main() {
	keyPath := flag.String("f", "id_stcp", "save path")
	keyValue := flag.String("k", "", "private key")
	flag.Parse()

	var privateKey types.Binary
	var err error
	if *keyValue != "" {
		privateKey, err = key.Base64(*keyValue)
		if err != nil {
			fmt.Println("Base64 err:", err)
			os.Exit(1)
		}
	} else {
		privateKey, err = key.Generate(*keyPath)
		if err != nil {
			fmt.Println("Generate err:", err)
			os.Exit(1)
		}
	}

	publicKey, err := key.PublicKey(privateKey)
	if err != nil {
		fmt.Println("PublicKey err:", err)
		os.Exit(1)
	}
	fmt.Println("publicKey:", publicKey)
}
