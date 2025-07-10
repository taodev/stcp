package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/taodev/stcp/keygen"
)

func main() {
	keypath := flag.String("f", "id_stcp", "save path")
	key := flag.String("k", "", "private key")
	flag.Parse()

	if *key != "" {
		pub, err := keygen.PublicKey(*key)
		if err != nil {
			fmt.Println("PublicKey err:", err)
			os.Exit(1)
		}
		fmt.Println(pub)
		return
	}

	pub, err := keygen.KeyGen(*keypath)
	if err != nil {
		fmt.Println("KeyGen err:", err)
		os.Exit(1)
	}
	fmt.Println(pub)
}
