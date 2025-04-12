package main

// miactf{S1gma_s1gma_b0y_S1gma_b0y_s1GMA_B0Y}
// Kazhdaya_devchonka_hochet_tancevat_s_toboy!

import (
	"encoding/hex"
	"fmt"
	"os"
)

const (
	argSize   = 22
	envSize   = 21
	xorKeyHex = "26081b0b100702326e0308173c1b5e090600000a5f1a3736453819003101550f3e076e34123530205f205c"
	expected  = "Kazhdaya_devchonka_hochet_tancevat_s_toboy!"
)

func xorEncrypt(input string, key []byte) string {
	result := make([]byte, len(input))
	keyLen := len(key)

	for i := 0; i < len(input); i++ {
		result[i] = input[i] ^ key[i%keyLen]
	}

	return string(result)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sigmach.go <22-symbol string>")
		return
	}

	arg := os.Args[1]
	if len(arg) != argSize {
		fmt.Println("Error: size must be 22")
		return
	}

	envVar := os.Getenv("SIGMA_BOY")
	if len(envVar) != envSize {
		fmt.Println("Error: size must be 21")
		return
	}

	xorKey, err := hex.DecodeString(xorKeyHex)
	if err != nil {
		fmt.Println("Error decoding xorKey:", err)
		return
	}

	combined := arg + envVar
	encrypted := xorEncrypt(combined, xorKey)

	if encrypted == expected {
		fmt.Println("You are a real sigmach!")
	} else {
		fmt.Println("You are a real imposter!")
	}
}
