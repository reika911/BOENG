package main

import (
	"flag"
	"fmt"
	"os"

	"filippo.io/age"
)

func main() {
	privateKeyFile := flag.String("out-private", "id_age_private", "Path to save the private key")
	publicKeyFile := flag.String("out-public", "id_age_public", "Path to save the public key")
	flag.Parse()

	// Generate a new age identity
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating age key pair: %v\n", err)
		os.Exit(1)
	}

	// Save private key
	privateKeyBytes := []byte(identity.String())
	if err := os.WriteFile(*privateKeyFile, privateKeyBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
		os.Exit(1)
	}

	// Save public key
	publicKey := identity.Recipient().String()
	publicKeyBytes := []byte(publicKey + "\n")
	if err := os.WriteFile(*publicKeyFile, publicKeyBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Age key pair generated successfully:\nPrivate Key: %s\nPublic Key: %s\n", *privateKeyFile, *publicKeyFile)
}
