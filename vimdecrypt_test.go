package vimdecrypt

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	password := []byte("strongpassword")
	plaintext := []byte("This is a secret message.")

	// Test encryption
	encrypted, err := Encrypt(plaintext, password)
	fmt.Printf("encrypted: %x\n", encrypted)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Test decryption
	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Check if decryption matches original plaintext
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match original.\nGot: %s\nWant: %s", decrypted, plaintext)
	} else {
		fmt.Println(string(decrypted))
	}

}

func TestWriteFile(t *testing.T) {
	// Open the file for writing (create if not exists, truncate if exists)
	file, err := os.OpenFile("output.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	password := []byte("strongpassword")
	plaintext := []byte("This is a secret message.")

	// Test encryption
	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Write binary data to the file
	_, err = file.Write(encrypted)
}
