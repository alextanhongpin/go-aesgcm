package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func main() {
	keyPhrase := "app.aesgcm"
	plaintext := []byte("hello world")

	nonceCiphertext, err := encrypt(keyPhrase, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println("ciphered:", hex.EncodeToString(nonceCiphertext))

	originalData, err := decrypt(keyPhrase, nonceCiphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println("plaintext:", string(originalData))
}

func md5Hashing(input string) string {
	byteInput := []byte(input)
	md5Hash := md5.Sum(byteInput)
	return hex.EncodeToString(md5Hash[:])
}

func encrypt(keyPhrase string, plaintext []byte) ([]byte, error) {
	// The key phrase is hashed for increased security.
	block, err := aes.NewCipher([]byte(md5Hashing(keyPhrase)))
	if err != nil {
		return nil, err
	}

	// Returns a 128-bit block cipher with a nonce length.
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the plain text using the nonce.
	// Here, nonceCiphertext consist of both nonce + cipheredText, so that we don't have
	// to keep track of the nonce separately when decrypting.
	//
	// nonce := nonceCiphertext[:nonceSize]
	// ciphertext := nonceCiphertext[nonceSize:]
	nonceCiphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)

	return nonceCiphertext, nil
}

func decrypt(keyPhrase string, nonceCiphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(md5Hashing(keyPhrase)))
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	nonce, ciphertext := nonceCiphertext[:nonceSize], nonceCiphertext[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
