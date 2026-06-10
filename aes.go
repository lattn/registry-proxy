package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// aesEncrypt encrypts plaintext with the derived key.
func aesEncrypt(plaintext []byte, key []byte) (encrypted []byte, err error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		err = fmt.Errorf("can't initialize crypto: %w", err)
		return
	}
	encrypted = gcm.Seal(nil, nonce, plaintext, nil)
	encrypted = append(nonce, encrypted...)
	return
}

// aesDecrypt decrypts ciphertext with the derived key.
func aesDecrypt(encrypted []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		err = errors.New("ciphertext too short")
		return
	}
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	return
}

// aesKey generates a 16-byte key from the input using MD5.
func aesKey(key []byte) []byte {
	hash := md5.New()
	hash.Write(key)
	return hash.Sum(nil)
}
