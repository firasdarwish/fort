/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

// Credits to https://www.melvinvivas.com/how-to-encrypt-and-decrypt-data-using-aes

func aesEncrypt(key []byte, payload string) (string, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())

	ciphertext := gcm.Seal(nonce, nonce, []byte(payload), nil)

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func aesDecrypt(key []byte, encText string) (string, error) {
	enc, err := base64.RawURLEncoding.DecodeString(encText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
