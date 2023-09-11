package w7dth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

type W7DTH struct {
	key []byte
}

func New() *W7DTH {
	return &W7DTH{}
}

func (w *W7DTH) Key(generate string) (string, error) {
	if generate == "generate" {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return "", err
		}
		w.key = key
		return hex.EncodeToString(key), nil
	}
	key, err := hex.DecodeString(generate)
	if err != nil {
		return "", err
	}
	w.key = key
	return generate, nil
}

func (w *W7DTH) Encrypt(data string) (string, error) {
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

func (w *W7DTH) Decrypt(data string) (string, error) {
	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
