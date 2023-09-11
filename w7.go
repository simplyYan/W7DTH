package w7

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

type W7 struct {
	key []byte
}

func New() *W7 {
	return &W7{}
}

func (w *W7) Key(generate string) (string, error) {
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

func (w *W7) Encrypt(data string) (string, error) {
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

func (w *W7) Decrypt(data string) (string, error) {
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
