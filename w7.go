package w7dth

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"time"
)

type W7DTH struct{}

func New() *W7DTH {
	return &W7DTH{}
}

func (w *W7DTH) key(generate string) string {
	if generate == "generate" {
		rand.Seed(time.Now().UnixNano())
		key := make([]byte, 32)
		rand.Read(key)
		return hex.EncodeToString(key)
	}
	return generate
}

func (w *W7DTH) Encrypt(data string, key string) string {
	hash := sha256.New()
	hash.Write([]byte(data + key))
	return hex.EncodeToString(hash.Sum(nil))
}

func (w *W7DTH) Decrypt(data string, key string) string {
	// SHA-256 is a one-way function, it cannot be decrypted
	return ""
}
