package keyexchange

import (
	"encoding/base64"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestChaCha20Poly1305EncryptAndDecrypt(t *testing.T) {
	aead := NewChaCha20Poly1305()

	key, _ := base64.StdEncoding.DecodeString("LhxSAkC2BKy6FsGy+hJ/U+mJwzxXl5tvCYzEo0Q1bkE=")
	plaintext := []byte("exampleplaintext")
	aeadNonce, _ := base64.StdEncoding.DecodeString("hAqd8PI6RlEhVikF")
	additionalData := []byte("abc")
	ciphertext, _ := base64.StdEncoding.DecodeString("hAqd8PI6RlEhVikFovtSMzKvyGqggJvjtsK3ZFnyvIhU+YL/+taFktRMSlI=")

	// Encrypt
	d, err := aead.Encrypt(key, nil, plaintext, aeadNonce, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, d.Ciphertext, ciphertext)
	assert.Equal(t, d.AEADNonce, aeadNonce)
	assert.Equal(t, d.AdditionalData, additionalData)

	// Decrypt
	b, err := aead.Decrypt(key, d.Ciphertext, d.AEADNonce, d.AdditionalData)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plaintext, b)
}
