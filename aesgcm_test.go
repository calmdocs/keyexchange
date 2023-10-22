package keyexchange

import (
	"encoding/base64"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestAESGCMEncryptAndDecrypt(t *testing.T) {
	aead := NewAESGCM()

	key, _ := base64.StdEncoding.DecodeString("LhxSAkC2BKy6FsGy+hJ/U+mJwzxXl5tvCYzEo0Q1bkE=")
	plaintext := []byte("exampleplaintext")
	aeadNonce, _ := base64.StdEncoding.DecodeString("hAqd8PI6RlEhVikF")
	additionalData := []byte("abc")
	//ciphertext, _ := base64.StdEncoding.DecodeString("lLWMvnibSUxvhIKue/0opwrnrJduO/8Lt/xF52C+wIk=")
	ciphertext, _ := base64.StdEncoding.DecodeString("hAqd8PI6RlEhVikFlLWMvnibSUxvhIKue/0opwrnrJduO/8Lt/xF52C+wIk=")

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
