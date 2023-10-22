package keyexchange

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305 combines the ChaCha20 stream cipher with the Poly1305 message authentication code.  haCha20Poly1305 conforms with the AEAD interface.
type ChaCha20Poly1305 struct {
	AEAD
}

// NewChaCha20Poly1305 creates a new ChaCha20Poly1305 struct.
func NewChaCha20Poly1305() *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{}
}

// Encrypt encrypts using the symmetricKey, kdfNonce, plaintext, aeadNonce, and additionalData.
func (c *ChaCha20Poly1305) Encrypt(symmetricKey, kdfNonce, plaintext, aeadNonce, additionalData []byte) (*AEADStore, error) {
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		return nil, err
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	if aeadNonce == nil {
		aeadNonce = make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
		if _, err := io.ReadFull(rand.Reader, aeadNonce); err != nil {
			return nil, err
		}
	}

	// Creates combined ciphertext -> nonce + cyphertext + additionalData
	return &AEADStore{
		KDFNonce:       kdfNonce,
		Ciphertext:     aead.Seal(aeadNonce, aeadNonce, plaintext, additionalData),
		AEADNonce:      aeadNonce,
		AdditionalData: additionalData,
	}, nil
}

// Decrypt decrypts using the symmetricKey, ciphertext, aeadNonce, and additionalData.
func (c *ChaCha20Poly1305) Decrypt(symmetricKey, ciphertext, aeadNonce, additionalData []byte) (plaintext []byte, err error) {
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, splitCiphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	return aead.Open(nil, nonce, splitCiphertext, additionalData)
}
