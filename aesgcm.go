package keyexchange

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// AESGCM is the Advanced Encryption Standard (AES) Galois/Counter Mode (GCM) struct.  AESGCM conforms with the AEAD interface.
type AESGCM struct {
	AEAD
}

// NewAESGCM creates a new AESGCM struct.
func NewAESGCM() *AESGCM {
	return &AESGCM{}
}

// Encrypt encrypts using the symmetricKey, kdfNonce, plaintext, aeadNonce, and additionalData.
func (c *AESGCM) Encrypt(symmetricKey, kdfNonce, plaintext, aeadNonce, additionalData []byte) (*AEADStore, error) {
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	if aeadNonce == nil {
		aeadNonce = make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, aeadNonce); err != nil {
			return nil, err
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Creates combined ciphertext -> nonce + cyphertext + additionalData
	cyphertext := aeadNonce[:]
	return &AEADStore{
		KDFNonce:       kdfNonce,
		Ciphertext:     gcm.Seal(cyphertext, aeadNonce, plaintext, additionalData),
		AEADNonce:      aeadNonce,
		AdditionalData: additionalData,
	}, nil
}

// Decrypt decrypts using the symmetricKey, ciphertext, aeadNonce, and additionalData.
func (c *AESGCM) Decrypt(symmetricKey, ciphertext, aeadNonce, additionalData []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Strip nonce from the start of the combined ciphertext
	ciphertextWithoutNonce := ciphertext[len(aeadNonce):]
	return gcm.Open(nil, aeadNonce, ciphertextWithoutNonce, additionalData)
}
