package keyexchange

import (
	"crypto/rand"
	"encoding/base64"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF is a key derivation function (KDF) based on the HMAC message authentication code.  HKDF conforms with the KDF interface.
type HKDF struct {
	KDF

	nonce    []byte
	HashSize int
}

// NewHKDF creates a new HKDF struct.
func NewHKDF() *HKDF {
	return &HKDF{}
}

// Nonce returns the nonce.
func (k *HKDF) Nonce() []byte {
	return k.nonce
}

// Derivekey creates a single HKDF key from a sharedSecret.
// Use Reader() and Next() to create multiple derived keys from a single sharedSecret.
func (k *HKDF) DeriveKey(
	sharedSecret string,
	hash func() hash.Hash,
	nonce []byte,
	additionalData []byte,
) (b []byte, err error) {
	r, err := k.Reader(
		sharedSecret,
		hash,
		nonce,
		additionalData,
	)
	if err != nil {
		return nil, ErrDeriveKey
	}
	return k.Next(r)
}

// Reader creates a reader to allow reading multiple HKDF derived keys from a single sharedSecret
func (k *HKDF) Reader(
	sharedSecret string,
	hash func() hash.Hash,
	nonce []byte,
	additionalData []byte,
) (r io.Reader, err error) {
	if nonce == nil {
		nonce = make([]byte, hash().Size())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
	}
	key, err := base64.StdEncoding.DecodeString(sharedSecret)
	if err != nil {
		return nil, err
	}
	k.nonce = nonce
	k.HashSize = hash().Size()
	return hkdf.New(hash, key, nonce, additionalData), nil
}

// Next returns the next HKDF key from the sharedSecret with the size hash().Size().
func (k *HKDF) Next(r io.Reader) (b []byte, err error) {
	b = make([]byte, k.HashSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
