package keyexchange

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
)

var ErrMarsal = errors.New("marshal error")
var ErrEncrypt = errors.New("encrypt error")
var ErrUnmarsal = errors.New("unmarshal error")
var ErrUnmarsalAEADStore = errors.New("AEADStore unmarshal error")
var ErrDeriveKey = errors.New("derive key error")
var ErrDecrypt = errors.New("decrypt error")
var ErrAdditionalData = errors.New("additional data authentication error")
var ErrPublicKeyNotSet = errors.New("external public key not set")

// Store stores key exchange variables.
type Store struct {
	curve             ecdh.Curve
	hash              func() hash.Hash
	kdf               KDF
	aead              AEAD
	ecdhPrivateKey    *ecdh.PrivateKey
	externalPublicKey string
	sharedSecret      string
}

// KDFStore stores key derivation function (KDF) variables.
type KDFStore struct {
	Key            []byte
	Nonce          []byte
	AdditionalData []byte
}

// AEADStore stores authenticated encryption with associated data (AEAD) variables.
type AEADStore struct {
	KDFNonce       []byte
	Ciphertext     []byte
	AEADNonce      []byte
	AdditionalData []byte
}

// KDF is the interface for key derivation functions (KDFs).
type KDF interface {
	Nonce() []byte
	DeriveKey(sharedSecret string, hash func() hash.Hash, nonce []byte, additionalData []byte) (b []byte, err error)
	Reader(sharedSecret string, hash func() hash.Hash, nonce []byte, additionalData []byte) (io.Reader, error)
	Next(r io.Reader) (b []byte, err error)
}

// AEAD is the interface for authenticated encryption with associated data (AEAD) ciphers.
type AEAD interface {
	Encrypt(symmetricKey, symmetricKeyNonce, plaintext, aeadNonce, additionalData []byte) (*AEADStore, error)
	Decrypt(symmetricKey, ciphertext, aeadNonce, additionalData []byte) (plaintext []byte, err error)
}

// New creates a new Store with a random private key.  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string and updated later using SetExternalPublicKey().
func New(
	curve ecdh.Curve,
	hash func() hash.Hash,
	kdf KDF,
	aead AEAD,
	externalPublicKey string,
) (s *Store, err error) {
	return NewWithPrivateKey(
		curve,
		hash,
		kdf,
		aead,
		"", // random private key
		externalPublicKey,
	)
}

// New creates a new Store with the specified private key.  Only use a specified (i.e. non-random) private key for testing.  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string and updated later using SetExternalPublicKey().
func NewWithPrivateKey(
	curve ecdh.Curve,
	hash func() hash.Hash,
	kdf KDF,
	aead AEAD,
	privateKey string,
	externalPublicKey string,
) (s *Store, err error) {
	var ecdhPrivateKey *ecdh.PrivateKey
	if privateKey == "" {
		ecdhPrivateKey, err = curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	} else {
		dec, err := base64.StdEncoding.DecodeString(privateKey)
		if err != nil {
			return nil, err
		}
		ecdhPrivateKey, err = curve.NewPrivateKey(dec)
		if err != nil {
			return nil, err
		}
	}
	s = &Store{
		curve:             curve,
		hash:              hash,
		kdf:               kdf,
		aead:              aead,
		ecdhPrivateKey:    ecdhPrivateKey,
		externalPublicKey: "",
		sharedSecret:      "",
	}
	if externalPublicKey != "" {
		err = s.SetExternalPublicKey(externalPublicKey)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// New_Curve25519_SHA256_HKDF_AESGCM creates a new Store using the Curve25519 curve, SHA256 as the hash, HKDF as the key derivation function, and AESGCM as the authenticated encryption with associated data (AEAD) cipher.  This is a commonly used Store combination as at September 2023. If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string here and updated later using SetExternalPublicKey().
func New_Curve25519_SHA256_HKDF_AESGCM(externalPublicKey string) (s *Store, err error) {
	return NewWithPrivateKey(
		ecdh.X25519(),
		sha256.New,
		NewHKDF(),
		NewAESGCM(),
		"", // random private key
		externalPublicKey,
	)
}

// New_Curve25519_SHA256_HKDF_AESGCM_WithPrivateKey is New_Curve25519_SHA256_HKDF_AESGCM() using the specified private key.  Only use specified (i.e. non-random) nonces for testing.  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string here and updated later using SetExternalPublicKey().
func New_Curve25519_SHA256_HKDF_AESGCM_WithPrivateKey(
	privateKey string,
	externalPublicKey string,
) (s *Store, err error) {
	return NewWithPrivateKey(
		ecdh.X25519(),
		sha256.New,
		NewHKDF(),
		NewAESGCM(),
		privateKey,
		externalPublicKey,
	)
}

// PrivateKey prints the Elliptic-curve Diffie–Hellman (ECDH) private key for the Store.
func (s *Store) PrivateKey() string {
	return base64.StdEncoding.EncodeToString(s.ecdhPrivateKey.Bytes())
}

// PublicKey prints the Elliptic-curve Diffie–Hellman (ECDH) public key for the Store.
func (s *Store) PublicKey() string {
	return base64.StdEncoding.EncodeToString(s.ecdhPrivateKey.PublicKey().Bytes())
}

// ExternalPublicKey prints the external Elliptic-curve Diffie–Hellman (ECDH) public key for the Store.  We use the ECDH private key and this ECDH ExternalPublicKey to create the SharedSecret for the Store.
func (s *Store) ExternalPublicKey() string {
	return s.externalPublicKey
}

// SharedSecret is the Elliptic-curve Diffie–Hellman (ECDH) sharded secret for the Store.  We use the ECDH private key and the ECDH ExternalPublicKey to create this SharedSecret for the Store.
func (s *Store) SharedSecret() string {
	return s.sharedSecret
}

// X963RepresentationPublicKey prints the Store Elliptic-curve Diffie–Hellman (ECDH) public key as bytes.  This produces the same result as calling X963RepresentationPublicKey in the Apple CryptoKit library.
func (s *Store) X963RepresentationPublicKey() []byte {
	return s.ecdhPrivateKey.PublicKey().Bytes()
}

// X963RepresentationPrivateKey prints the Store Elliptic-curve Diffie–Hellman (ECDH) public key and private key as bytes.  This produces the same result as calling X963RepresentationPrivateKey in the Apple CryptoKit library.
func (s *Store) X963RepresentationPrivateKey() []byte {
	return append(s.ecdhPrivateKey.PublicKey().Bytes(), s.ecdhPrivateKey.Bytes()...)
}

// SetExternalPublicKey sets the externalPublicKey, and uses the ECDH private key and the ECDH ExternalPublicKey to create the SharedSecret for the Store. We only need to call this function if we set the externalPublicKey as an empty string when we created the Store.
func (s *Store) SetExternalPublicKey(externalPublicKey string) error {
	if externalPublicKey == "" {
		return fmt.Errorf("empty key")
	}

	// Create *ecdh.PublicKey
	dec, err := base64.StdEncoding.DecodeString(externalPublicKey)
	if err != nil {
		return err
	}
	ecdhPub, err := s.curve.NewPublicKey([]byte(dec))
	if err != nil {
		return err
	}

	// Create ECDH shared secret
	b, err := s.ecdhPrivateKey.ECDH(ecdhPub)
	if err != nil {
		return err
	}
	s.externalPublicKey = externalPublicKey
	s.sharedSecret = base64.StdEncoding.EncodeToString(b[:])
	return nil
}

// Encrypt creates a random nonce (the symmetricKeyNonce), uses the key derivation function with this symmetricKeyNonceto to create a derived key for our SharedSecret, creates a second random nonce (the aeadNonce), and then encrypts the plaintext with the aeadNonce.  The additionalData bytes (which do not need to be secret) are used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).  Encrypt() returns an AEADStore struct containing both nonces, the ciphertext, and the additionalData.
func (s *Store) Encrypt(
	plaintext []byte,
	additionalData []byte,
) (v *AEADStore, err error) {
	return s.EncryptWithNonces(
		nil, // random symmetricKeyNonce
		plaintext,
		nil, // random aeadNonce
		additionalData,
	)
}

// EncryptWithNonces is the same as Encrypt() but with user specified nonces (i.e. the symmetricKeyNonce and aeadNonce).  Set these nonces as nil to create random nonces.  Only use specified (i.e. non-random) nonces for testing.
func (s *Store) EncryptWithNonces(
	symmetricKeyNonce []byte, // nil for random
	plaintext []byte,
	aeadNonce []byte, // nil for random
	additionalData []byte,
) (v *AEADStore, err error) {
	if s.sharedSecret == "" {
		return nil, fmt.Errorf("external public key not set")
	}
	key, err := s.kdf.DeriveKey(
		s.SharedSecret(),
		s.hash,
		symmetricKeyNonce,
		additionalData,
	)
	if err != nil {
		return nil, ErrDeriveKey
	}
	v, err = s.aead.Encrypt(key, s.kdf.Nonce(), plaintext, aeadNonce, additionalData)
	if err != nil {
		return nil, ErrEncrypt
	}
	return v, nil
}

// EncodeJSONAndEncryptToJSON JSON is a convenience function that encodes the value to JSON (using the provided additionalData), performs Encrypt(), then encodes the AEADStore as JSON bytes.
func (s *Store) EncodeJSONAndEncryptToJSON(
	value interface{},
	additionalData []byte,
) (jsonData []byte, err error) {
	return s.EncodeJSONAndEncryptToJSONWithNonces(
		nil, // random symmetricKeyNonce
		value,
		nil, // random aeadNonce
		additionalData,
	)
}

// EncodeJSONAndEncryptToJSONWithNonce is the same as EncodeJSONAndEncryptToJSON but with user specified nonces (i.e. the symmetricKeyNonce and aeadNonce).  Set these nonces as nil to create random nonces.  Only use specified (i.e. non-random) nonces for testing.
func (s *Store) EncodeJSONAndEncryptToJSONWithNonces(
	symmetricKeyNonce []byte, // nil for random
	value interface{},
	aeadNonce []byte, // nil for random
	additionalData []byte,
) (jsonData []byte, err error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	v, err := s.EncryptWithNonces(
		symmetricKeyNonce,
		b,
		aeadNonce,
		additionalData,
	)
	if err != nil {
		return nil, err
	}
	jsonData, err = json.Marshal(v)
	if err != nil {
		return nil, ErrMarsal
	}
	return jsonData, nil
}

// Decrypt decrypts (i.e. performs the opposite of the Encrypt() function) the ciphertext using the provided symmetricKeyNonce, aeadNonce, and additionalData.  All of this information is included in AEADStore structs.
func (s *Store) Decrypt(
	symmetricKeyNonce []byte,
	ciphertext []byte,
	aeadNonce []byte,
	additionalData []byte,
) (plaintext []byte, err error) {
	if s.sharedSecret == "" {
		return nil, ErrPublicKeyNotSet
	}
	key, err := s.kdf.DeriveKey(
		s.SharedSecret(),
		s.hash,
		symmetricKeyNonce,
		additionalData,
	)
	if err != nil {
		return nil, ErrDeriveKey
	}
	plaintext, err = s.aead.Decrypt(key, ciphertext, aeadNonce, additionalData)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, err
}

// DecryptAEADStore performs Decrypt() using the provided AEADStore struct.
func (s *Store) DecryptAEADStore(v *AEADStore) (plaintext []byte, err error) {
	return s.Decrypt(
		v.KDFNonce,
		v.Ciphertext,
		v.AEADNonce,
		v.AdditionalData,
	)
}

// UnmarshalJSONAndDecryptFromJSON is a convenience function that performs the opposite of EncodeJSONAndEncryptToJSON().  This function unmarshals JSON AEADStore bytes, decrypts, and then unmarshals the resulting JSON plaintext.
func (s *Store) UnmarshalJSONAndDecryptFromJSON(jsonData []byte, v any) (err error) {
	return s.UnmarshalJSONAndDecryptFromJSONWithADCheck(jsonData, v, nil)
}

// UnmarshalJSONAndDecryptFromJSONWithAdditionalData is a convenience function that performs the opposite of EncodeJSONAndEncryptToJSON().  This function unmarshals JSON AEADStore bytes, decrypts, and then unmarshals the resulting JSON plaintext.  This function also checks whether the provided additionalData matches with the AEADStore additionalData.
func (s *Store) UnmarshalJSONAndDecryptFromJSONWithADCheck(
	jsonData []byte,
	v any,
	authFunc func(additionalData []byte) (bool, error),
) (err error) {
	var aeadStore AEADStore
	err = json.Unmarshal(jsonData, &aeadStore)
	if err != nil {
		return ErrUnmarsalAEADStore
	}
	plaintext, err := s.DecryptAEADStore(&aeadStore)
	if err != nil {
		return err
	}
	err = json.Unmarshal(plaintext, &v)
	if err != nil {
		return ErrUnmarsal
	}
	if authFunc != nil {
		ok, err := authFunc(aeadStore.AdditionalData)
		if err != nil {
			return err
		}
		if !ok {
			return ErrAdditionalData
		}
	}
	return nil
}
