package keyexchange

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
)

// HPKEStore stores key exchange variables.
type HPKEStore struct {
	curve              ecdh.Curve
	hash               func() hash.Hash
	kdfSender          KDF
	kdfSenderReader    io.Reader
	kdfRecipient       KDF
	kdfRecipientReader io.Reader
	aead               AEAD
	ecdhPrivateKey     *ecdh.PrivateKey
	externalPublicKey  string
	sharedSecret       string
}

// HPKEAEADStore stores authenticated encryption with associated data (AEAD) variables.
type HPKEAEADStore struct {
	Ciphertext     []byte
	AEADNonce      []byte
	AdditionalData []byte
}

// NewHPKE creates a new Store with a random private key.  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string and updated later using SetExternalPublicKey().
func NewHPKE(
	curve ecdh.Curve,
	hash func() hash.Hash,
	kdfSender KDF,
	kdfRecipient KDF,
	aead AEAD,
) (s *HPKEStore, err error) {
	return NewHPKEWithPrivateKey(
		curve,
		hash,
		kdfSender,
		kdfRecipient,
		aead,
		"", // random private key
	)
}

// NewHPKEWithPrivateKey creates a new Store with the specified private key.  Only use a specified (i.e. non-random) private key for testing.  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string and updated later using SetExternalPublicKey().
func NewHPKEWithPrivateKey(
	curve ecdh.Curve,
	hash func() hash.Hash,
	kdfSender KDF,
	kdfRecipient KDF,
	aead AEAD,
	privateKey string, // "" for random
) (s *HPKEStore, err error) {
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
	s = &HPKEStore{
		curve:     curve,
		hash:      hash,
		kdfSender: kdfSender,
		//kdfSenderReader: nil,
		kdfRecipient: kdfRecipient,
		//kdfRecipientReader: nil,
		aead:              aead,
		ecdhPrivateKey:    ecdhPrivateKey,
		externalPublicKey: "",
		sharedSecret:      "",
	}
	return s, nil
}

// NewHPKE_Curve25519_SHA256_HKDF_AESGCM creates a new Store using the Curve25519 curve, SHA256 as the hash, HKDF as the key derivation function, and AESGCM as the authenticated encryption with associated data (AEAD) cipher.  This is a commonly used Store combination as at September 2023. If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string here and updated later using SetExternalPublicKey().
func NewHPKE_Curve25519_SHA256_HKDF_AESGCM() (s *HPKEStore, err error) {
	return NewHPKEWithPrivateKey(
		ecdh.X25519(),
		sha256.New,
		NewHKDF(),
		NewHKDF(),
		NewAESGCM(),
		"", // random privateKey
	)
}

// NewHPKE_Curve25519_SHA256_HKDF_AESGCM_WithPrivateKey is New_Curve25519_SHA256_HKDF_AESGCM() using the specified private key.  Only use specified (i.e. non-random) nonces for testing.  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string here and updated later using SetExternalPublicKey().
func NewHPKE_Curve25519_SHA256_HKDF_AESGCM_WithPrivateKey(
	privateKey string,
) (s *HPKEStore, err error) {
	return NewHPKEWithPrivateKey(
		ecdh.X25519(),
		sha256.New,
		NewHKDF(),
		NewHKDF(),
		NewAESGCM(),
		privateKey,
	)
}

// PrivateKey prints the Elliptic-curve Diffie–Hellman (ECDH) private key for the Store.
func (s *HPKEStore) PrivateKey() string {
	return base64.StdEncoding.EncodeToString(s.ecdhPrivateKey.Bytes())
}

// PublicKey prints the Elliptic-curve Diffie–Hellman (ECDH) public key for the Store.
func (s *HPKEStore) PublicKey() string {
	return base64.StdEncoding.EncodeToString(s.ecdhPrivateKey.PublicKey().Bytes())
}

// ExternalPublicKey prints the external Elliptic-curve Diffie–Hellman (ECDH) public key for the Store.  We use the ECDH private key and this ECDH ExternalPublicKey to create the SharedSecret for the Store.
func (s *HPKEStore) ExternalPublicKey() string {
	return s.externalPublicKey
}

// SharedSecret is the Elliptic-curve Diffie–Hellman (ECDH) sharded secret for the Store.  We use the ECDH private key and the ECDH ExternalPublicKey to create this SharedSecret for the Store.
func (s *HPKEStore) SharedSecret() string {
	return s.sharedSecret
}

// X963RepresentationPublicKey prints the Store Elliptic-curve Diffie–Hellman (ECDH) public key as bytes.  This produces the same result as calling X963RepresentationPublicKey in the Apple CryptoKit library.
func (s *HPKEStore) X963RepresentationPublicKey() []byte {
	return s.ecdhPrivateKey.PublicKey().Bytes()
}

// X963RepresentationPrivateKey prints the Store Elliptic-curve Diffie–Hellman (ECDH) public key and private key as bytes.  This produces the same result as calling X963RepresentationPrivateKey in the Apple CryptoKit library.
func (s *HPKEStore) X963RepresentationPrivateKey() []byte {
	return append(s.ecdhPrivateKey.PublicKey().Bytes(), s.ecdhPrivateKey.Bytes()...)
}

// SetExternalPublicKeyAndKDF sets the externalPublicKey, uses the ECDH private key and the ECDH ExternalPublicKey to create the SharedSecret for the Store, and starts the key derivation functions. We only need to call this function if we set the externalPublicKey as an empty string when we created the Store.
func (s *HPKEStore) SetExternalPublicKeyAndStartKDFs(
	externalPublicKey string,
	senderKDFNonce []byte,
	recipientKDFNonce []byte,
	additionalData []byte,
) (err error) {
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

	// Start the kdfs
	s.kdfSenderReader, err = s.kdfSender.Reader(
		s.SharedSecret(),
		s.hash,
		senderKDFNonce,
		additionalData,
	)
	if err != nil {
		return err
	}
	s.kdfRecipientReader, err = s.kdfRecipient.Reader(
		s.SharedSecret(),
		s.hash,
		recipientKDFNonce,
		additionalData,
	)
	if err != nil {
		return err
	}
	return nil
}

// Encrypt creates a random nonce (the symmetricKeyNonce), uses the key derivation function with this symmetricKeyNonceto to create a derived key for our SharedSecret, creates a second random nonce (the aeadNonce), and then encrypts the plaintext with the aeadNonce.  The additionalData bytes (which do not need to be secret) are used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).  Encrypt() returns an AEADStore struct containing both nonces, the ciphertext, and the additionalData.
func (s *HPKEStore) Encrypt(
	plaintext []byte,
	additionalData []byte,
) (v *AEADStore, err error) {
	return s.EncryptWithNonce(
		plaintext,
		nil, // random aeadNonce
		additionalData,
	)
}

// EncryptWithNonce is the same as Encrypt() but with a user specified aeadNonce.  Set this nonce as nil to create a random nonce.  Only use specified (i.e. non-random) nonces for testing.
func (s *HPKEStore) EncryptWithNonce(
	plaintext []byte,
	aeadNonce []byte, // nil for random
	additionalData []byte,
) (v *AEADStore, err error) {
	if s.sharedSecret == "" {
		return nil, fmt.Errorf("external public key not set")
	}
	key, err := s.kdfSender.Next(s.kdfSenderReader)
	if err != nil {
		return nil, ErrDeriveKey
	}
	// Send an empty kdf nonce which will be ignored
	v, err = s.aead.Encrypt(key, []byte(""), plaintext, aeadNonce, additionalData)
	if err != nil {
		return nil, ErrEncrypt
	}
	return v, nil
}

// EncodeJSONAndEncryptToJSON JSON is a convenience function that encodes the value to JSON (using the provided additionalData), performs Encrypt(), then encodes the AEADStore as JSON bytes.
func (s *HPKEStore) EncodeJSONAndEncryptToJSON(
	value interface{},
	additionalData []byte,
) (jsonData []byte, err error) {
	return s.EncodeJSONAndEncryptToJSONWithNonce(
		value,
		nil, // random aeadNonce
		additionalData,
	)
}

// EncodeJSONAndEncryptToJSONWithNonce is the same as EncodeJSONAndEncryptToJSON but with user specified aeadNonce.  Set these nonce as nil to create a random nonce.  Only use specified (i.e. non-random) nonces for testing.
func (s *HPKEStore) EncodeJSONAndEncryptToJSONWithNonce(
	value interface{},
	aeadNonce []byte, // nil for random
	additionalData []byte,
) (jsonData []byte, err error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	v, err := s.EncryptWithNonce(
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

// Decrypt decrypts (i.e. performs the opposite of the Encrypt() function) the ciphertext using the provided aeadNonce and additionalData.  All of this information is included in AEADStore structs.
func (s *HPKEStore) Decrypt(
	ciphertext []byte,
	aeadNonce []byte,
	additionalData []byte,
) (plaintext []byte, err error) {
	if s.sharedSecret == "" {
		return nil, ErrPublicKeyNotSet
	}
	key, err := s.kdfRecipient.Next(s.kdfRecipientReader)
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
func (s *HPKEStore) DecryptAEADStore(v *AEADStore) (plaintext []byte, err error) {
	return s.Decrypt(
		v.Ciphertext,
		v.AEADNonce,
		v.AdditionalData,
	)
}

// UnmarshalJSONAndDecryptFromJSON is a convenience function that performs the opposite of EncodeJSONAndEncryptToJSON().  This function unmarshals JSON AEADStore bytes, decrypts, and then unmarshals the resulting JSON plaintext.
func (s *HPKEStore) UnmarshalJSONAndDecryptFromJSON(jsonData []byte, v any) (err error) {
	return s.UnmarshalJSONAndDecryptFromJSONWithADCheck(jsonData, v, nil)
}

// UnmarshalJSONAndDecryptFromJSONWithAdditionalData is a convenience function that performs the opposite of EncodeJSONAndEncryptToJSON().  This function unmarshals JSON AEADStore bytes, decrypts, and then unmarshals the resulting JSON plaintext.  This function also checks whether the provided additionalData matches with the AEADStore additionalData.
func (s *HPKEStore) UnmarshalJSONAndDecryptFromJSONWithADCheck(
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
