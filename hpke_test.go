package keyexchange

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestHPKE(t *testing.T) {

	curve := ecdh.X25519()
	hash := sha256.New
	kdf := func() KDF { return NewHKDF() }
	aead := NewAESGCM()

	alicePrivateKey := "DDooYaf2wbGQ2V1MWj8jM+KxLxu6apnMYetwdHMY4vI="
	alicePublicKey := "xql2dqP8MqbQSHgwMdTQSaSqUUtaPewDKzT/FR9xpG8="
	bobPrivateKey := "gBeL2f79WIcTfW45zvMj7SZcJBOAE/sbUAb5ch7WA0Y="
	bobPublicKey := "dXuLU5sg+svTjqnk6UvWidfJS4DeDBbs037A4fPhAiU="

	kdfNonce := []byte("4780bf3061ebbaab7562d3ef")
	plaintext := []byte("exampleplaintext")
	aeadNonce, _ := base64.StdEncoding.DecodeString("hAqd8PI6RlEhVikF")
	additionalData := []byte("abc")

	ciphertext, _ := base64.StdEncoding.DecodeString("hAqd8PI6RlEhVikFlLWMvnibSUxvhIKue/0opwrnrJduO/8Lt/xF52C+wIk=")
	ciphertext2, _ := base64.StdEncoding.DecodeString("hAqd8PI6RlEhVikFww1Ni6OwtehPneafdlLz+9MzootXrwPwjXwFPEwO/2g=")

	aliceStore, err := NewHPKEWithPrivateKey(
		curve,
		hash,
		kdf(),
		kdf(),
		aead,
		alicePrivateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = aliceStore.SetExternalPublicKeyAndStartKDFs(
		bobPublicKey,
		kdfNonce,
		kdfNonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}

	bobStore, err := NewHPKEWithPrivateKey(
		curve,
		hash,
		kdf(),
		kdf(),
		aead,
		bobPrivateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = bobStore.SetExternalPublicKeyAndStartKDFs(
		alicePublicKey,
		kdfNonce,
		kdfNonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Alice encrypt
	v, err := aliceStore.EncryptWithNonce(
		plaintext,
		aeadNonce, // []byte of size 12 or nil for random
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ciphertext, v.Ciphertext)
	assert.Equal(t, aeadNonce, v.AEADNonce)
	assert.Equal(t, additionalData, v.AdditionalData)

	// Bob decrypt
	bobPlaintext, err := bobStore.Decrypt(
		ciphertext,
		aeadNonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plaintext, bobPlaintext)

	// Bob encrypt
	v, err = bobStore.EncryptWithNonce(
		plaintext,
		aeadNonce, // []byte of size 12 or nil for random
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ciphertext, v.Ciphertext)
	assert.Equal(t, aeadNonce, v.AEADNonce)
	assert.Equal(t, additionalData, v.AdditionalData)

	// Alice decrypt
	alicePlaintext, err := aliceStore.Decrypt(
		ciphertext,
		aeadNonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plaintext, alicePlaintext)

	// Round 2 (different kdf keys)

	// Alice encrypt
	v, err = aliceStore.EncryptWithNonce(
		plaintext,
		aeadNonce, // []byte of size 12 or nil for random
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, ciphertext2, v.Ciphertext)
	assert.Equal(t, aeadNonce, v.AEADNonce)
	assert.Equal(t, additionalData, v.AdditionalData)

	// Bob decrypt
	bobPlaintext, err = bobStore.Decrypt(
		ciphertext2,
		aeadNonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plaintext, bobPlaintext)
}
