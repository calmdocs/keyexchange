package keyexchange

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestKeyexchange(t *testing.T) {
	curve := ecdh.X25519()
	hash := sha256.New
	kdf := NewHKDF()
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

	aliceStore, err := NewWithPrivateKey(
		curve,
		hash,
		kdf,
		aead,
		alicePrivateKey,
		bobPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	bobStore, err := NewWithPrivateKey(
		curve,
		hash,
		kdf,
		aead,
		bobPrivateKey,
		alicePublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Alice encrypt
	v, err := aliceStore.EncryptWithNonces(
		kdfNonce, // []byte of size hash.Size() or nil for random
		plaintext,
		aeadNonce, // []byte of size 12 or nil for random
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, kdfNonce, v.KDFNonce)
	assert.Equal(t, ciphertext, v.Ciphertext)
	assert.Equal(t, aeadNonce, v.AEADNonce)
	assert.Equal(t, additionalData, v.AdditionalData)

	// Bob decrypt
	bobPlaintext, err := bobStore.Decrypt(
		kdfNonce,
		ciphertext,
		aeadNonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plaintext, bobPlaintext)

	// Bob encrypt
	v, err = bobStore.EncryptWithNonces(
		kdfNonce, // []byte of size hash.Size() or nil for random
		plaintext,
		aeadNonce, // []byte of size 12 or nil for random
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, kdfNonce, v.KDFNonce)
	assert.Equal(t, ciphertext, v.Ciphertext)
	assert.Equal(t, aeadNonce, v.AEADNonce)
	assert.Equal(t, additionalData, v.AdditionalData)

	// Alice decrypt
	alicePlaintext, err := aliceStore.Decrypt(
		kdfNonce,
		ciphertext,
		aeadNonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plaintext, alicePlaintext)
}

func TestEDCH(t *testing.T) {
	curve := ecdh.X25519()
	hash := sha256.New
	kdf := NewHKDF()
	aead := NewAESGCM()

	alicePrivateKey := "DDooYaf2wbGQ2V1MWj8jM+KxLxu6apnMYetwdHMY4vI="
	alicePublicKey := "xql2dqP8MqbQSHgwMdTQSaSqUUtaPewDKzT/FR9xpG8="
	bobPrivateKey := "gBeL2f79WIcTfW45zvMj7SZcJBOAE/sbUAb5ch7WA0Y="
	bobPublicKey := "dXuLU5sg+svTjqnk6UvWidfJS4DeDBbs037A4fPhAiU="

	expectedSecretString := "3Nji+LTOtQpaVBuzPN2XgBPUlAn961hGYlSMweTjERI="

	// Alice

	aliceStore, err := NewWithPrivateKey(
		curve,
		hash,
		kdf,
		aead,
		alicePrivateKey,
		bobPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, aliceStore.PrivateKey(), alicePrivateKey)
	assert.Equal(t, aliceStore.PublicKey(), alicePublicKey)
	aliceSecretString := aliceStore.SharedSecret()
	assert.Equal(t, aliceSecretString, expectedSecretString)

	// Bob

	bobStore, err := NewWithPrivateKey(
		curve,
		hash,
		kdf,
		aead,
		bobPrivateKey,
		alicePublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bobStore.PrivateKey(), bobPrivateKey)
	assert.Equal(t, bobStore.PublicKey(), bobPublicKey)
	bobSecretString := bobStore.SharedSecret()
	assert.Equal(t, bobSecretString, expectedSecretString)

	// Check that the secrets match

	assert.Equal(t, aliceSecretString, bobSecretString)
}
