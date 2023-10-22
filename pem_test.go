package keyexchange

import (
	"crypto/ecdh"
	"crypto/sha256"
	"strings"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestPEM(t *testing.T) {
	curve := ecdh.X25519()
	hash := sha256.New
	kdf := NewHKDF()
	aead := NewAESGCM()

	alicePrivateKey := "DDooYaf2wbGQ2V1MWj8jM+KxLxu6apnMYetwdHMY4vI="
	alicePublicKey := "xql2dqP8MqbQSHgwMdTQSaSqUUtaPewDKzT/FR9xpG8="
	bobPrivateKey := "gBeL2f79WIcTfW45zvMj7SZcJBOAE/sbUAb5ch7WA0Y="
	bobPublicKey := "dXuLU5sg+svTjqnk6UvWidfJS4DeDBbs037A4fPhAiU="

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

	k, err := aliceStore.PublicKeyPEM()
	assert.Equal(t, err, nil)
	assert.True(t, strings.Contains(k, alicePublicKey))
	k, err = aliceStore.PrivateKeyPEM()
	assert.Equal(t, err, nil)
	assert.True(t, strings.Contains(k, alicePrivateKey))
	k, err = bobStore.PublicKeyPEM()
	assert.Equal(t, err, nil)
	assert.True(t, strings.Contains(k, bobPublicKey))
	k, err = bobStore.PrivateKeyPEM()
	assert.Equal(t, err, nil)
	assert.True(t, strings.Contains(k, bobPrivateKey))
}
