package keyexchange

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestHKDF(t *testing.T) {
	curve := ecdh.X25519()
	hash := sha256.New
	kdf := NewHKDF()
	aead := NewAESGCM()

	alicePrivateKey := "DDooYaf2wbGQ2V1MWj8jM+KxLxu6apnMYetwdHMY4vI="
	alicePublicKey := "xql2dqP8MqbQSHgwMdTQSaSqUUtaPewDKzT/FR9xpG8="
	bobPrivateKey := "gBeL2f79WIcTfW45zvMj7SZcJBOAE/sbUAb5ch7WA0Y="
	bobPublicKey := "dXuLU5sg+svTjqnk6UvWidfJS4DeDBbs037A4fPhAiU="

	nonce := []byte("4780bf3061ebbaab7562d3ef")
	additionalData := []byte("abc")

	expectedHKDF1 := "LhxSAkC2BKy6FsGy+hJ/U+mJwzxXl5tvCYzEo0Q1bkE="
	expectedHKDF2 := "rXQI9J7kKRhrNrYc1CgaVhfjf8aoi7mm9MNZJmIUIyo="
	expectedHKDF3 := "oQ6IVr2NbZ4I250ULuGkIX1RvaNeTWWjHTcWNNuW2W0="

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

	r, err := kdf.Reader(
		aliceStore.SharedSecret(),
		hash,
		nonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	key1, err := kdf.Next(r)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t,
		expectedHKDF1,
		base64.StdEncoding.EncodeToString(key1),
	)
	key2, err := kdf.Next(r)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t,
		expectedHKDF2,
		base64.StdEncoding.EncodeToString(key2),
	)
	key3, err := kdf.Next(r)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t,
		expectedHKDF3,
		base64.StdEncoding.EncodeToString(key3),
	)

	r, err = kdf.Reader(
		bobStore.SharedSecret(),
		hash,
		nonce,
		additionalData,
	)
	if err != nil {
		t.Fatal(err)
	}
	key1, err = kdf.Next(r)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t,
		expectedHKDF1,
		base64.StdEncoding.EncodeToString(key1),
	)
	key2, err = kdf.Next(r)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t,
		expectedHKDF2,
		base64.StdEncoding.EncodeToString(key2),
	)
	key3, err = kdf.Next(r)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t,
		expectedHKDF3,
		base64.StdEncoding.EncodeToString(key3),
	)
}
