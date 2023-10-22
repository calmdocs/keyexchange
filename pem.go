package keyexchange

import (
	"bytes"
	"encoding/pem"
)

// PrivateKeyPEM returns the private key in the Privacy-Enhanced Mail (PEM) format.
func (s *Store) PrivateKeyPEM() (string, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: s.ecdhPrivateKey.Bytes(),
	})
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

// PrivateKeyPEM returns the public key in the Privacy-Enhanced Mail (PEM) format.
func (s *Store) PublicKeyPEM() (string, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: s.ecdhPrivateKey.PublicKey().Bytes(),
	})
	if err != nil {
		return "", err
	}
	return b.String(), nil
}
