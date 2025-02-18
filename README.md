# keyexchange

[![godoc](https://godoc.org/github.com/calmdocs/keyexchange?status.svg)](https://godoc.org/github.com/calmdocs/keyexchange)

Golang Diffie–Hellman key exchange ([DHKE](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)) library built using the go standard library and golang.org/x/crypto.

Designed to mirror the Swift [calmdocs/SwiftKeyExchange](https://github.com/calmdocs/SwiftKeyExchange) library.  For example we use the same test keys, nonces, and results in this library as we use in the Swift [calmdocs/SwiftKeyExchange](https://github.com/calmdocs/SwiftKeyExchange) library.

## A note on security

We have been as conservative as possible when creating this library.  See the security discussion below.  However, please note that you use this library, and the code in this repo, at your own risk, and we accept no liability in relation to its use.

## Example
```
curve := ecdh.X25519()
hash := sha256.New
kdf := NewHKDF()
aead := NewAESGCM()

plaintext := []byte("exampleplaintext")
additionalData := []byte("abc")

// Create Alice's store
aliceStore, err := New(
    curve,
    hash,
    kdf,
    aead,
    "", // a new public key is created if this string is left empty
)
if err != nil {
    panic(err)
}

// Create Bob's store
bobStore, err := New(
    curve,
    hash,
    kdf,
    aead,
    "", // a new public key is created if this string is left empty
)
if err != nil {
    panic(err)
}

// Set public keys
err = aliceStore.SetExternalPublicKey(bobStore.PublicKey())
if err != nil {
    panic(err)
}
err = bobStore.SetExternalPublicKey(aliceStore.PublicKey())
if err != nil {
    panic(err)
}

// Alice encrypt
v, err := aliceStore.Encrypt(
    plaintext,
    additionalData,
)
if err != nil {
    panic(err)
}

// Bob decrypt
bobPlaintext, err := bobStore.Decrypt(
    v.KDFNonce,
    v.Ciphertext,
    v.AEADNonce,
    v.AdditionalData,
)
if err != nil {
    panic(err)
}

// Bob encrypt
v, err = bobStore.Encrypt(
    plaintext,
    additionalData,
)
if err != nil {
    panic(err)
}

// Alice decrypt
alicePlaintext, err := aliceStore.Decrypt(
    v.KDFNonce,
    v.Ciphertext,
    v.AEADNonce,
    v.AdditionalData,
)
if err != nil {
    panic(err)
}

fmt.Println(plaintext == alicePlaintext)
fmt.Println(plaintext == bobPlaintext)
```

## Security approach

As mentioned above, we have been as conservative as possible when creating this library.  For example, we have only used the go standard library and golang.org/x/crypto, and have not used any third party cryptography libraries to create this package.

Please notify us of any security issues by creating a github issue. Please propose how you would like to securely communicate with us (via email or other communication method). Please do not post the security issue on github.  

## Why not just use HPKE?

Because:
- when this library was written, [HPKE](https://developer.apple.com/documentation/cryptokit/hpke) was in beta in Apple's Cryptokit library; and
- when this library was written, there was no HPKE implementation in golang's standard library, or even in golang.org/x/crypto; and
- using [HPKE](https://developer.apple.com/documentation/cryptokit/hpke) does not allow any messages to be missed or dropped, and one of the author's use-case for this library *requires* some messages to be able to be missed or dropped (for example, this is useful for [calmdocs/SwiftPollManager](https://github.com/calmdocs/SwiftPollManager) and [calmdocs/SwiftStreamManager](https://github.com/calmdocs/SwiftStreamManager)).

If the above changes, we will probably add [HPKE](https://developer.apple.com/documentation/cryptokit/hpke) to this library as well as to [calmdocs/SwiftKeyExchange](https://github.com/calmdocs/SwiftKeyExchange).  We will also try to follow SemVer, but may not if there are security issues and/or as the underlying encryption used by this library becomes insecure over time. 





