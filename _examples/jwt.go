package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"zntr.io/exchange"
)

var (
	alice = []byte("Alice")
	// Static Alice Private/Public Key
	aliceStaticJWK = mustJWK([]byte(`{"kty":"EC", "crv":"P-256", "x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis", "y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE", "d":"Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"}`))
	bob            = []byte("Bob")
	// Static Bob Public Key
	bobStaticJWK = mustJWK([]byte(`{"kty":"EC", "crv":"P-256", "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ", "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck", "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}`))
)

func main() {
	// Create an ephemeral key
	ephemeralPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Wrap it as JWK encoded key
	ephemeralJWK := jose.JSONWebKey{
		Algorithm: jose.ES256,
		Key:       ephemeralPrivateKey,
	}

	// Generate shared encryption key
	x := exchange.ECDH1PU(aliceStaticJWK, sha256.New, []byte{"A256GCM"}, 256, alice)

	// Proceed to ECDH-1PU exchange
	encryptionKey, err := x.SecretKey(ephemeralPrivateKey, bobStaticJWK.Public().Key.(*ecdsa.PublicKey), bob)
	if err != nil {
		panic(err)
	}

	// Create a signer
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       aliceStaticJWK, // Use Alice static private to sign token
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderContentType: "JWT",
		},
	})
	if err != nil {
		panic(err)
	}

	// Create an encrypter
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.DIRECT,
		Key:       encryptionKey,
	}, &jose.EncrypterOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderContentType: jose.ContentType("JWT"),
			"alg":                  "ECDH-1PU",
			"apu":                  base64.RawURLEncoding.EncodeToString(alice),
			"apv":                  base64.RawURLEncoding.EncodeToString(bob),
			"epk":                  ephemeralJWK.Public(), // Embed ephemeral public key
		},
	})
	if err != nil {
		panic(err)
	}

	// Create a encrypted and signed token
	token, err := jwt.SignedAndEncrypted(signer, encrypter).Claims(&jwt.Claims{
		ID:      "12345",
		Subject: fmt.Sprintf("%s", alice),
	}).CompactSerialize()
	if err != nil {
		panic(err)
	}

	fmt.Printf("SignedEncrypted Token: %s\n", token)
}
