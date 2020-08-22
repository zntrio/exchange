package exchange

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"hash"
	"reflect"
	"testing"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/square/go-jose.v2"
)

// Values from https://tools.ietf.org/id/draft-madden-jose-ecdh-1pu-03.html
var (
	// Static Alice Private/Public Key
	aliceStaticJWK = mustJWK([]byte(`{"kty":"EC", "crv":"P-256", "x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis", "y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE", "d":"Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"}`))
	// Ephemeral Alice Private/Public Key
	aliceEphemeralJWK = mustJWK([]byte(`{"kty":"EC", "crv":"P-256",	"x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0", "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps", "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}`))
	// Static Bob Public Key
	bobStaticJWK = mustJWK([]byte(`{"kty":"EC", "crv":"P-256", "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ", "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck", "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}`))
)

// mustJWK decodes JWK encoded keys and panic if decode fail.
func mustJWK(data []byte) *jose.JSONWebKey {
	var key jose.JSONWebKey
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&key); err != nil {
		panic(err)
	}

	return &key
}

func mustBase64UrlDecode(input string) []byte {
	out, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		panic(err)
	}

	return out
}

func Test_ecdh1PuExchange_SecretKey(t *testing.T) {
	type fields struct {
		ourPrivate  *ecdsa.PrivateKey
		algorithmID []byte
		dkLenBits   uint32
		partyInfo   []byte
		h           func() hash.Hash
	}
	type args struct {
		ephemeralPrivateKey *ecdsa.PrivateKey
		theirPublicKey      *ecdsa.PublicKey
		theirAgreementInfo  []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "fields: missing private key",
			fields: fields{
				ourPrivate:  nil,
				algorithmID: []byte("A256GCM"),
				dkLenBits:   256,
				partyInfo:   []byte("Alice"),
				h:           sha256.New,
			},
			args: args{
				ephemeralPrivateKey: aliceEphemeralJWK.Key.(*ecdsa.PrivateKey),
				theirAgreementInfo:  []byte("Bob"),
				theirPublicKey:      bobStaticJWK.Public().Key.(*ecdsa.PublicKey),
			},
			wantErr: true,
		},
		{
			name: "fields: missing hash function",
			fields: fields{
				ourPrivate:  aliceStaticJWK.Key.(*ecdsa.PrivateKey),
				algorithmID: []byte("A256GCM"),
				dkLenBits:   256,
				partyInfo:   []byte("Alice"),
				h:           nil,
			},
			args: args{
				ephemeralPrivateKey: aliceEphemeralJWK.Key.(*ecdsa.PrivateKey),
				theirAgreementInfo:  []byte("Bob"),
				theirPublicKey:      bobStaticJWK.Public().Key.(*ecdsa.PublicKey),
			},
			wantErr: true,
		},
		{
			name: "args: missing ephemeral key",
			fields: fields{
				ourPrivate:  aliceStaticJWK.Key.(*ecdsa.PrivateKey),
				algorithmID: []byte("A256GCM"),
				dkLenBits:   256,
				partyInfo:   []byte("Alice"),
				h:           sha256.New,
			},
			args: args{
				ephemeralPrivateKey: nil,
				theirAgreementInfo:  []byte("Bob"),
				theirPublicKey:      bobStaticJWK.Public().Key.(*ecdsa.PublicKey),
			},
			wantErr: true,
		},
		{
			name: "args: missing public key",
			fields: fields{
				ourPrivate:  aliceStaticJWK.Key.(*ecdsa.PrivateKey),
				algorithmID: []byte("A256GCM"),
				dkLenBits:   256,
				partyInfo:   []byte("Alice"),
				h:           sha256.New,
			},
			args: args{
				ephemeralPrivateKey: aliceEphemeralJWK.Key.(*ecdsa.PrivateKey),
				theirAgreementInfo:  []byte("Bob"),
				theirPublicKey:      nil,
			},
			wantErr: true,
		},
		{
			name: "valid: ECDH-1PU+SHA256+A128GCM",
			fields: fields{
				ourPrivate:  aliceStaticJWK.Key.(*ecdsa.PrivateKey),
				algorithmID: []byte("A128GCM"),
				dkLenBits:   128,
				partyInfo:   []byte("Alice"),
				h:           sha256.New,
			},
			args: args{
				ephemeralPrivateKey: aliceEphemeralJWK.Key.(*ecdsa.PrivateKey),
				theirAgreementInfo:  []byte("Bob"),
				theirPublicKey:      bobStaticJWK.Public().Key.(*ecdsa.PublicKey),
			},
			wantErr: false,
			want:    mustBase64UrlDecode("AiVWJdYQJPxPu-lJu_OkeA"),
		},
		{
			name: "valid: ECDH-1PU+SHA256+A192GCM",
			fields: fields{
				ourPrivate:  aliceStaticJWK.Key.(*ecdsa.PrivateKey),
				algorithmID: []byte("A192GCM"),
				dkLenBits:   192,
				partyInfo:   []byte("Alice"),
				h:           sha256.New,
			},
			args: args{
				ephemeralPrivateKey: aliceEphemeralJWK.Key.(*ecdsa.PrivateKey),
				theirAgreementInfo:  []byte("Bob"),
				theirPublicKey:      bobStaticJWK.Public().Key.(*ecdsa.PublicKey),
			},
			wantErr: false,
			want:    mustBase64UrlDecode("IXAgU5hhkaK5wGiPzFcP2ho3qPLjqSAZ"),
		},
		{
			name: "valid: ECDH-1PU+SHA256+A256GCM",
			fields: fields{
				ourPrivate:  aliceStaticJWK.Key.(*ecdsa.PrivateKey),
				algorithmID: []byte("A256GCM"),
				dkLenBits:   256,
				partyInfo:   []byte("Alice"),
				h:           sha256.New,
			},
			args: args{
				ephemeralPrivateKey: aliceEphemeralJWK.Key.(*ecdsa.PrivateKey),
				theirAgreementInfo:  []byte("Bob"),
				theirPublicKey:      bobStaticJWK.Public().Key.(*ecdsa.PublicKey),
			},
			wantErr: false,
			want:    mustBase64UrlDecode("bK8Tcj0UhQrUtCzW3ek1v_0v_wCpunDeBcIDpeFyLKc"),
		},
		{
			name: "valid: ECDH-1PU+B2B256+A256GCM",
			fields: fields{
				ourPrivate:  aliceStaticJWK.Key.(*ecdsa.PrivateKey),
				algorithmID: []byte("A256GCM"),
				dkLenBits:   256,
				partyInfo:   []byte("Alice"),
				h: func() hash.Hash {
					// Idea blake2b key could be used as a preshared key for encryption key derivation.
					hasher, err := blake2b.New256(nil)
					if err != nil {
						panic(err)
					}
					return hasher
				},
			},
			args: args{
				ephemeralPrivateKey: aliceEphemeralJWK.Key.(*ecdsa.PrivateKey),
				theirAgreementInfo:  []byte("Bob"),
				theirPublicKey:      bobStaticJWK.Public().Key.(*ecdsa.PublicKey),
			},
			wantErr: false,
			want:    mustBase64UrlDecode("wfW-ULXOp_4lSNyLAu2PHaQfnb-g6R6NRCiTqCh_EJ0"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exchange := ECDH1PU(tt.fields.ourPrivate, tt.fields.h, tt.fields.algorithmID, tt.fields.dkLenBits, tt.fields.partyInfo)
			got, err := exchange.SecretKey(tt.args.ephemeralPrivateKey, tt.args.theirPublicKey, tt.args.theirAgreementInfo)
			if (err != nil) != tt.wantErr {
				t.Errorf("ecdh1PuExchange.SecretKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ecdh1PuExchange.SecretKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
