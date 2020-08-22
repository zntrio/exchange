package exchange

import (
	"crypto/ecdsa"
)

// Exchange represents key exchange protocol contract.
type Exchange interface {
	SecretKey(ephemeralPrivateKey *ecdsa.PrivateKey, theirPublicKey *ecdsa.PublicKey, theirAgreementInfo []byte) ([]byte, error)
}
