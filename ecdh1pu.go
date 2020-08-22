package exchange

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

type ecdh1PuExchange struct {
	ourPrivate  *ecdsa.PrivateKey
	algorithmID []byte
	dkLenBits   uint32
	partyInfo   []byte
	h           func() hash.Hash
}

func ECDH1PU(staticPrivateKey *ecdsa.PrivateKey, h func() hash.Hash, algorithmID []byte, dkLenBits uint32, agreementPartyInfo []byte) Exchange {
	return &ecdh1PuExchange{
		ourPrivate:  staticPrivateKey,
		h:           h,
		algorithmID: algorithmID,
		dkLenBits:   dkLenBits,
		partyInfo:   agreementPartyInfo,
	}
}

// -----------------------------------------------------------------

func (exchange *ecdh1PuExchange) SecretKey(ephemeralPrivateKey *ecdsa.PrivateKey, theirPublicKey *ecdsa.PublicKey, theirAgreementInfo []byte) ([]byte, error) {
	// Check arguments
	if ephemeralPrivateKey == nil {
		return nil, fmt.Errorf("ephemeral private key is mandatory")
	}
	if theirPublicKey == nil {
		return nil, fmt.Errorf("their public key is mandatory")
	}
	if exchange.h == nil {
		return nil, fmt.Errorf("hash function is mandatory")
	}

	// Compute sharedSecret
	sharedSecret, err := exchange.computeSharedSecret(ephemeralPrivateKey, theirPublicKey)
	if err != nil {
		return nil, err
	}

	// Prepare info: ( AlgorithmID || PartyUInfo || PartyVInfo || KeyLength )
	fixedInfo := []byte{}
	fixedInfo = append(fixedInfo, lengthPrefixedArray(exchange.algorithmID)...)
	fixedInfo = append(fixedInfo, lengthPrefixedArray(exchange.partyInfo)...)
	fixedInfo = append(fixedInfo, lengthPrefixedArray(theirAgreementInfo)...)
	fixedInfo = append(fixedInfo, uint32ToBytes(exchange.dkLenBits)...)

	// Compute KDF
	dk, err := nistKdf(exchange.h(), sharedSecret, fixedInfo, exchange.dkLenBits>>3)
	if err != nil {
		return nil, fmt.Errorf("unable to apply kdf: %v", err)
	}

	// No error
	return dk, nil
}

// -----------------------------------------------------------------

func (exchange *ecdh1PuExchange) computeSharedSecret(ourEphemeralPrivateKey *ecdsa.PrivateKey, theirPublicKey *ecdsa.PublicKey) ([]byte, error) {
	// Check arguments
	if exchange.ourPrivate == nil {
		return nil, fmt.Errorf("unable to process with nil private key")
	}
	if ourEphemeralPrivateKey == nil {
		return nil, fmt.Errorf("unable to process with nil ephemeral private key")
	}
	if theirPublicKey == nil {
		return nil, fmt.Errorf("unable to process with remote public key")
	}

	// Compute Ze - ECDH(localPrivateEphemeral, remotePublic)
	Ze, _ := ourEphemeralPrivateKey.Curve.ScalarMult(theirPublicKey.X, theirPublicKey.Y, ourEphemeralPrivateKey.D.Bytes())

	// Compute Zs - ECDH(localPrivate, remotePublic)
	Zs, _ := exchange.ourPrivate.Curve.ScalarMult(theirPublicKey.X, theirPublicKey.Y, exchange.ourPrivate.D.Bytes())

	// Z = (Ze || Zs)
	Z := append(Ze.Bytes(), Zs.Bytes()...)

	// No error
	return Z, nil
}

// ----------------------------------------------------------------

func lengthPrefixedArray(value []byte) []byte {
	if len(value) == 0 {
		return []byte{}
	}
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(len(value)))

	return append(result, value...)
}

func uint32ToBytes(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(value))

	return result
}

func nistKdf(h hash.Hash, sharedSecret, info []byte, dkLen uint32) ([]byte, error) {
	// Compute necessary round count
	reps := int(math.Ceil(float64(dkLen) / float64(h.Size())))

	// Check max round count
	if reps >= 1<<32 {
		return nil, fmt.Errorf("too many round count for KDF")
	}

	dk := make([]byte, 0, dkLen)
	for counter := 1; counter <= reps; counter++ {
		h.Reset()
		// nolint // Never return error according to documentation
		h.Write(uint32ToBytes(uint32(counter)))
		// nolint // Never return error according to documentation
		h.Write(sharedSecret)
		// nolint // Never return error according to documentation
		h.Write(info)
		dk = h.Sum(dk)
	}

	// No error
	return dk[:dkLen], nil
}
