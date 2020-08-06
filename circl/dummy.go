// +build !cfgo

package circl

import (
	"crypto"
	"crypto/x509"
	"encoding"
	"encoding/asn1"
	"errors"
)

// When we're not using http://github.com/cloudflare/go, we can't use any
// of the signature schemes from Circl, so we'll just put a dummy API here.

type SignatureOpts struct {
	Context string
}

type PublicKey interface {
	Scheme() Scheme
	encoding.BinaryMarshaler
	Equal(crypto.PublicKey) bool
}

type PrivateKey interface {
	Scheme() Scheme
	crypto.Signer
	encoding.BinaryMarshaler
	Equal(crypto.PrivateKey) bool
}

type Scheme interface {
	GenerateKey() (PublicKey, PrivateKey, error)
	Sign(sk PrivateKey, message []byte, opts *SignatureOpts) []byte
	Verify(pk PublicKey, message []byte, signature []byte, opts *SignatureOpts) bool
	DeriveKey(seed []byte) (PublicKey, PrivateKey)
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)
	PublicKeySize() uint
	PrivateKeySize() uint
	Name() string
	SignatureSize() uint
	SeedSize() uint
}

type CertificateScheme interface {
	Oid() asn1.ObjectIdentifier
}

type TLSScheme interface {
	TLSIdentifier() uint
}

func SchemeByName(name string) Scheme {
	return nil
}

func AllSchemes() []Scheme {
	return []Scheme{}
}

func SchemeByOid(oid asn1.ObjectIdentifier) Scheme {
	return nil
}

func SchemeByTLSIdentifier(id uint) Scheme {
	return nil
}

func UnmarshalPEMPublicKey(data []byte) (PublicKey, error) {
	return nil, errors.New("not supported")
}

func MarshalPEMPublicKey(pk PublicKey) ([]byte, error) {
	return nil, errors.New("not supported")
}

func UnmarshalPKIXPublicKey(data []byte) (PublicKey, error) {
	return nil, errors.New("not supported")
}

func MarshalPKIXPublicKey(pk PublicKey) ([]byte, error) {
	return nil, errors.New("not supported")
}

func UnmarshalPEMPrivateKey(data []byte) (PrivateKey, error) {
	return nil, errors.New("not supported")
}

func MarshalPEMPrivateKey(sk PrivateKey) ([]byte, error) {
	return nil, errors.New("not supported")
}

func UnmarshalPKIXPrivateKey(data []byte) (PrivateKey, error) {
	return nil, errors.New("not supported")
}

func SchemeByX509PublicKeyAlgorithm(id x509.PublicKeyAlgorithm) Scheme {
	return nil
}

func X509SignatureAlgorithmByScheme(scheme Scheme) x509.SignatureAlgorithm {
	return x509.UnknownSignatureAlgorithm
}
