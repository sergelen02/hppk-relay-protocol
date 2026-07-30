package hppk

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/sergelen02/HPPK_2/pkg/hppkapi"
)

type Config struct {
	PublicKeyPath string
	SecretKeyPath string
}

type Signer struct {
	mu sync.RWMutex

	publicKey *hppkapi.Public
	secretKey *hppkapi.Secret

	publicKeyJSON []byte
}

func NewSigner(cfg Config) (*Signer, error) {
	if cfg.PublicKeyPath == "" {
		return nil, errors.New("HPPK public key path is required")
	}
	if cfg.SecretKeyPath == "" {
		return nil, errors.New("HPPK secret key path is required")
	}

	publicKeyJSON, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read HPPK public key %q: %w",
			cfg.PublicKeyPath,
			err,
		)
	}

	secretKeyJSON, err := os.ReadFile(cfg.SecretKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read HPPK secret key %q: %w",
			cfg.SecretKeyPath,
			err,
		)
	}

	publicKey, err := hppkapi.DecodePublicJSON(publicKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("decode HPPK public key: %w", err)
	}

	secretKey, err := hppkapi.DecodeSecretJSON(secretKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("decode HPPK secret key: %w", err)
	}

	// Decode 후 다시 canonical JSON으로 직렬화합니다.
	canonicalPublicKeyJSON, err :=
		hppkapi.EncodePublicJSON(publicKey)
	if err != nil {
		return nil, fmt.Errorf(
			"encode canonical HPPK public key: %w",
			err,
		)
	}

	return &Signer{
		publicKey:     publicKey,
		secretKey:     secretKey,
		publicKeyJSON: canonicalPublicKeyJSON,
	}, nil
}

func (s *Signer) Sign(msg []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("HPPK signer is nil")
	}
	if len(msg) == 0 {
		return nil, errors.New("message is empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.secretKey == nil {
		return nil, errors.New("HPPK secret key is nil")
	}
	if s.publicKey == nil {
		return nil, errors.New("HPPK public key is nil")
	}

	signature, err := hppkapi.SignWithPK(
		s.secretKey,
		s.publicKey,
		msg,
	)
	if err != nil {
		return nil, fmt.Errorf("HPPK SignWithPK: %w", err)
	}

	signatureJSON, err :=
		hppkapi.EncodeSignatureJSON(signature)
	if err != nil {
		return nil, fmt.Errorf(
			"encode HPPK signature JSON: %w",
			err,
		)
	}

	return signatureJSON, nil
}

func (s *Signer) Verify(
	publicKeyJSON []byte,
	msg []byte,
	signatureJSON []byte,
) (bool, error) {
	if s == nil {
		return false, errors.New("HPPK signer is nil")
	}
	if len(publicKeyJSON) == 0 {
		return false, errors.New("public key is empty")
	}
	if len(msg) == 0 {
		return false, errors.New("message is empty")
	}
	if len(signatureJSON) == 0 {
		return false, errors.New("signature is empty")
	}

	publicKey, err :=
		hppkapi.DecodePublicJSON(publicKeyJSON)
	if err != nil {
		return false, fmt.Errorf(
			"decode received HPPK public key: %w",
			err,
		)
	}

	signature, err :=
		hppkapi.DecodeSignatureJSON(signatureJSON)
	if err != nil {
		return false, fmt.Errorf(
			"decode received HPPK signature: %w",
			err,
		)
	}

	return hppkapi.Verify(
		publicKey,
		msg,
		signature,
	), nil
}

func (s *Signer) PublicKeyBytes() ([]byte, error) {
	if s == nil {
		return nil, errors.New("HPPK signer is nil")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.publicKeyJSON) == 0 {
		return nil, errors.New("HPPK public key JSON is empty")
	}

	out := make([]byte, len(s.publicKeyJSON))
	copy(out, s.publicKeyJSON)

	return out, nil
}
