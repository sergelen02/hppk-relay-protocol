package hppk

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	hapi "github.com/sergelen02/HPPK_2/pkg/hppkapi"
)

type SignerConfig struct {
	PublicKeyPath  string
	SecretKeyPath  string
	AlgorithmName  string
	EnableVerify   bool
	StrictKeyCheck bool
}

type Signer struct {
	algorithmName  string
	enableVerify   bool
	strictKeyCheck bool

	publicKeyRaw []byte
	secretKeyRaw []byte

	publicKey *hapi.Public
	secretKey *hapi.Secret
}

func NewSigner(cfg SignerConfig) (*Signer, error) {
	if strings.TrimSpace(cfg.PublicKeyPath) == "" {
		return nil, errors.New("public key path is required")
	}
	if strings.TrimSpace(cfg.SecretKeyPath) == "" {
		return nil, errors.New("secret key path is required")
	}

	pubRaw, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	secRaw, err := os.ReadFile(cfg.SecretKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read secret key file: %w", err)
	}

	pubRaw = bytes.TrimSpace(pubRaw)
	secRaw = bytes.TrimSpace(secRaw)

	if len(pubRaw) == 0 {
		return nil, errors.New("public key file is empty")
	}
	if len(secRaw) == 0 {
		return nil, errors.New("secret key file is empty")
	}

	pk, err := hapi.DecodePublicJSON(pubRaw)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	sk, err := hapi.DecodeSecretJSON(secRaw)
	if err != nil {
		return nil, fmt.Errorf("decode secret key: %w", err)
	}

	return &Signer{
		algorithmName:  cfg.AlgorithmName,
		enableVerify:   cfg.EnableVerify,
		strictKeyCheck: cfg.StrictKeyCheck,
		publicKeyRaw:   pubRaw,
		secretKeyRaw:   secRaw,
		publicKey:      pk,
		secretKey:      sk,
	}, nil
}

func (s *Signer) Algorithm() string {
	if s == nil {
		return ""
	}
	return s.algorithmName
}

func (s *Signer) PublicKeyBytes() ([]byte, error) {
	if s == nil {
		return nil, errors.New("signer is nil")
	}
	out := make([]byte, len(s.publicKeyRaw))
	copy(out, s.publicKeyRaw)
	return out, nil
}

func (s *Signer) PublicKeyHash() (string, error) {
	if s == nil {
		return "", errors.New("signer is nil")
	}
	// 공개키 원문(JSON)의 해시를 식별자로 사용
	return ethKeccak256Hex(s.publicKeyRaw), nil
}

func (s *Signer) Sign(msg []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("signer is nil")
	}
	if s.secretKey == nil {
		return nil, errors.New("secret key is nil")
	}
	if s.publicKey == nil {
		return nil, errors.New("public key is nil")
	}
	if len(msg) == 0 {
		return nil, errors.New("msg is empty")
	}

	sig, err := hapi.SignWithPK(s.secretKey, s.publicKey, msg)
	if err != nil {
		return nil, fmt.Errorf("hppk sign: %w", err)
	}

	out, err := hapi.EncodeSignatureJSON(sig)
	if err != nil {
		return nil, fmt.Errorf("encode signature json: %w", err)
	}
	return out, nil
}

func (s *Signer) Verify(pubKey []byte, msg []byte, sig []byte) (bool, error) {
	if s == nil {
		return false, errors.New("signer is nil")
	}
	if !s.enableVerify {
		return true, nil
	}
	if len(pubKey) == 0 {
		return false, errors.New("pubKey is empty")
	}
	if len(msg) == 0 {
		return false, errors.New("msg is empty")
	}
	if len(sig) == 0 {
		return false, errors.New("sig is empty")
	}

	if s.strictKeyCheck && !bytes.Equal(bytes.TrimSpace(pubKey), bytes.TrimSpace(s.publicKeyRaw)) {
		return false, errors.New("public key mismatch against configured key")
	}

	pk, err := hapi.DecodePublicJSON(bytes.TrimSpace(pubKey))
	if err != nil {
		return false, fmt.Errorf("decode verify public key: %w", err)
	}

	parsedSig, err := hapi.DecodeSignatureJSON(bytes.TrimSpace(sig))
	if err != nil {
		return false, fmt.Errorf("decode verify signature: %w", err)
	}

	ok := hapi.Verify(pk, msg, parsedSig)
	return ok, nil
}
