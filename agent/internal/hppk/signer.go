package hppk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
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

	publicKey  []byte
	secretKey  []byte
	pubKeyHash string
}

// NewSigner는 현재 "어댑터 + placeholder" 구현이다.
// 실제 HPPK 라이브러리로 교체할 때는 아래 3개만 바꾸면 된다.
//  1. Sign
//  2. Verify
//  3. key loading/decoding
func NewSigner(cfg SignerConfig) (*Signer, error) {
	if strings.TrimSpace(cfg.PublicKeyPath) == "" {
		return nil, errors.New("public key path is required")
	}
	if strings.TrimSpace(cfg.SecretKeyPath) == "" {
		return nil, errors.New("secret key path is required")
	}

	pub, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	sec, err := os.ReadFile(cfg.SecretKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read secret key file: %w", err)
	}

	pub = bytes.TrimSpace(pub)
	sec = bytes.TrimSpace(sec)

	if len(pub) == 0 {
		return nil, errors.New("public key file is empty")
	}
	if len(sec) == 0 {
		return nil, errors.New("secret key file is empty")
	}

	pubHash := sha256.Sum256(pub)

	s := &Signer{
		algorithmName:  strings.TrimSpace(cfg.AlgorithmName),
		enableVerify:   cfg.EnableVerify,
		strictKeyCheck: cfg.StrictKeyCheck,
		publicKey:      pub,
		secretKey:      sec,
		pubKeyHash:     "0x" + hex.EncodeToString(pubHash[:]),
	}

	return s, nil
}

func (s *Signer) Algorithm() string {
	if s == nil {
		return ""
	}
	return s.algorithmName
}

func (s *Signer) PublicKeyHash() (string, error) {
	if s == nil {
		return "", errors.New("signer is nil")
	}
	return s.pubKeyHash, nil
}

func (s *Signer) PublicKeyBytes() ([]byte, error) {
	if s == nil {
		return nil, errors.New("signer is nil")
	}
	out := make([]byte, len(s.publicKey))
	copy(out, s.publicKey)
	return out, nil
}

func (s *Signer) SecretKeyBytes() ([]byte, error) {
	if s == nil {
		return nil, errors.New("signer is nil")
	}
	out := make([]byte, len(s.secretKey))
	copy(out, s.secretKey)
	return out, nil
}

// Sign은 현재 placeholder 구현이다.
// 현재 규칙:
//
//	signature = sha256(secretKey || msg)
//
// 실제 HPPK 라이브러리 연결 시:
//
//	sig, err := realhppk.Sign(sk, msg)
//
// 로 교체해야 한다.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("signer is nil")
	}
	if len(msg) == 0 {
		return nil, errors.New("msg is empty")
	}

	h := sha256.New()
	h.Write(s.secretKey)
	h.Write(msg)
	sum := h.Sum(nil)

	return sum, nil
}

// Verify는 현재 placeholder 구현이다.
// 현재 규칙:
//
//	expected = sha256(secretKey || msg)
//	expected == sig
//
// 이 구현은 진짜 공개키 검증이 아니라 "개발 골격용"이다.
// 실제 HPPK 라이브러리 연결 시:
//
//	ok := realhppk.Verify(pubKey, msg, sig)
//
// 로 반드시 교체해야 한다.
func (s *Signer) Verify(pubKey []byte, msg []byte, sig []byte) (bool, error) {
	if s == nil {
		return false, errors.New("signer is nil")
	}
	if !s.enableVerify {
		return true, nil
	}
	if len(msg) == 0 {
		return false, errors.New("msg is empty")
	}
	if len(sig) == 0 {
		return false, errors.New("sig is empty")
	}
	if len(pubKey) == 0 {
		return false, errors.New("pubKey is empty")
	}

	if s.strictKeyCheck && !bytes.Equal(bytes.TrimSpace(pubKey), bytes.TrimSpace(s.publicKey)) {
		return false, errors.New("public key mismatch against local configured public key")
	}

	expected, err := s.Sign(msg)
	if err != nil {
		return false, err
	}

	return bytes.Equal(expected, sig), nil
}
