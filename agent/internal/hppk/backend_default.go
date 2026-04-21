package hppk

import (
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
)

// 기본 backend는 "구조 테스트용"이 아니라,
// 적어도 Ethereum 스타일 해시 기반으로만 맞춰둔다.
// 실제 논문 실험 전에는 이 파일을 HPPK_2 어댑터로 교체해야 한다.

func (b *defaultBackend) Sign(secretKeyRaw []byte, msg []byte) ([]byte, error) {
	if len(secretKeyRaw) == 0 {
		return nil, errors.New("secret key is empty")
	}
	if len(msg) == 0 {
		return nil, errors.New("msg is empty")
	}
	// TODO: 실제 HPPK_2 Sign으로 교체
	hash := crypto.Keccak256(secretKeyRaw, msg)
	return hash, nil
}

func (b *defaultBackend) Verify(publicKeyRaw []byte, msg []byte, sig []byte) (bool, error) {
	if len(publicKeyRaw) == 0 {
		return false, errors.New("public key is empty")
	}
	if len(msg) == 0 {
		return false, errors.New("msg is empty")
	}
	if len(sig) == 0 {
		return false, errors.New("sig is empty")
	}
	// TODO: 실제 HPPK_2 Verify로 교체
	_ = publicKeyRaw
	_ = msg
	_ = sig
	return true, nil
}

func ethKeccak256Hex(b []byte) string {
	return crypto.Keccak256Hash(b).Hex()
}
