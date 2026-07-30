package hppk

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/sergelen02/HPPK_2/pkg/hppkapi"
)

const defaultAlgorithmName = "HPPK"

type Config struct {
	PublicKeyPath  string
	SecretKeyPath  string
	AlgorithmName  string
	EnableVerify   bool
	StrictKeyCheck bool
}

// SignerConfig는 기존 호출부와의 호환성을 위한 별칭입니다.
type SignerConfig = Config

type Signer struct {
	mu sync.RWMutex

	algorithmName  string
	enableVerify   bool
	strictKeyCheck bool

	publicKey *hppkapi.Public
	secretKey *hppkapi.Secret

	// Decode 후 다시 직렬화한 canonical JSON입니다.
	// 패킷에 포함할 공개키와 공개키 해시 계산에 사용합니다.
	publicKeyJSON []byte

	// canonical publicKeyJSON에 대한 Keccak-256 해시입니다.
	publicKeyHash string
}

func NewSigner(cfg Config) (*Signer, error) {
	publicKeyPath := strings.TrimSpace(cfg.PublicKeyPath)
	secretKeyPath := strings.TrimSpace(cfg.SecretKeyPath)

	if publicKeyPath == "" {
		return nil, errors.New("HPPK public key path is required")
	}

	if secretKeyPath == "" {
		return nil, errors.New("HPPK secret key path is required")
	}

	algorithmName := strings.TrimSpace(cfg.AlgorithmName)
	if algorithmName == "" {
		algorithmName = defaultAlgorithmName
	}

	if err := validateRegularFile(publicKeyPath, "HPPK public key"); err != nil {
		return nil, err
	}

	if err := validateRegularFile(secretKeyPath, "HPPK secret key"); err != nil {
		return nil, err
	}

	publicKeyFileBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read HPPK public key %q: %w",
			publicKeyPath,
			err,
		)
	}

	if len(publicKeyFileBytes) == 0 {
		return nil, fmt.Errorf(
			"HPPK public key file %q is empty",
			publicKeyPath,
		)
	}

	secretKeyFileBytes, err := os.ReadFile(secretKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read HPPK secret key %q: %w",
			secretKeyPath,
			err,
		)
	}

	if len(secretKeyFileBytes) == 0 {
		return nil, fmt.Errorf(
			"HPPK secret key file %q is empty",
			secretKeyPath,
		)
	}

	// JSON decode가 끝난 뒤 비밀키 원본 바이트를 가능한 한 빨리 지웁니다.
	defer zeroBytes(secretKeyFileBytes)

	publicKey, err := hppkapi.DecodePublicJSON(publicKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"decode HPPK public key: %w",
			err,
		)
	}

	if publicKey == nil {
		return nil, errors.New("decoded HPPK public key is nil")
	}

	secretKey, err := hppkapi.DecodeSecretJSON(secretKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"decode HPPK secret key: %w",
			err,
		)
	}

	if secretKey == nil {
		return nil, errors.New("decoded HPPK secret key is nil")
	}

	// 입력 JSON의 공백과 필드 순서 영향을 줄이기 위해
	// decode 후 다시 JSON으로 직렬화합니다.
	canonicalPublicKeyJSON, err :=
		hppkapi.EncodePublicJSON(publicKey)
	if err != nil {
		return nil, fmt.Errorf(
			"encode canonical HPPK public key: %w",
			err,
		)
	}

	if len(canonicalPublicKeyJSON) == 0 {
		return nil, errors.New(
			"canonical HPPK public key JSON is empty",
		)
	}

	publicKeyHash :=
		ethcrypto.Keccak256Hash(canonicalPublicKeyJSON).Hex()

	signer := &Signer{
		algorithmName:  algorithmName,
		enableVerify:   cfg.EnableVerify,
		strictKeyCheck: cfg.StrictKeyCheck,

		publicKey: publicKey,
		secretKey: secretKey,

		publicKeyJSON: cloneBytes(canonicalPublicKeyJSON),
		publicKeyHash: publicKeyHash,
	}

	// Verify 기능이 활성화된 경우 실제 공개키·비밀키 쌍을 검사합니다.
	if signer.enableVerify {
		if err := signer.selfTest(); err != nil {
			return nil, fmt.Errorf(
				"HPPK key-pair self-test failed: %w",
				err,
			)
		}
	}

	return signer, nil
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
		return nil, fmt.Errorf(
			"HPPK SignWithPK: %w",
			err,
		)
	}

	if signature == nil {
		return nil, errors.New(
			"HPPK SignWithPK returned nil signature",
		)
	}

	signatureJSON, err :=
		hppkapi.EncodeSignatureJSON(signature)
	if err != nil {
		return nil, fmt.Errorf(
			"encode HPPK signature JSON: %w",
			err,
		)
	}

	if len(signatureJSON) == 0 {
		return nil, errors.New(
			"encoded HPPK signature is empty",
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

	if !s.enableVerify {
		return false, errors.New(
			"HPPK verification is disabled",
		)
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

	if publicKey == nil {
		return false, errors.New(
			"decoded received HPPK public key is nil",
		)
	}

	// 수신 공개키도 canonical JSON으로 변환하여 비교합니다.
	canonicalReceivedPublicKey, err :=
		hppkapi.EncodePublicJSON(publicKey)
	if err != nil {
		return false, fmt.Errorf(
			"encode received HPPK public key: %w",
			err,
		)
	}

	if len(canonicalReceivedPublicKey) == 0 {
		return false, errors.New(
			"canonical received HPPK public key is empty",
		)
	}

	// StrictKeyCheck가 true이면 이 Signer에 등록된 공개키만 허용합니다.
	if s.strictKeyCheck {
		s.mu.RLock()
		localPublicKeyJSON := cloneBytes(s.publicKeyJSON)
		s.mu.RUnlock()

		if !constantTimeBytesEqual(
			localPublicKeyJSON,
			canonicalReceivedPublicKey,
		) {
			return false, errors.New(
				"received HPPK public key does not match registered public key",
			)
		}
	}

	signature, err :=
		hppkapi.DecodeSignatureJSON(signatureJSON)
	if err != nil {
		return false, fmt.Errorf(
			"decode received HPPK signature: %w",
			err,
		)
	}

	if signature == nil {
		return false, errors.New(
			"decoded HPPK signature is nil",
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
		return nil, errors.New(
			"HPPK public key JSON is empty",
		)
	}

	return cloneBytes(s.publicKeyJSON), nil
}

// PublicKeyHash는 canonical public-key JSON의 Keccak-256 해시를 반환합니다.
func (s *Signer) PublicKeyHash() (string, error) {
	if s == nil {
		return "", errors.New("HPPK signer is nil")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if strings.TrimSpace(s.publicKeyHash) == "" {
		return "", errors.New(
			"HPPK public key hash is empty",
		)
	}

	return s.publicKeyHash, nil
}

func (s *Signer) AlgorithmName() string {
	if s == nil {
		return ""
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.algorithmName
}

func (s *Signer) VerificationEnabled() bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.enableVerify
}

func (s *Signer) StrictKeyCheckEnabled() bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.strictKeyCheck
}

// selfTest는 로드된 공개키와 비밀키가 실제 서명·검증 가능한 쌍인지 확인합니다.
func (s *Signer) selfTest() error {
	if s == nil {
		return errors.New("HPPK signer is nil")
	}

	if !s.enableVerify {
		return errors.New(
			"cannot run self-test while verification is disabled",
		)
	}

	testMessage := []byte(
		"hppk-relay-protocol-signer-self-test",
	)

	signatureJSON, err := s.Sign(testMessage)
	if err != nil {
		return fmt.Errorf("self-test sign: %w", err)
	}

	publicKeyJSON, err := s.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf(
			"self-test public key: %w",
			err,
		)
	}

	ok, err := s.Verify(
		publicKeyJSON,
		testMessage,
		signatureJSON,
	)
	if err != nil {
		return fmt.Errorf("self-test verify: %w", err)
	}

	if !ok {
		return errors.New(
			"self-test verification returned false",
		)
	}

	return nil
}

func validateRegularFile(path, description string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf(
			"%s file %q is not accessible: %w",
			description,
			path,
			err,
		)
	}

	if info.IsDir() {
		return fmt.Errorf(
			"%s path %q is a directory",
			description,
			path,
		)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf(
			"%s path %q is not a regular file",
			description,
			path,
		)
	}

	return nil
}

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	dst := make([]byte, len(src))
	copy(dst, src)

	return dst
}

func zeroBytes(src []byte) {
	for i := range src {
		src[i] = 0
	}
}

func constantTimeBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	if len(a) == 0 {
		return true
	}

	return subtle.ConstantTimeCompare(a, b) == 1
}
