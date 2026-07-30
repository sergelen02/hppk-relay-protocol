package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	realhppk "github.com/sergelen02/hppk-relay-protocol/agent/internal/hppk"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
)

const (
	benchmarkAgentAddress = "0x2222222222222222222222222222222222222222"
	benchmarkFromAddress  = "0x1111111111111111111111111111111111111111"
)

type realBenchmarkMemoryStore struct {
	mu sync.RWMutex

	lastNonce       map[string]uint64
	processedPacket map[string]bool
	sessionStates   map[string]store.SessionState
	checkpoints     map[string]store.SessionCheckpoint
}

func newRealBenchmarkMemoryStore() *realBenchmarkMemoryStore {
	return &realBenchmarkMemoryStore{
		lastNonce:       make(map[string]uint64),
		processedPacket: make(map[string]bool),
		sessionStates:   make(map[string]store.SessionState),
		checkpoints:     make(map[string]store.SessionCheckpoint),
	}
}

func (s *realBenchmarkMemoryStore) Ping(_ context.Context) error {
	return nil
}

func (s *realBenchmarkMemoryStore) Close() error {
	return nil
}

func (s *realBenchmarkMemoryStore) GetLastNonce(
	sessionID string,
) (uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, ok := s.lastNonce[sessionID]
	return value, ok
}

func (s *realBenchmarkMemoryStore) SetLastNonce(
	sessionID string,
	nonce uint64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastNonce[sessionID] = nonce
	return nil
}

func (s *realBenchmarkMemoryStore) HasProcessedPacket(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.processedPacket[key]
}

func (s *realBenchmarkMemoryStore) MarkProcessedPacket(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.processedPacket[key] = true
	return nil
}

func (s *realBenchmarkMemoryStore) GetSessionState(
	sessionID string,
) (store.SessionState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, ok := s.sessionStates[sessionID]
	return value, ok
}

func (s *realBenchmarkMemoryStore) SetSessionState(
	state store.SessionState,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.UpdatedAt = time.Now().UTC()
	s.sessionStates[state.SessionID] = state
	return nil
}

func (s *realBenchmarkMemoryStore) GetCheckpoint(
	sessionID string,
) (store.SessionCheckpoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, ok := s.checkpoints[sessionID]
	return value, ok
}

func (s *realBenchmarkMemoryStore) SetCheckpoint(
	checkpoint store.SessionCheckpoint,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	checkpoint.CreatedAt = time.Now().UTC()
	s.checkpoints[checkpoint.SessionID] = checkpoint
	return nil
}

// loadRealBenchmarkSigner는 환경변수에 지정된 실제 HPPK 키를 읽습니다.
//
// 잘못된 형태:
//
//	os.Getenv("/home/.../hppk_pub.key")
//
// 올바른 형태:
//
//	os.Getenv("HPPK_PUBLIC_KEY_PATH")
func loadRealBenchmarkSigner(b *testing.B) *realhppk.Signer {
	b.Helper()

	publicKeyPath := os.Getenv(hppkPublicKeyPathEnv)
	secretKeyPath := os.Getenv(hppkSecretKeyPathEnv)

	if publicKeyPath == "" {
		b.Fatalf(
			"%s environment variable is required",
			hppkPublicKeyPathEnv,
		)
	}

	if secretKeyPath == "" {
		b.Fatalf(
			"%s environment variable is required",
			hppkSecretKeyPathEnv,
		)
	}

	if _, err := os.Stat(publicKeyPath); err != nil {
		b.Fatalf(
			"public key file is not accessible: path=%s err=%v",
			publicKeyPath,
			err,
		)
	}

	if _, err := os.Stat(secretKeyPath); err != nil {
		b.Fatalf(
			"secret key file is not accessible: path=%s err=%v",
			secretKeyPath,
			err,
		)
	}

	signer, err := realhppk.NewSigner(realhppk.SignerConfig{
		PublicKeyPath:  publicKeyPath,
		SecretKeyPath:  secretKeyPath,
		AlgorithmName:  "HPPK",
		EnableVerify:   true,
		StrictKeyCheck: true,
	})
	if err != nil {
		b.Fatalf("create real HPPK signer: %v", err)
	}

	return signer
}

func newRealBenchmarkEngineWithSigner(
	signer *realhppk.Signer,
) *Engine {
	return NewEngine(EngineConfig{
		AgentID:              "real-hppk-benchmark-agent",
		MyAddress:            benchmarkAgentAddress,
		ExpectedStep:         2,
		EnablePayloadCompare: true,
		MaxClockSkew:         5 * time.Minute,
		Store:                newRealBenchmarkMemoryStore(),
		HPPKSigner:           signer,

		// 순수 오프체인 프로토콜 성능만 측정합니다.
		EthClient:   nil,
		RelayClient: nil,
	})
}

func makeRealBenchmarkPacket(
	tb testing.TB,
	signer *realhppk.Signer,
	index int,
	payloadSize int,
) RelayPacket {
	tb.Helper()

	if payloadSize <= 0 {
		tb.Fatalf("payload size must be positive: %d", payloadSize)
	}

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	sessionID := fmt.Sprintf("0x%064x", index+1)

	packet := RelayPacket{
		SessionID:     sessionID,
		Step:          1,
		From:          benchmarkFromAddress,
		To:            benchmarkAgentAddress,
		Payload:       payload,
		PayloadHash:   hashBytesHex(payload),
		PrevChainHash: zeroHashHex(),
		LocalNonce:    uint64(index + 1),
		Meta: map[string]string{
			"benchmark": "real-hppk",
		},
		TimestampUnix: time.Now().UTC().Unix(),
	}

	chainHash, err := computeChainHash(
		packet.SessionID,
		packet.Step,
		packet.From,
		packet.To,
		packet.PayloadHash,
		packet.PrevChainHash,
		packet.LocalNonce,
		packet.TimestampUnix,
		packet.Meta,
	)
	if err != nil {
		tb.Fatalf("compute chain hash: %v", err)
	}

	signature, err := signer.Sign(mustDecodeHex(chainHash))
	if err != nil {
		tb.Fatalf("sign packet chain hash: %v", err)
	}

	publicKey, err := signer.PublicKeyBytes()
	if err != nil {
		tb.Fatalf("load public key bytes: %v", err)
	}

	packet.ChainHash = chainHash
	packet.Signature = signature
	packet.PubKey = publicKey

	return packet
}

func BenchmarkRealHPPKSign32Bytes(b *testing.B) {
	signer := loadRealBenchmarkSigner(b)
	message := make([]byte, 32)

	b.SetBytes(int64(len(message)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		signature, err := signer.Sign(message)
		if err != nil {
			b.Fatal(err)
		}

		runtime.KeepAlive(signature)
	}
}

func BenchmarkRealHPPKVerify32Bytes(b *testing.B) {
	signer := loadRealBenchmarkSigner(b)
	message := make([]byte, 32)

	signature, err := signer.Sign(message)
	if err != nil {
		b.Fatal(err)
	}

	publicKey, err := signer.PublicKeyBytes()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(message)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ok, verifyErr := signer.Verify(
			publicKey,
			message,
			signature,
		)
		if verifyErr != nil {
			b.Fatal(verifyErr)
		}
		if !ok {
			b.Fatal("real HPPK verification returned false")
		}
	}
}

// 이 benchmark의 ns/op는 의미가 없습니다.
// 논문에는 public_key_bytes 값만 사용하세요.
func BenchmarkRealHPPKPublicKeySize(b *testing.B) {
	signer := loadRealBenchmarkSigner(b)

	publicKey, err := signer.PublicKeyBytes()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportMetric(
		float64(len(publicKey)),
		"public_key_bytes",
	)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		runtime.KeepAlive(publicKey)
	}
}

// 이 benchmark의 ns/op는 의미가 없습니다.
// 논문에는 signature_bytes 값만 사용하세요.
func BenchmarkRealHPPKSignatureSize(b *testing.B) {
	signer := loadRealBenchmarkSigner(b)
	message := make([]byte, 32)

	signature, err := signer.Sign(message)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportMetric(
		float64(len(signature)),
		"signature_bytes",
	)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		runtime.KeepAlive(signature)
	}
}

func BenchmarkProcessRelayRealHPPK32Bytes(b *testing.B) {
	benchmarkProcessRelayRealHPPK(b, 32)
}

func BenchmarkProcessRelayRealHPPK128Bytes(b *testing.B) {
	benchmarkProcessRelayRealHPPK(b, 128)
}

func BenchmarkProcessRelayRealHPPK512Bytes(b *testing.B) {
	benchmarkProcessRelayRealHPPK(b, 512)
}

func BenchmarkProcessRelayRealHPPK1024Bytes(b *testing.B) {
	benchmarkProcessRelayRealHPPK(b, 1024)
}

// 이 벤치마크는 패킷 생성과 송신자 서명 비용을 제외하고,
// 수신 측 Engine.ProcessRelay() 처리 비용만 측정합니다.
//
// 포함:
//   - 기본 필드 검증
//   - replay 검사
//   - payloadHash 검사
//   - chainHash 재계산
//   - 실제 HPPK Verify
//   - 다음 chainHash 생성
//   - 실제 HPPK Sign
//   - session state 저장
//
// 제외:
//   - 입력 패킷 생성
//   - 입력 패킷 최초 서명
//   - Ethereum 제출
//   - HTTP 전송
func benchmarkProcessRelayRealHPPK(
	b *testing.B,
	payloadSize int,
) {
	signer := loadRealBenchmarkSigner(b)
	engine := newRealBenchmarkEngineWithSigner(signer)
	ctx := context.Background()

	firstPacket := makeRealBenchmarkPacket(
		b,
		signer,
		1,
		payloadSize,
	)

	packetJSON, err := json.Marshal(firstPacket)
	if err != nil {
		b.Fatalf("marshal benchmark packet: %v", err)
	}

	b.ReportMetric(
		float64(len(firstPacket.Signature)),
		"signature_bytes",
	)

	b.ReportMetric(
		float64(len(firstPacket.PubKey)),
		"public_key_bytes",
	)

	b.ReportMetric(
		float64(len(packetJSON)),
		"packet_json_bytes",
	)

	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 패킷 생성과 최초 송신자 서명은 ProcessRelay 성능이 아니므로
		// 측정 시간에서 제외합니다.
		b.StopTimer()

		packet := makeRealBenchmarkPacket(
			b,
			signer,
			i+1000,
			payloadSize,
		)

		b.StartTimer()

		response, processErr := engine.ProcessRelay(
			ctx,
			ProcessRelayRequest{Packet: packet},
		)
		if processErr != nil {
			b.Fatal(processErr)
		}
		if !response.OK {
			b.Fatal("real HPPK relay returned non-OK response")
		}
	}
}

// 위조된 서명이 수신된 이후의 거부 비용만 측정합니다.
// 정상 서명 생성과 패킷 생성 시간은 제외합니다.
func BenchmarkRejectRealHPPKForgedSignature(b *testing.B) {
	signer := loadRealBenchmarkSigner(b)
	engine := newRealBenchmarkEngineWithSigner(signer)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		packet := makeRealBenchmarkPacket(
			b,
			signer,
			i+5000,
			32,
		)

		packet.Signature = append(
			[]byte(nil),
			packet.Signature...,
		)

		packet.Signature[len(packet.Signature)/2] ^= 0xff

		b.StartTimer()

		_, err := engine.ProcessRelay(
			ctx,
			ProcessRelayRequest{Packet: packet},
		)
		if err == nil {
			b.Fatal("forged signature was accepted")
		}
	}
}

// 첫 번째 정상 처리는 측정에서 제외하고,
// 동일 패킷의 두 번째 replay 거부 경로만 측정합니다.
func BenchmarkRejectRealHPPKReplay(b *testing.B) {
	signer := loadRealBenchmarkSigner(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// 각 반복은 독립된 store를 사용해야 합니다.
		engine := newRealBenchmarkEngineWithSigner(signer)

		packet := makeRealBenchmarkPacket(
			b,
			signer,
			i+10000,
			32,
		)

		_, err := engine.ProcessRelay(
			ctx,
			ProcessRelayRequest{Packet: packet},
		)
		if err != nil {
			b.Fatalf(
				"initial valid packet failed before replay test: %v",
				err,
			)
		}

		b.StartTimer()

		_, err = engine.ProcessRelay(
			ctx,
			ProcessRelayRequest{Packet: packet},
		)

		b.StopTimer()

		if err == nil {
			b.Fatal("replayed packet was accepted")
		}
	}
}
