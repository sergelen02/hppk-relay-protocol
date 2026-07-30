package protocol

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	realhppk "github.com/sergelen02/hppk-relay-protocol/agent/internal/hppk"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
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

func (s *realBenchmarkMemoryStore) Ping(
	_ context.Context,
) error {
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

func (s *realBenchmarkMemoryStore) HasProcessedPacket(
	key string,
) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.processedPacket[key]
}

func (s *realBenchmarkMemoryStore) MarkProcessedPacket(
	key string,
) error {
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

	s.checkpoints[checkpoint.SessionID] = checkpoint
	return nil
}

func loadRealBenchmarkSigner(
	b *testing.B,
) *realhppk.Signer {
	b.Helper()

	publicKeyPath := os.Getenv("/home/seegii/다운로드/hppk-relay-protocol/keys/hppk_pub.key")
	secretKeyPath := os.Getenv("/home/seegii/다운로드/hppk-relay-protocol/keys/hppk_sec.key")

	if publicKeyPath == "" {
		b.Fatal("HPPK_PUBLIC_KEY_PATH is required")
	}
	if secretKeyPath == "" {
		b.Fatal("HPPK_SECRET_KEY_PATH is required")
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

func newRealBenchmarkEngine(
	b *testing.B,
) (*Engine, *realhppk.Signer) {
	b.Helper()

	signer := loadRealBenchmarkSigner(b)

	engine := NewEngine(EngineConfig{
		AgentID:              "real-hppk-benchmark-agent",
		MyAddress:            "0x2222222222222222222222222222222222222222",
		ExpectedStep:         2,
		EnablePayloadCompare: true,
		MaxClockSkew:         5 * time.Minute,
		Store:                newRealBenchmarkMemoryStore(),
		HPPKSigner:           signer,
		EthClient:            nil,
		RelayClient:          nil,
	})

	return engine, signer
}

func makeRealBenchmarkPacket(
	b *testing.B,
	signer *realhppk.Signer,
	index int,
	payloadSize int,
) RelayPacket {
	b.Helper()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	sessionID := fmt.Sprintf(
		"0x%064x",
		index+1,
	)

	packet := RelayPacket{
		SessionID:     sessionID,
		Step:          1,
		From:          "0x1111111111111111111111111111111111111111",
		To:            "0x2222222222222222222222222222222222222222",
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
		b.Fatal(err)
	}

	signature, err := signer.Sign(
		mustDecodeHex(chainHash),
	)
	if err != nil {
		b.Fatal(err)
	}

	publicKey, err := signer.PublicKeyBytes()
	if err != nil {
		b.Fatal(err)
	}

	packet.ChainHash = chainHash
	packet.Signature = signature
	packet.PubKey = publicKey

	return packet
}

func BenchmarkRealHPPKSign32Bytes(b *testing.B) {
	signer := loadRealBenchmarkSigner(b)
	message := make([]byte, 32)

	b.ReportAllocs()
	b.SetBytes(int64(len(message)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(message)
		if err != nil {
			b.Fatal(err)
		}
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

	b.ReportAllocs()
	b.SetBytes(int64(len(message)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ok, err := signer.Verify(
			publicKey,
			message,
			signature,
		)
		if err != nil {
			b.Fatal(err)
		}
		if !ok {
			b.Fatal("real HPPK verification failed")
		}
	}
}

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

	for i := 0; i < b.N; i++ {
		_ = len(publicKey)
	}
}

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

	for i := 0; i < b.N; i++ {
		_ = len(signature)
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

func benchmarkProcessRelayRealHPPK(
	b *testing.B,
	payloadSize int,
) {
	engine, signer := newRealBenchmarkEngine(b)

	firstPacket :=
		makeRealBenchmarkPacket(
			b,
			signer,
			1,
			payloadSize,
		)

	b.ReportMetric(
		float64(len(firstPacket.Signature)),
		"signature_bytes",
	)
	b.ReportMetric(
		float64(len(firstPacket.PubKey)),
		"public_key_bytes",
	)

	packetBytes :=
		len(firstPacket.Payload) +
			len(firstPacket.Signature) +
			len(firstPacket.PubKey) +
			len(firstPacket.SessionID) +
			len(firstPacket.From) +
			len(firstPacket.To) +
			len(firstPacket.PayloadHash) +
			len(firstPacket.PrevChainHash) +
			len(firstPacket.ChainHash)

	b.ReportMetric(
		float64(packetBytes),
		"estimated_packet_bytes",
	)

	b.ReportAllocs()
	b.SetBytes(int64(payloadSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		packet := makeRealBenchmarkPacket(
			b,
			signer,
			i+1000,
			payloadSize,
		)

		response, err := engine.ProcessRelay(
			context.Background(),
			ProcessRelayRequest{Packet: packet},
		)
		if err != nil {
			b.Fatal(err)
		}
		if !response.OK {
			b.Fatal("real HPPK relay failed")
		}
	}
}

func BenchmarkRejectRealHPPKForgedSignature(b *testing.B) {
	engine, signer := newRealBenchmarkEngine(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		packet := makeRealBenchmarkPacket(
			b,
			signer,
			i+5000,
			32,
		)

		packet.Signature =
			append([]byte(nil), packet.Signature...)

		packet.Signature[len(packet.Signature)/2] ^= 0xff

		_, err := engine.ProcessRelay(
			context.Background(),
			ProcessRelayRequest{Packet: packet},
		)
		if err == nil {
			b.Fatal("forged signature was accepted")
		}
	}
}

func BenchmarkRejectRealHPPKReplay(b *testing.B) {
	for i := 0; i < b.N; i++ {
		engine, signer := newRealBenchmarkEngine(b)

		packet := makeRealBenchmarkPacket(
			b,
			signer,
			i+10000,
			32,
		)

		_, err := engine.ProcessRelay(
			context.Background(),
			ProcessRelayRequest{Packet: packet},
		)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()

		_, err = engine.ProcessRelay(
			context.Background(),
			ProcessRelayRequest{Packet: packet},
		)

		b.StopTimer()

		if err == nil {
			b.Fatal("replayed packet was accepted")
		}
	}
}
