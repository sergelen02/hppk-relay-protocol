package protocol

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	realhppk "github.com/sergelen02/hppk-relay-protocol/agent/internal/hppk"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
)

func loadRealHPPKSigner(t *testing.T) *realhppk.Signer {
	t.Helper()

	publicKeyPath := strings.TrimSpace(
		os.Getenv(hppkPublicKeyPathEnv),
	)
	secretKeyPath := strings.TrimSpace(
		os.Getenv(hppkSecretKeyPathEnv),
	)

	if publicKeyPath == "" {
		t.Fatalf(
			"%s environment variable is required",
			hppkPublicKeyPathEnv,
		)
	}

	if secretKeyPath == "" {
		t.Fatalf(
			"%s environment variable is required",
			hppkSecretKeyPathEnv,
		)
	}

	if _, err := os.Stat(publicKeyPath); err != nil {
		t.Fatalf(
			"HPPK public key file is not accessible: path=%s err=%v",
			publicKeyPath,
			err,
		)
	}

	if _, err := os.Stat(secretKeyPath); err != nil {
		t.Fatalf(
			"HPPK secret key file is not accessible: path=%s err=%v",
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
		t.Fatalf("create real HPPK signer: %v", err)
	}

	return signer
}

func newRealHPPKTestEngine(
	t *testing.T,
	expectedStep int,
) (*Engine, *store.FileStore, *realhppk.Signer) {
	t.Helper()

	fs, err := store.NewFileStore(
		t.TempDir() + "/real-hppk-store.json",
	)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	t.Cleanup(func() {
		if err := fs.Close(); err != nil {
			t.Errorf("close test store: %v", err)
		}
	})

	signer := loadRealHPPKSigner(t)

	engine := NewEngine(EngineConfig{
		AgentID:              "real-hppk-agent",
		MyAddress:            realHPPKAgentAddress,
		ExpectedStep:         expectedStep,
		EnablePayloadCompare: true,
		MaxClockSkew:         5 * time.Minute,
		Store:                fs,
		HPPKSigner:           signer,

		// 1단계 오프체인 실험이므로 비활성화합니다.
		EthClient:   nil,
		RelayClient: nil,
	})

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}

	return engine, fs, signer
}

func makeRealHPPKPacket(
	t *testing.T,
	signer *realhppk.Signer,
	step int,
	nonce uint64,
) RelayPacket {
	t.Helper()

	if signer == nil {
		t.Fatal("real HPPK signer is nil")
	}

	if step < 1 {
		t.Fatalf("step must be at least 1: got=%d", step)
	}

	if nonce == 0 {
		t.Fatal("nonce must be greater than zero")
	}

	payload := []byte("real HPPK secure relay message")

	prevChainHash := zeroHashHex()
	if step > 1 {
		prevChainHash =
			"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	}

	packet := RelayPacket{
		SessionID:     realHPPKSessionID,
		Step:          step,
		From:          realHPPKFromAddress,
		To:            realHPPKAgentAddress,
		Payload:       payload,
		PayloadHash:   hashBytesHex(payload),
		PrevChainHash: prevChainHash,
		LocalNonce:    nonce,
		Meta: map[string]string{
			"next_address": realHPPKNextAddress,
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
		t.Fatalf("compute chainHash: %v", err)
	}

	signature, err := signer.Sign(
		mustDecodeHex(chainHash),
	)
	if err != nil {
		t.Fatalf("real HPPK sign: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("real HPPK Sign returned empty signature")
	}

	publicKey, err := signer.PublicKeyBytes()
	if err != nil {
		t.Fatalf("load HPPK public key: %v", err)
	}

	if len(publicKey) == 0 {
		t.Fatal("real HPPK public key is empty")
	}

	packet.ChainHash = chainHash
	packet.Signature = signature
	packet.PubKey = publicKey

	return packet
}

func requireErrorContains(
	t *testing.T,
	err error,
	expectedText string,
) {
	t.Helper()

	if err == nil {
		t.Fatalf(
			"expected error containing %q, got nil",
			expectedText,
		)
	}

	if !strings.Contains(err.Error(), expectedText) {
		t.Fatalf(
			"expected error containing %q, got: %v",
			expectedText,
			err,
		)
	}
}

func TestRealHPPKSignVerifyDirect(t *testing.T) {
	signer := loadRealHPPKSigner(t)

	message := []byte("real HPPK direct verification")

	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := signer.PublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}

	ok, err := signer.Verify(
		publicKey,
		message,
		signature,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("real HPPK direct verification failed")
	}

	t.Logf(
		"real HPPK direct verification passed: publicKey=%d bytes signature=%d bytes",
		len(publicKey),
		len(signature),
	)
}

func TestRealHPPKTamperedMessageDirectReject(t *testing.T) {
	signer := loadRealHPPKSigner(t)

	originalMessage := []byte("original real HPPK message")

	signature, err := signer.Sign(originalMessage)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := signer.PublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}

	ok, err := signer.Verify(
		publicKey,
		[]byte("tampered real HPPK message"),
		signature,
	)
	if err != nil {
		t.Fatal(err)
	}

	if ok {
		t.Fatal("real HPPK accepted signature for tampered message")
	}
}

func TestProcessRelayRealHPPKValidPacket(t *testing.T) {
	engine, fs, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	response, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)
	if err != nil {
		t.Fatal(err)
	}

	if response == nil {
		t.Fatal("ProcessRelay returned nil response")
	}

	if !response.OK {
		t.Fatal("real HPPK packet was rejected")
	}

	if response.AcceptedStep != 2 {
		t.Fatalf(
			"expected accepted step 2, got %d",
			response.AcceptedStep,
		)
	}

	state, ok := fs.GetSessionState(packet.SessionID)
	if !ok {
		t.Fatal("real HPPK session state was not saved")
	}

	if state.LastValidStep != 2 {
		t.Fatalf(
			"expected saved step 2, got %d",
			state.LastValidStep,
		)
	}

	if state.LastChainHash != response.NewChainHash {
		t.Fatalf(
			"saved chainHash mismatch: state=%s response=%s",
			state.LastChainHash,
			response.NewChainHash,
		)
	}
}

func TestProcessRelayRealHPPKPayloadTamperReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.Payload = []byte("tampered payload")

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"payload hash mismatch",
	)
}

func TestProcessRelayRealHPPKChainHashTamperReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.ChainHash =
		"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"chain hash mismatch",
	)
}

func TestProcessRelayRealHPPKPrevChainHashTamperReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.PrevChainHash =
		"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"chain hash mismatch",
	)
}

func TestProcessRelayRealHPPKReplayReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)
	if err != nil {
		t.Fatalf("initial packet processing failed: %v", err)
	}

	_, err = engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"replay detected",
	)
}

func TestProcessRelayRealHPPKWrongSequenceReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 3)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"unexpected incoming step",
	)
}

func TestProcessRelayRealHPPKExpiredTimestampReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.TimestampUnix =
		time.Now().UTC().Add(-1 * time.Hour).Unix()

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"timestamp outside allowed skew",
	)
}

func TestProcessRelayRealHPPKFutureTimestampReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.TimestampUnix =
		time.Now().UTC().Add(1 * time.Hour).Unix()

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"timestamp outside allowed skew",
	)
}

func TestProcessRelayRealHPPKWrongReceiverReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.To =
		"0x9999999999999999999999999999999999999999"

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"wrong recipient",
	)
}

func TestProcessRelayRealHPPKForgedSignatureReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	// JSON 바이트를 깨뜨리는 대신 다른 메시지에 대해 생성한
	// 정상 형식의 HPPK 서명을 사용합니다.
	forgedSignature, err := signer.Sign(
		[]byte("signature generated for a different message"),
	)
	if err != nil {
		t.Fatalf("create forged signature: %v", err)
	}

	packet.Signature = forgedSignature

	_, err = engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"hppk verification returned false",
	)
}

func TestProcessRelayRealHPPKWrongPublicKeyReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.PubKey = []byte(`{"invalid":"public-key"}`)

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	if err == nil {
		t.Fatal("invalid public key was accepted")
	}
}

func TestProcessRelayRealHPPKEmptySignatureReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.Signature = nil

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"signature is required",
	)
}

func TestProcessRelayRealHPPKEmptyPublicKeyReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	packet.PubKey = nil

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)

	requireErrorContains(
		t,
		err,
		"pub_key is required",
	)
}
