package protocol

import (
	"context"
	"os"
	"testing"
	"time"

	realhppk "github.com/sergelen02/hppk-relay-protocol/agent/internal/hppk"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
)

func loadRealHPPKSigner(t *testing.T) *realhppk.Signer {
	t.Helper()

	publicKeyPath := os.Getenv("/home/seegii/다운로드/hppk-relay-protocol/keys/hppk_pub.key")
	secretKeyPath := os.Getenv("/home/seegii/다운로드/hppk-relay-protocol/keys/hppk_sec.key")

	if publicKeyPath == "" {
		t.Fatal("HPPK_PUBLIC_KEY_PATH is required")
	}
	if secretKeyPath == "" {
		t.Fatal("HPPK_SECRET_KEY_PATH is required")
	}

	signer, err := realhppk.NewSigner(realhppk.SignerConfig{
		PublicKeyPath: publicKeyPath,
		SecretKeyPath: secretKeyPath,
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

	signer := loadRealHPPKSigner(t)

	engine := NewEngine(EngineConfig{
		AgentID:              "real-hppk-agent",
		MyAddress:            "0x2222222222222222222222222222222222222222",
		ExpectedStep:         expectedStep,
		EnablePayloadCompare: true,
		MaxClockSkew:         5 * time.Minute,
		Store:                fs,
		HPPKSigner:           signer,

		// 오프체인 실험이므로 비활성화
		EthClient:   nil,
		RelayClient: nil,
	})

	return engine, fs, signer
}

func makeRealHPPKPacket(
	t *testing.T,
	signer *realhppk.Signer,
	step int,
	nonce uint64,
) RelayPacket {
	t.Helper()

	payload := []byte("real HPPK secure relay message")

	prevChainHash := zeroHashHex()
	if step > 1 {
		prevChainHash =
			"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	}

	packet := RelayPacket{
		SessionID:
			"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Step: step,
		From:
			"0x1111111111111111111111111111111111111111",
		To:
			"0x2222222222222222222222222222222222222222",
		Payload:       payload,
		PayloadHash:   hashBytesHex(payload),
		PrevChainHash: prevChainHash,
		LocalNonce:    nonce,
		Meta: map[string]string{
			"next_address":
				"0x3333333333333333333333333333333333333333",
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

	publicKey, err := signer.PublicKeyBytes()
	if err != nil {
		t.Fatalf("load HPPK public key: %v", err)
	}

	packet.ChainHash = chainHash
	packet.Signature = signature
	packet.PubKey = publicKey

	return packet
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

	if !response.OK {
		t.Fatal("real HPPK packet was rejected")
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
		t.Fatal("saved chainHash does not match response chainHash")
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
	if err == nil {
		t.Fatal("tampered payload was accepted")
	}
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
	if err == nil {
		t.Fatal("tampered chainHash was accepted")
	}
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
	if err == nil {
		t.Fatal("tampered prevChainHash was accepted")
	}
}

func TestProcessRelayRealHPPKReplayReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)
	if err == nil {
		t.Fatal("replayed real HPPK packet was accepted")
	}
}

func TestProcessRelayRealHPPKWrongSequenceReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 3)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)
	if err == nil {
		t.Fatal("wrong sequence packet was accepted")
	}
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
	if err == nil {
		t.Fatal("expired timestamp packet was accepted")
	}
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
	if err == nil {
		t.Fatal("wrong receiver packet was accepted")
	}
}

func TestProcessRelayRealHPPKForgedSignatureReject(t *testing.T) {
	engine, _, signer := newRealHPPKTestEngine(t, 2)
	packet := makeRealHPPKPacket(t, signer, 1, 1)

	if len(packet.Signature) == 0 {
		t.Fatal("real HPPK signature is empty")
	}

	packet.Signature =
		append([]byte(nil), packet.Signature...)

	packet.Signature[len(packet.Signature)/2] ^= 0xff

	_, err := engine.ProcessRelay(
		context.Background(),
		ProcessRelayRequest{Packet: packet},
	)
	if err == nil {
		t.Fatal("forged real HPPK signature was accepted")
	}
}
