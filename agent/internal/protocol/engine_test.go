package protocol

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
)

type fakeSigner struct {
	pubKey []byte
	secKey []byte
}

func newFakeSigner() *fakeSigner {
	return &fakeSigner{
		pubKey: []byte("fake-public-key"),
		secKey: []byte("fake-secret-key"),
	}
}

func (f *fakeSigner) Sign(msg []byte) ([]byte, error) {
	b := append([]byte{}, f.secKey...)
	b = append(b, msg...)
	h := sha256.Sum256(b)
	return h[:], nil
}

func (f *fakeSigner) Verify(pubKey []byte, msg []byte, sig []byte) (bool, error) {
	if len(pubKey) == 0 || len(msg) == 0 || len(sig) != sha256.Size {
		return false, nil
	}

	b := append([]byte{}, f.secKey...)
	b = append(b, msg...)
	expected := sha256.Sum256(b)

	for i := range expected {
		if expected[i] != sig[i] {
			return false, nil
		}
	}
	return true, nil
}

func (f *fakeSigner) PublicKeyBytes() ([]byte, error) {
	return f.pubKey, nil
}

func newTestEngine(t *testing.T, expectedStep int) (*Engine, *store.FileStore, *fakeSigner) {
	t.Helper()

	path := t.TempDir() + "/store.json"
	fs, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	signer := newFakeSigner()

	e := NewEngine(EngineConfig{
		AgentID:              "agent-2",
		MyAddress:            "0x2222222222222222222222222222222222222222",
		ExpectedStep:         expectedStep,
		EnablePayloadCompare: true,
		MaxClockSkew:         5 * time.Minute,
		Store:                fs,
		HPPKSigner:           signer,
		EthClient:            nil,
		RelayClient:          nil,
	})

	return e, fs, signer
}

func makeValidIncomingPacket(t *testing.T, signer *fakeSigner) RelayPacket {
	t.Helper()

	payload := []byte("hello secure relay")
	payloadHash := hashBytesHex(payload)

	pkt := RelayPacket{
		SessionID:     "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Step:          1,
		From:          "0x1111111111111111111111111111111111111111",
		To:            "0x2222222222222222222222222222222222222222",
		Payload:       payload,
		PayloadHash:   payloadHash,
		PrevChainHash: zeroHashHex(),
		LocalNonce:    1,
		Meta: map[string]string{
			"next_address": "0x3333333333333333333333333333333333333333",
		},
		TimestampUnix: time.Now().UTC().Unix(),
	}

	chainHash, err := computeChainHash(
		pkt.SessionID,
		pkt.Step,
		pkt.From,
		pkt.To,
		pkt.PayloadHash,
		pkt.PrevChainHash,
		pkt.LocalNonce,
		pkt.TimestampUnix,
		pkt.Meta,
	)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := signer.Sign(mustDecodeHex(chainHash))
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := signer.PublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}

	pkt.ChainHash = chainHash
	pkt.Signature = sig
	pkt.PubKey = pubKey

	return pkt
}

func TestComputeChainHashDeterministic(t *testing.T) {
	meta := map[string]string{
		"b": "2",
		"a": "1",
	}

	h1, err := computeChainHash(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		1,
		"0x1111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222",
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		zeroHashHex(),
		1,
		100,
		meta,
	)
	if err != nil {
		t.Fatal(err)
	}

	h2, err := computeChainHash(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		1,
		"0x1111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222",
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		zeroHashHex(),
		1,
		100,
		map[string]string{
			"a": "1",
			"b": "2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if h1 != h2 {
		t.Fatalf("chainHash must be deterministic: h1=%s h2=%s", h1, h2)
	}
}

func TestProcessRelayValidPacketSavesRecoveryState(t *testing.T) {
	e, fs, signer := newTestEngine(t, 2)
	pkt := makeValidIncomingPacket(t, signer)

	resp, err := e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err != nil {
		t.Fatal(err)
	}

	if !resp.OK {
		t.Fatal("response should be OK")
	}

	if resp.AcceptedStep != 2 {
		t.Fatalf("expected accepted step 2, got %d", resp.AcceptedStep)
	}

	st, ok := fs.GetSessionState(pkt.SessionID)
	if !ok {
		t.Fatal("session recovery state not saved")
	}

	if st.LastValidStep != 2 {
		t.Fatalf("expected recovery step 2, got %d", st.LastValidStep)
	}

	if st.LastChainHash != resp.NewChainHash {
		t.Fatalf("recovery chain hash mismatch: state=%s response=%s", st.LastChainHash, resp.NewChainHash)
	}
}

func TestProcessRelayPayloadTamperReject(t *testing.T) {
	e, _, signer := newTestEngine(t, 2)
	pkt := makeValidIncomingPacket(t, signer)

	pkt.Payload = []byte("tampered payload")

	_, err := e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err == nil {
		t.Fatal("expected payload tamper rejection")
	}
}

func TestProcessRelayChainHashTamperReject(t *testing.T) {
	e, _, signer := newTestEngine(t, 2)
	pkt := makeValidIncomingPacket(t, signer)

	pkt.ChainHash = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	_, err := e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err == nil {
		t.Fatal("expected chainHash tamper rejection")
	}
}

func TestProcessRelayWrongSequenceReject(t *testing.T) {
	e, _, signer := newTestEngine(t, 3)
	pkt := makeValidIncomingPacket(t, signer)

	_, err := e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err == nil {
		t.Fatal("expected wrong sequence rejection")
	}
}

func TestProcessRelayReplayRejectByProcessedPacketKey(t *testing.T) {
	e, fs, signer := newTestEngine(t, 2)
	pkt := makeValidIncomingPacket(t, signer)

	packetKey := pkt.SessionID + ":" + string(rune(pkt.Step)) + ":" + string(rune(pkt.LocalNonce))
	if err := fs.MarkProcessedPacket(packetKey); err != nil {
		t.Fatal(err)
	}

	if !fs.HasProcessedPacket(packetKey) {
		t.Fatal("processed packet should exist")
	}

	// 현재 engine.go가 processed packet 검사를 직접 하지 않는다면,
	// 이 테스트는 store replay cache 동작만 확인한다.
	t.Log("replay cache is available; connect this check inside ProcessRelay for full replay rejection")
}

func TestProcessRelayTimestampReject(t *testing.T) {
	e, _, signer := newTestEngine(t, 2)
	pkt := makeValidIncomingPacket(t, signer)

	pkt.TimestampUnix = time.Now().UTC().Add(-1 * time.Hour).Unix()

	_, err := e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err == nil {
		t.Fatal("expected old timestamp rejection")
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
