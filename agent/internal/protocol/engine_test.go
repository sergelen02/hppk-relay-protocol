package protocol

import (
	"context"
	"crypto/sha256"
	"fmt"
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

	fs, err := store.NewFileStore(t.TempDir() + "/store.json")
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
	return makeValidIncomingPacketWithStep(t, signer, 1, 1)
}

func makeValidIncomingPacketWithStep(t *testing.T, signer *fakeSigner, step int, nonce uint64) RelayPacket {
	t.Helper()

	payload := []byte("hello secure relay")
	payloadHash := hashBytesHex(payload)

	prevChainHash := zeroHashHex()
	if step > 1 {
		prevChainHash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	}

	pkt := RelayPacket{
		SessionID:     "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Step:          step,
		From:          "0x1111111111111111111111111111111111111111",
		To:            "0x2222222222222222222222222222222222222222",
		Payload:       payload,
		PayloadHash:   payloadHash,
		PrevChainHash: prevChainHash,
		LocalNonce:    nonce,
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
	meta1 := map[string]string{
		"b": "2",
		"a": "1",
	}

	meta2 := map[string]string{
		"a": "1",
		"b": "2",
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
		meta1,
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
		meta2,
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

func TestProcessRelayCheckpointSavedAtStep10(t *testing.T) {
	e, fs, signer := newTestEngine(t, 10)
	pkt := makeValidIncomingPacketWithStep(t, signer, 9, 9)

	resp, err := e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err != nil {
		t.Fatal(err)
	}

	if resp.AcceptedStep != 10 {
		t.Fatalf("expected accepted step 10, got %d", resp.AcceptedStep)
	}

	cp, ok := fs.GetCheckpoint(pkt.SessionID)
	if !ok {
		t.Fatal("checkpoint was not saved")
	}

	if cp.Step != 10 {
		t.Fatalf("expected checkpoint step 10, got %d", cp.Step)
	}

	if cp.ChainHash != resp.NewChainHash {
		t.Fatalf("checkpoint hash mismatch: checkpoint=%s response=%s", cp.ChainHash, resp.NewChainHash)
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

func TestProcessRelayTimestampReject(t *testing.T) {
	e, _, signer := newTestEngine(t, 2)
	pkt := makeValidIncomingPacket(t, signer)

	pkt.TimestampUnix = time.Now().UTC().Add(-1 * time.Hour).Unix()

	_, err := e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err == nil {
		t.Fatal("expected old timestamp rejection")
	}
}

func TestProcessRelayReplayReject(t *testing.T) {
	e, _, signer := newTestEngine(t, 2)
	pkt := makeValidIncomingPacket(t, signer)

	_, err := e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err != nil {
		t.Fatal(err)
	}

	_, err = e.ProcessRelay(context.Background(), ProcessRelayRequest{Packet: pkt})
	if err == nil {
		t.Fatal("expected replay rejection")
	}

}

func TestReplayCacheStoreKey(t *testing.T) {
	_, fs, signer := newTestEngine(t, 2)
	pkt := makeValidIncomingPacket(t, signer)

	packetKey := fmt.Sprintf("%s:%d:%d", normalizeHex(pkt.SessionID), pkt.Step, pkt.LocalNonce)

	if fs.HasProcessedPacket(packetKey) {
		t.Fatal("packet should not be processed yet")
	}

	if err := fs.MarkProcessedPacket(packetKey); err != nil {
		t.Fatal(err)
	}

	if !fs.HasProcessedPacket(packetKey) {
		t.Fatal("replay cache failed")
	}
}
