package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Go map의 삽입 순서가 서명 대상 메타데이터에 영향을 주지 않는지 검증한다.
func TestCanonicalMetaStableOrdering(t *testing.T) {
	metaA := map[string]string{
		"zeta":   "last",
		"alpha":  "first",
		"middle": "value",
	}
	metaB := map[string]string{
		"middle": "value",
		"zeta":   "last",
		"alpha":  "first",
	}

	const want = "alpha=first,middle=value,zeta=last"

	if got := canonicalMeta(metaA); got != want {
		t.Fatalf("canonicalMeta(metaA) = %q, want %q", got, want)
	}
	if got := canonicalMeta(metaB); got != want {
		t.Fatalf("canonicalMeta(metaB) = %q, want %q", got, want)
	}
}

// 동일한 Meta는 삽입 순서와 무관하게 같은 metaHash를 가져야 한다.
func TestMetaDigestIndependentOfMapInsertionOrder(t *testing.T) {
	metaA := map[string]string{"b": "2", "a": "1"}
	metaB := map[string]string{"a": "1", "b": "2"}

	gotA := hashMetaToBytes32(metaA)
	gotB := hashMetaToBytes32(metaB)

	if gotA != gotB {
		t.Fatalf("metadata digest depends on insertion order: %x != %x", gotA, gotB)
	}

	if got := hashMetaToBytes32(nil); got != ([32]byte{}) {
		t.Fatalf("empty metadata digest = %x, want all zero bytes", got)
	}
}

// chainHash에 포함되는 값이 바뀌면 HPPK 서명 입력도 반드시 바뀌어야 한다.
func TestChainHashDigestChangesWhenCommittedFieldsChange(t *testing.T) {
	meta := map[string]string{
		"next_address": "0x3333333333333333333333333333333333333333",
	}

	base, err := computeChainHash(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		1,
		"0x1111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222",
		"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		zeroHashHex(),
		1,
		1700000000,
		meta,
	)
	if err != nil {
		t.Fatalf("compute base chain hash: %v", err)
	}

	changed, err := computeChainHash(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		1,
		"0x1111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222",
		"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		zeroHashHex(),
		1,
		1700000000,
		meta,
	)
	if err != nil {
		t.Fatalf("compute changed chain hash: %v", err)
	}

	if base == changed {
		t.Fatal("chain hash did not change after payload digest changed")
	}
}

// HTTP JSON 전송 시 []byte 필드가 Base64 처리된 후 원래 바이트로 복원되는지 검증한다.
func TestRelayPacketJSONEncodingRoundTrip(t *testing.T) {
	want := RelayPacket{
		SessionID:     "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Step:          1,
		From:          "0x1111111111111111111111111111111111111111",
		To:            "0x2222222222222222222222222222222222222222",
		Payload:       []byte("canonical relay payload"),
		PayloadHash:   "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PrevChainHash: zeroHashHex(),
		ChainHash:     "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		LocalNonce:    7,
		Meta:          map[string]string{"a": "1", "b": "2"},
		PubKey:        []byte(`{"key":"canonical"}`),
		Signature:     []byte(`{"signature":"valid"}`),
		TimestampUnix: 1700000000,
	}

	wire, err := json.Marshal(ProcessRelayRequest{Packet: want})
	if err != nil {
		t.Fatalf("marshal relay request: %v", err)
	}

	var got ProcessRelayRequest
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal relay request: %v", err)
	}

	if got.Packet.SessionID != want.SessionID ||
		got.Packet.Step != want.Step ||
		got.Packet.PayloadHash != want.PayloadHash ||
		got.Packet.ChainHash != want.ChainHash ||
		got.Packet.LocalNonce != want.LocalNonce ||
		got.Packet.TimestampUnix != want.TimestampUnix {
		t.Fatalf("relay packet scalar fields changed: got=%+v", got.Packet)
	}

	if !bytes.Equal(got.Packet.Payload, want.Payload) ||
		!bytes.Equal(got.Packet.PubKey, want.PubKey) ||
		!bytes.Equal(got.Packet.Signature, want.Signature) {
		t.Fatal("relay packet byte field changed during JSON round trip")
	}

	if canonicalMeta(got.Packet.Meta) != canonicalMeta(want.Meta) {
		t.Fatalf(
			"metadata changed during JSON round trip: got=%q want=%q",
			canonicalMeta(got.Packet.Meta),
			canonicalMeta(want.Meta),
		)
	}
}
