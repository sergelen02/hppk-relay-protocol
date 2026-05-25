package store

import (
	"context"
	"testing"
)

func TestFileStoreSessionRecovery(t *testing.T) {
	fs, err := NewFileStore("/tmp/hppk-relay-store-test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if err := fs.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := fs.SetLastNonce("session-1", 10); err != nil {
		t.Fatal(err)
	}

	if err := fs.SetSessionState(SessionState{
		SessionID:      "session-1",
		LastValidStep: 3,
		LastChainHash: "0xabc123",
	}); err != nil {
		t.Fatal(err)
	}

	st, ok := fs.GetSessionState("session-1")
	if !ok {
		t.Fatal("session state not found")
	}

	if st.LastValidStep != 3 {
		t.Fatalf("expected step 3, got %d", st.LastValidStep)
	}

	if st.LastChainHash != "0xabc123" {
		t.Fatalf("unexpected chain hash: %s", st.LastChainHash)
	}

	if err := fs.SetCheckpoint(SessionCheckpoint{
		SessionID: "session-1",
		Step:      3,
		ChainHash: "0xabc123",
	}); err != nil {
		t.Fatal(err)
	}

	cp, ok := fs.GetCheckpoint("session-1")
	if !ok {
		t.Fatal("checkpoint not found")
	}

	if cp.Step != 3 {
		t.Fatalf("expected checkpoint step 3, got %d", cp.Step)
	}

	t.Log("session recovery store test passed")
}
