package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store interface {
	Ping(ctx context.Context) error
	Close() error

	GetLastNonce(sessionID string) (uint64, bool)
	SetLastNonce(sessionID string, nonce uint64) error

	HasProcessedPacket(key string) bool
	MarkProcessedPacket(key string) error

	GetSessionState(sessionID string) (SessionState, bool)
	SetSessionState(state SessionState) error

	GetCheckpoint(sessionID string) (SessionCheckpoint, bool)
	SetCheckpoint(checkpoint SessionCheckpoint) error
}

type SessionState struct {
	SessionID     string    `json:"session_id"`
	LastValidStep uint64    `json:"last_valid_step"`
	LastChainHash string    `json:"last_chain_hash"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type SessionCheckpoint struct {
	SessionID string    `json:"session_id"`
	Step      uint64    `json:"step"`
	ChainHash string    `json:"chain_hash"`
	CreatedAt time.Time `json:"created_at"`
}

type FileStore struct {
	mu   sync.RWMutex
	path string
	data *stateFile
}

type stateFile struct {
	UpdatedAt          time.Time                    `json:"updated_at"`
	LastNonceBySession map[string]uint64            `json:"last_nonce_by_session"`
	ProcessedPackets   map[string]bool              `json:"processed_packets"`
	SessionStates      map[string]SessionState      `json:"session_states"`
	Checkpoints        map[string]SessionCheckpoint `json:"checkpoints"`
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("store path is required")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create store dir: %w", err)
	}

	fs := &FileStore{
		path: path,
		data: newStateFile(),
	}

	if err := fs.load(); err != nil {
		return nil, err
	}

	return fs, nil
}

func newStateFile() *stateFile {
	return &stateFile{
		UpdatedAt:          time.Now().UTC(),
		LastNonceBySession: map[string]uint64{},
		ProcessedPackets:   map[string]bool{},
		SessionStates:      map[string]SessionState{},
		Checkpoints:        map[string]SessionCheckpoint{},
	}
}

func (f *FileStore) Ping(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.data == nil {
		return errors.New("store data is nil")
	}
	return nil
}

func (f *FileStore) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saveLocked()
}

func (f *FileStore) GetLastNonce(sessionID string) (uint64, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.data == nil {
		return 0, false
	}
	v, ok := f.data.LastNonceBySession[sessionID]
	return v, ok
}

func (f *FileStore) SetLastNonce(sessionID string, nonce uint64) error {
	if sessionID == "" {
		return errors.New("sessionID is required")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.data.LastNonceBySession[sessionID] = nonce
	f.data.UpdatedAt = time.Now().UTC()
	return f.saveLocked()
}

func (f *FileStore) HasProcessedPacket(key string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if key == "" || f.data == nil {
		return false
	}
	return f.data.ProcessedPackets[key]
}

func (f *FileStore) MarkProcessedPacket(key string) error {
	if key == "" {
		return errors.New("processed packet key is required")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.data.ProcessedPackets[key] = true
	f.data.UpdatedAt = time.Now().UTC()
	return f.saveLocked()
}

func (f *FileStore) GetSessionState(sessionID string) (SessionState, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if sessionID == "" || f.data == nil {
		return SessionState{}, false
	}

	st, ok := f.data.SessionStates[sessionID]
	return st, ok
}

func (f *FileStore) SetSessionState(state SessionState) error {
	if state.SessionID == "" {
		return errors.New("sessionID is required")
	}
	if state.LastChainHash == "" {
		return errors.New("lastChainHash is required")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	state.UpdatedAt = time.Now().UTC()
	f.data.SessionStates[state.SessionID] = state
	f.data.UpdatedAt = time.Now().UTC()
	return f.saveLocked()
}

func (f *FileStore) GetCheckpoint(sessionID string) (SessionCheckpoint, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if sessionID == "" || f.data == nil {
		return SessionCheckpoint{}, false
	}

	cp, ok := f.data.Checkpoints[sessionID]
	return cp, ok
}

func (f *FileStore) SetCheckpoint(checkpoint SessionCheckpoint) error {
	if checkpoint.SessionID == "" {
		return errors.New("sessionID is required")
	}
	if checkpoint.ChainHash == "" {
		return errors.New("checkpoint chainHash is required")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	checkpoint.CreatedAt = time.Now().UTC()
	f.data.Checkpoints[checkpoint.SessionID] = checkpoint
	f.data.UpdatedAt = time.Now().UTC()
	return f.saveLocked()
}

func (f *FileStore) load() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	b, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return f.saveLocked()
		}
		return fmt.Errorf("read store file: %w", err)
	}

	if len(b) == 0 {
		return f.saveLocked()
	}

	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("unmarshal store file: %w", err)
	}

	normalizeStateFile(&st)
	f.data = &st
	return nil
}

func normalizeStateFile(st *stateFile) {
	if st.LastNonceBySession == nil {
		st.LastNonceBySession = map[string]uint64{}
	}
	if st.ProcessedPackets == nil {
		st.ProcessedPackets = map[string]bool{}
	}
	if st.SessionStates == nil {
		st.SessionStates = map[string]SessionState{}
	}
	if st.Checkpoints == nil {
		st.Checkpoints = map[string]SessionCheckpoint{}
	}
	if st.UpdatedAt.IsZero() {
		st.UpdatedAt = time.Now().UTC()
	}
}

func (f *FileStore) saveLocked() error {
	if f.data == nil {
		return errors.New("store data is nil")
	}

	b, err := json.MarshalIndent(f.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal store data: %w", err)
	}

	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("write temp store file: %w", err)
	}

	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("replace store file: %w", err)
	}

	return nil
}
