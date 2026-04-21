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
}

type FileStore struct {
	mu   sync.RWMutex
	path string
	data *stateFile
}

type stateFile struct {
	UpdatedAt          time.Time         `json:"updated_at"`
	LastNonceBySession map[string]uint64 `json:"last_nonce_by_session"`
	ProcessedPackets   map[string]bool   `json:"processed_packets"`
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
		data: &stateFile{
			UpdatedAt:          time.Now().UTC(),
			LastNonceBySession: map[string]uint64{},
			ProcessedPackets:   map[string]bool{},
		},
	}

	if err := fs.load(); err != nil {
		return nil, err
	}

	return fs, nil
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

	if st.LastNonceBySession == nil {
		st.LastNonceBySession = map[string]uint64{}
	}
	if st.ProcessedPackets == nil {
		st.ProcessedPackets = map[string]bool{}
	}

	f.data = &st
	return nil
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
