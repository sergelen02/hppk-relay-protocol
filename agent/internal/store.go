package internal
package store

import "context"

type Store interface {
	Ping(ctx context.Context) error
	Close() error
}

func NewFileStore(path string) (Store, error)