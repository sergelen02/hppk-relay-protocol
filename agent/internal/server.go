package internal
package server

import (
	"net/http"
	"time"

	"github.com/sergelen02/hppk-relay-protocol/agent/internal/logging"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/metrics"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/protocol"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
)

type Config struct {
	Logger             logging.Logger
	Metrics            *metrics.Metrics
	Store              store.Store
	ProtocolEngine     *protocol.Engine
	ReadTimeout        time.Duration
	ReadHeaderTimeout  time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
}

type Server struct{}

func New(cfg Config) (*Server, error)
func (s *Server) Router() http.Handler