package internal
package protocol

import (
	"context"
	"time"

	"github.com/sergelen02/hppk-relay-protocol/agent/internal/client"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/eth"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/hppk"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/logging"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/metrics"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
)

type EngineConfig struct {
	AgentID              string
	MyAddress            string
	ExpectedStep         int
	NextAgentURL         string
	EnablePayloadCompare bool
	MaxClockSkew         time.Duration

	Logger               logging.Logger
	Metrics              *metrics.Metrics
	Store                store.Store
	EthClient            *eth.Client
	HPPKSigner           *hppk.Signer
	RelayClient          *client.RelayClient
}

type Engine struct{}

type InitSessionRequest struct {
	SessionID      string
	PayloadPath    string
	RouteAddresses []string
	Meta           map[string]string
}

func NewEngine(cfg EngineConfig) *Engine
func (e *Engine) InitSessionAndRelay(ctx context.Context, req InitSessionRequest) error