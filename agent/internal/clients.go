package client

import (
	"time"

	"github.com/sergelen02/hppk-relay-protocol/agent/internal/logging"
)

type Config struct {
	Timeout       time.Duration
	MaxRetries    int
	RetryInterval time.Duration
	Logger        logging.Logger
}

type RelayClient struct{}

func NewRelayClient(cfg Config) *RelayClient
