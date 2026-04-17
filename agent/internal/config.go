package internal
package config

import "time"

type Config struct {
	AgentID               string
	LogLevel              string
	HTTPListenAddr        string

	RPCURL                string
	ChainID               int64
	ContractAddress       string
	EthAddress            string
	EthPrivateKey         string
	TxConfirmTimeout      time.Duration

	HPPKPublicKeyPath     string
	HPPKSecretKeyPath     string
	HPPKAlgorithm         string

	StateFile             string

	ExpectedStep          int
	NextAgentURL          string
	EnablePayloadCompare  bool
	MaxClockSkew          time.Duration

	NextRelayTimeout      time.Duration
	NextRelayMaxRetries   int
	NextRelayRetryInterval time.Duration

	AutoInitSession       bool
	InitSessionID         string
	InitPayloadPath       string
	InitMeta              map[string]string
	RouteAddresses        []string
}

func Load() (*Config, error)