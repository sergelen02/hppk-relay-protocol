package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AgentID        string
	LogLevel       string
	HTTPListenAddr string

	RPCURL           string
	ChainID          int64
	ContractAddress  string
	EthAddress       string
	EthPrivateKey    string
	TxConfirmTimeout time.Duration

	HPPKPublicKeyPath string
	HPPKSecretKeyPath string
	HPPKAlgorithm     string

	StateFile string

	ExpectedStep         int
	NextAgentURL         string
	EnablePayloadCompare bool
	MaxClockSkew         time.Duration

	NextRelayTimeout       time.Duration
	NextRelayMaxRetries    int
	NextRelayRetryInterval time.Duration

	AutoInitSession bool
	InitSessionID   string
	InitPayloadPath string
	InitMeta        map[string]string
	RouteAddresses  []string
}

func Load() (*Config, error) {
	cfg := &Config{
		AgentID:        getEnv("AGENT_ID", ""),
		LogLevel:       getEnv("LOG_LEVEL", "info"),
		HTTPListenAddr: getEnv("HTTP_LISTEN_ADDR", ":8080"),

		RPCURL:           getEnv("RPC_URL", ""),
		ChainID:          getEnvInt64("CHAIN_ID", 1337),
		ContractAddress:  getEnv("CONTRACT_ADDRESS", ""),
		EthAddress:       normalizeHex(getEnv("ETH_ADDRESS", "")),
		EthPrivateKey:    normalizeHex(getEnv("ETH_PRIVATE_KEY", "")),
		TxConfirmTimeout: getEnvDuration("TX_CONFIRM_TIMEOUT", 60*time.Second),

		HPPKPublicKeyPath: getEnv("HPPK_PUBLIC_KEY_PATH", ""),
		HPPKSecretKeyPath: getEnv("HPPK_SECRET_KEY_PATH", ""),
		HPPKAlgorithm:     getEnv("HPPK_ALGORITHM", "hppk"),

		StateFile: getEnv("STATE_FILE", "./data/agent-state.json"),

		ExpectedStep:         getEnvInt("EXPECTED_STEP", 1),
		NextAgentURL:         strings.TrimSpace(getEnv("NEXT_AGENT_URL", "")),
		EnablePayloadCompare: getEnvBool("ENABLE_PAYLOAD_COMPARE", true),
		MaxClockSkew:         getEnvDuration("MAX_CLOCK_SKEW", 2*time.Minute),

		NextRelayTimeout:       getEnvDuration("NEXT_RELAY_TIMEOUT", 10*time.Second),
		NextRelayMaxRetries:    getEnvInt("NEXT_RELAY_MAX_RETRIES", 3),
		NextRelayRetryInterval: getEnvDuration("NEXT_RELAY_RETRY_INTERVAL", 2*time.Second),

		AutoInitSession: getEnvBool("AUTO_INIT_SESSION", false),
		InitSessionID:   getEnv("INIT_SESSION_ID", ""),
		InitPayloadPath: getEnv("INIT_PAYLOAD_PATH", ""),
		InitMeta:        parseKVCSV(getEnv("INIT_META", "")),
		RouteAddresses:  parseCSV(getEnv("ROUTE_ADDRESSES", "")),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	var errs []string

	if c.AgentID == "" {
		errs = append(errs, "AGENT_ID is required")
	}
	if c.RPCURL == "" {
		errs = append(errs, "RPC_URL is required")
	}
	if c.ContractAddress == "" {
		errs = append(errs, "CONTRACT_ADDRESS is required")
	}
	if c.EthAddress == "" {
		errs = append(errs, "ETH_ADDRESS is required")
	}
	if c.EthPrivateKey == "" {
		errs = append(errs, "ETH_PRIVATE_KEY is required")
	}
	if c.HPPKPublicKeyPath == "" {
		errs = append(errs, "HPPK_PUBLIC_KEY_PATH is required")
	}
	if c.HPPKSecretKeyPath == "" {
		errs = append(errs, "HPPK_SECRET_KEY_PATH is required")
	}
	if c.ExpectedStep < 1 {
		errs = append(errs, "EXPECTED_STEP must be >= 1")
	}
	if c.AutoInitSession {
		if c.InitSessionID == "" {
			errs = append(errs, "INIT_SESSION_ID is required when AUTO_INIT_SESSION=true")
		}
		if c.InitPayloadPath == "" {
			errs = append(errs, "INIT_PAYLOAD_PATH is required when AUTO_INIT_SESSION=true")
		}
		if len(c.RouteAddresses) == 0 {
			errs = append(errs, "ROUTE_ADDRESSES is required when AUTO_INIT_SESSION=true")
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func getEnv(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func getEnvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getEnvInt64(key string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func getEnvBool(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func parseCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		x := strings.TrimSpace(p)
		if x != "" {
			out = append(out, normalizeHex(x))
		}
	}
	return out
}

func parseKVCSV(s string) map[string]string {
	out := map[string]string{}
	if strings.TrimSpace(s) == "" {
		return out
	}
	pairs := strings.Split(s, ",")
	for _, p := range pairs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k != "" {
			out[k] = v
		}
	}
	return out
}

func normalizeHex(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s
	}
	// 주소/해시/키 모두 통일을 위해 hex prefix 추가
	if looksHexLike(s) {
		return "0x" + s
	}
	return s
}

func looksHexLike(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' ||
			r >= 'a' && r <= 'f' ||
			r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func (c *Config) String() string {
	return fmt.Sprintf(
		"agent_id=%s http_listen_addr=%s eth_address=%s contract_address=%s rpc_url=%s expected_step=%d next_agent_url=%s",
		c.AgentID,
		c.HTTPListenAddr,
		c.EthAddress,
		c.ContractAddress,
		c.RPCURL,
		c.ExpectedStep,
		c.NextAgentURL,
	)
}
