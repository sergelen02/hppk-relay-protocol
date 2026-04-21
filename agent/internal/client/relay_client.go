package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sergelen02/hppk-relay-protocol/agent/internal/logging"
)

type Config struct {
	Timeout       time.Duration
	MaxRetries    int
	RetryInterval time.Duration
	Logger        logging.Logger
}

type RelayClient struct {
	httpClient    *http.Client
	maxRetries    int
	retryInterval time.Duration
	logger        logging.Logger
}

func NewRelayClient(cfg Config) *RelayClient {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxRetries := cfg.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	retryInterval := cfg.RetryInterval
	if retryInterval <= 0 {
		retryInterval = 2 * time.Second
	}

	return &RelayClient{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		maxRetries:    maxRetries,
		retryInterval: retryInterval,
		logger:        cfg.Logger,
	}
}

func (c *RelayClient) Send(ctx context.Context, url string, body any) error {
	if c == nil || c.httpClient == nil {
		return errors.New("relay client is nil")
	}
	url = strings.TrimSpace(url)
	if url == "" {
		return errors.New("relay url is empty")
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal relay body: %w", err)
	}

	var lastErr error
	attempts := c.maxRetries + 1

	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("build relay request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d/%d failed: %w", i+1, attempts, err)
			c.logWarn("relay http request failed", "url", url, "attempt", i+1, "err", err)
			if i < attempts-1 {
				if err := sleepContext(ctx, c.retryInterval); err != nil {
					return err
				}
				continue
			}
			break
		}

		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.logInfo("relay sent successfully",
				"url", url,
				"attempt", i+1,
				"status_code", resp.StatusCode,
			)
			return nil
		}

		lastErr = fmt.Errorf("attempt %d/%d got non-2xx status=%d body=%s", i+1, attempts, resp.StatusCode, string(respBody))
		c.logWarn("relay got non-2xx response",
			"url", url,
			"attempt", i+1,
			"status_code", resp.StatusCode,
			"body", string(respBody),
		)

		if i < attempts-1 {
			if err := sleepContext(ctx, c.retryInterval); err != nil {
				return err
			}
		}
	}

	if lastErr == nil {
		lastErr = errors.New("relay send failed with unknown error")
	}
	return lastErr
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *RelayClient) logInfo(msg string, args ...any) {
	if c != nil && c.logger != nil {
		c.logger.Info(msg, args...)
	}
}

func (c *RelayClient) logWarn(msg string, args ...any) {
	if c != nil && c.logger != nil {
		c.logger.Warn(msg, args...)
	}
}
