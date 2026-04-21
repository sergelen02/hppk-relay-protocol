package eth

import (
	"context"
	"time"
)

type ClientConfig struct {
	RPCURL          string
	ChainID         int64
	ContractAddress string
	PrivateKeyHex   string
	FromAddress     string
	ConfirmTimeout  time.Duration
}

type Client struct{}

func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error)
func (c *Client) Ping(ctx context.Context) error
func (c *Client) ChainID(ctx context.Context) (int64, error)
func (c *Client) HasContractCode(ctx context.Context) (bool, error)
func (c *Client) Close() error
