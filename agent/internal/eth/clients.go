package eth

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type ClientConfig struct {
	RPCURL          string
	ChainID         int64
	ContractAddress string
	PrivateKeyHex   string
	FromAddress     string
	ConfirmTimeout  time.Duration
}

type SubmitHopRequest struct {
	SessionID     string
	Step          int
	From          string
	To            string
	PayloadHash   string
	PrevChainHash string
	ChainHash     string
	LocalNonce    uint64
	PubKey        []byte
	Signature     []byte
	TimestampUnix int64
	Meta          map[string]string
}

type Client struct {
	rpcURL            string
	configuredChainID int64
	contractAddress   common.Address
	privateKeyHex     string
	fromAddress       common.Address
	confirmTimeout    time.Duration

	ec *ethclient.Client
}

func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return nil, errors.New("RPCURL is required")
	}
	if strings.TrimSpace(cfg.ContractAddress) == "" {
		return nil, errors.New("ContractAddress is required")
	}
	if strings.TrimSpace(cfg.FromAddress) == "" {
		return nil, errors.New("FromAddress is required")
	}
	if cfg.ConfirmTimeout <= 0 {
		cfg.ConfirmTimeout = 60 * time.Second
	}

	ec, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("dial ethereum rpc: %w", err)
	}

	c := &Client{
		rpcURL:            cfg.RPCURL,
		configuredChainID: cfg.ChainID,
		contractAddress:   common.HexToAddress(cfg.ContractAddress),
		privateKeyHex:     strings.TrimSpace(cfg.PrivateKeyHex),
		fromAddress:       common.HexToAddress(cfg.FromAddress),
		confirmTimeout:    cfg.ConfirmTimeout,
		ec:                ec,
	}
	return c, nil
}

func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.ec == nil {
		return errors.New("ethereum client is nil")
	}

	_, err := c.ec.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("rpc ping failed: %w", err)
	}
	return nil
}

func (c *Client) ChainID(ctx context.Context) (int64, error) {
	if c == nil || c.ec == nil {
		return 0, errors.New("ethereum client is nil")
	}

	id, err := c.ec.ChainID(ctx)
	if err != nil {
		return 0, fmt.Errorf("get chain id: %w", err)
	}
	return id.Int64(), nil
}

func (c *Client) HasContractCode(ctx context.Context) (bool, error) {
	if c == nil || c.ec == nil {
		return false, errors.New("ethereum client is nil")
	}

	code, err := c.ec.CodeAt(ctx, c.contractAddress, nil)
	if err != nil {
		return false, fmt.Errorf("get contract code: %w", err)
	}
	return len(code) > 0, nil
}

func (c *Client) NonceAt(ctx context.Context) (uint64, error) {
	if c == nil || c.ec == nil {
		return 0, errors.New("ethereum client is nil")
	}
	nonce, err := c.ec.PendingNonceAt(ctx, c.fromAddress)
	if err != nil {
		return 0, fmt.Errorf("get pending nonce: %w", err)
	}
	return nonce, nil
}

func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	if c == nil || c.ec == nil {
		return nil, errors.New("ethereum client is nil")
	}
	price, err := c.ec.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("suggest gas price: %w", err)
	}
	return price, nil
}

func (c *Client) LatestHeader(ctx context.Context) (*gethtypes.Header, error) {
	if c == nil || c.ec == nil {
		return nil, errors.New("ethereum client is nil")
	}
	h, err := c.ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get latest header: %w", err)
	}
	return h, nil
}

// SubmitHop은 현재 placeholder다.
// 지금 단계에서 하는 일:
//  1. 입력 유효성 검증
//  2. 컨트랙트 코드 존재 재확인
//  3. tx 전송 자리에 해당하는 지점까지 골격 제공
//
// 실제 컨트랙트 ABI가 정해지면 이 함수 안에서:
//   - abi.JSON(...)
//
// /  - Pack("submitHop", ...)
// /  - types.NewTx(...)
// /  - crypto.HexToECDSA(...)
// /  - types.SignTx(...)
// /  - SendTransaction(...)
// /  - receipt polling
// 로 완성하면 된다.
func (c *Client) SubmitHop(ctx context.Context, req SubmitHopRequest) error {
	if c == nil || c.ec == nil {
		return errors.New("ethereum client is nil")
	}
	if strings.TrimSpace(req.SessionID) == "" {
		return errors.New("submit hop: session id is required")
	}
	if req.Step < 1 {
		return errors.New("submit hop: step must be >= 1")
	}
	if strings.TrimSpace(req.From) == "" {
		return errors.New("submit hop: from is required")
	}
	if strings.TrimSpace(req.PayloadHash) == "" {
		return errors.New("submit hop: payload hash is required")
	}
	if strings.TrimSpace(req.ChainHash) == "" {
		return errors.New("submit hop: chain hash is required")
	}
	if len(req.Signature) == 0 {
		return errors.New("submit hop: signature is required")
	}
	if len(req.PubKey) == 0 {
		return errors.New("submit hop: pubkey is required")
	}

	ok, err := c.HasContractCode(ctx)
	if err != nil {
		return fmt.Errorf("submit hop: contract code check failed: %w", err)
	}
	if !ok {
		return errors.New("submit hop: contract code not found")
	}

	// 현재는 placeholder.
	// 여기까지 왔다는 것은 "온체인 제출 직전까지의 입력 형식"이 맞다는 뜻이다.
	// 실제 배포 단계에서는 ABI 인코딩 + signed tx 전송으로 교체해야 한다.
	return nil
}

func (c *Client) Close() error {
	if c == nil || c.ec == nil {
		return nil
	}
	c.ec.Close()
	return nil
}
