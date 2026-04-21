package eth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
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
	if strings.TrimSpace(cfg.PrivateKeyHex) == "" {
		return nil, errors.New("PrivateKeyHex is required")
	}
	if cfg.ConfirmTimeout <= 0 {
		cfg.ConfirmTimeout = 60 * time.Second
	}

	ec, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("dial ethereum rpc: %w", err)
	}

	return &Client{
		rpcURL:            cfg.RPCURL,
		configuredChainID: cfg.ChainID,
		contractAddress:   common.HexToAddress(cfg.ContractAddress),
		privateKeyHex:     normalizeHex(cfg.PrivateKeyHex),
		fromAddress:       common.HexToAddress(cfg.FromAddress),
		confirmTimeout:    cfg.ConfirmTimeout,
		ec:                ec,
	}, nil
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

func (c *Client) Close() error {
	if c == nil || c.ec == nil {
		return nil
	}
	c.ec.Close()
	return nil
}

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
	if len(req.PubKey) == 0 {
		return errors.New("submit hop: pubkey is required")
	}
	if len(req.Signature) == 0 {
		return errors.New("submit hop: signature is required")
	}

	ok, err := c.HasContractCode(ctx)
	if err != nil {
		return fmt.Errorf("submit hop: contract code check failed: %w", err)
	}
	if !ok {
		return errors.New("submit hop: contract code not found")
	}

	privateKey, err := c.loadPrivateKey()
	if err != nil {
		return fmt.Errorf("submit hop: load private key: %w", err)
	}

	chainID, err := c.ec.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("submit hop: get chain id: %w", err)
	}

	nonce, err := c.ec.PendingNonceAt(ctx, c.fromAddress)
	if err != nil {
		return fmt.Errorf("submit hop: get nonce: %w", err)
	}

	gasPrice, err := c.ec.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("submit hop: suggest gas price: %w", err)
	}

	metaHash := hashMetaToBytes32(req.Meta)

	contractABI, err := abi.JSON(strings.NewReader(submitHopABI))
	if err != nil {
		return fmt.Errorf("submit hop: parse abi: %w", err)
	}

	data, err := contractABI.Pack(
		"submitHop",
		hexToBytes32(req.SessionID),
		big.NewInt(int64(req.Step)),
		common.HexToAddress(req.From),
		common.HexToAddress(req.To),
		hexToBytes32(req.PayloadHash),
		hexToBytes32(req.PrevChainHash),
		hexToBytes32(req.ChainHash),
		new(big.Int).SetUint64(req.LocalNonce),
		req.PubKey,
		req.Signature,
		new(big.Int).SetInt64(req.TimestampUnix),
		metaHash,
	)
	if err != nil {
		return fmt.Errorf("submit hop: abi pack: %w", err)
	}

	msg := ethereum.CallMsg{
		From:     c.fromAddress,
		To:       &c.contractAddress,
		GasPrice: gasPrice,
		Value:    big.NewInt(0),
		Data:     data,
	}

	gasLimit, err := c.ec.EstimateGas(ctx, msg)
	if err != nil {
		gasLimit = 1_500_000
	}

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &c.contractAddress,
		Value:    big.NewInt(0),
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})

	signer := types.LatestSignerForChainID(chainID)
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return fmt.Errorf("submit hop: sign tx: %w", err)
	}

	if err := c.ec.SendTransaction(ctx, signedTx); err != nil {
		return fmt.Errorf("submit hop: send tx: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, c.confirmTimeout)
	defer cancel()

	receipt, err := waitReceipt(waitCtx, c.ec, signedTx.Hash())
	if err != nil {
		return fmt.Errorf("submit hop: wait receipt: %w", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("submit hop: tx reverted tx_hash=%s", signedTx.Hash().Hex())
	}

	return nil
}

func (c *Client) loadPrivateKey() (*ecdsa.PrivateKey, error) {
	keyHex := strings.TrimPrefix(c.privateKeyHex, "0x")
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func waitReceipt(ctx context.Context, ec *ethclient.Client, txHash common.Hash) (*types.Receipt, error) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		receipt, err := ec.TransactionReceipt(ctx, txHash)
		if err == nil && receipt != nil {
			return receipt, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func normalizeHex(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s
	}
	return "0x" + s
}

func hexToBytes32(s string) [32]byte {
	var out [32]byte
	h := common.HexToHash(normalizeHex(s))
	copy(out[:], h.Bytes())
	return out
}

func hashMetaToBytes32(meta map[string]string) [32]byte {
	var out [32]byte
	if len(meta) == 0 {
		return out
	}

	hash := crypto.Keccak256Hash([]byte(canonicalMeta(meta)))
	copy(out[:], hash.Bytes())
	return out
}

func canonicalMeta(meta map[string]string) string {
	if len(meta) == 0 {
		return ""
	}

	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sortStrings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(meta[k])
	}
	return b.String()
}

func sortStrings(a []string) {
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			if a[j] < a[i] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}

const submitHopABI = `[
  {
    "inputs": [
      { "internalType": "bytes32", "name": "sessionId", "type": "bytes32" },
      { "internalType": "uint256", "name": "step", "type": "uint256" },
      { "internalType": "address", "name": "from", "type": "address" },
      { "internalType": "address", "name": "to", "type": "address" },
      { "internalType": "bytes32", "name": "payloadHash", "type": "bytes32" },
      { "internalType": "bytes32", "name": "prevChainHash", "type": "bytes32" },
      { "internalType": "bytes32", "name": "chainHash", "type": "bytes32" },
      { "internalType": "uint256", "name": "localNonce", "type": "uint256" },
      { "internalType": "bytes", "name": "pubKey", "type": "bytes" },
      { "internalType": "bytes", "name": "signature", "type": "bytes" },
      { "internalType": "uint256", "name": "timestampUnix", "type": "uint256" },
      { "internalType": "bytes32", "name": "metaHash", "type": "bytes32" }
    ],
    "name": "submitHop",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]`
