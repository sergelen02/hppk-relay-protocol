package protocol

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

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

	Logger      logging.Logger
	Metrics     *metrics.Metrics
	Store       store.Store
	EthClient   *eth.Client
	HPPKSigner  *hppk.Signer
	RelayClient *client.RelayClient
}

type Engine struct {
	agentID              string
	myAddress            string
	expectedStep         int
	nextAgentURL         string
	enablePayloadCompare bool
	maxClockSkew         time.Duration

	logger      logging.Logger
	metrics     *metrics.Metrics
	store       store.Store
	ethClient   *eth.Client
	hppkSigner  *hppk.Signer
	relayClient *client.RelayClient
}

type RelayPacket struct {
	SessionID     string            `json:"session_id"`
	Step          int               `json:"step"`
	From          string            `json:"from"`
	To            string            `json:"to"`
	Payload       []byte            `json:"payload,omitempty"`
	PayloadHash   string            `json:"payload_hash"`
	PrevChainHash string            `json:"prev_chain_hash"`
	ChainHash     string            `json:"chain_hash"`
	LocalNonce    uint64            `json:"local_nonce"`
	Meta          map[string]string `json:"meta,omitempty"`
	PubKey        []byte            `json:"pub_key,omitempty"`
	Signature     []byte            `json:"signature,omitempty"`
	TimestampUnix int64             `json:"timestamp_unix"`
}

type ProcessRelayRequest struct {
	Packet RelayPacket `json:"packet"`
}

type ProcessRelayResponse struct {
	OK           bool   `json:"ok"`
	SessionID    string `json:"session_id"`
	AcceptedStep int    `json:"accepted_step"`
	NewChainHash string `json:"new_chain_hash,omitempty"`
	Forwarded    bool   `json:"forwarded"`
	Message      string `json:"message"`
}

type InitSessionRequest struct {
	SessionID      string            `json:"session_id"`
	PayloadPath    string            `json:"payload_path"`
	RouteAddresses []string          `json:"route_addresses"`
	Meta           map[string]string `json:"meta"`
}

func NewEngine(cfg EngineConfig) *Engine {
	return &Engine{
		agentID:              cfg.AgentID,
		myAddress:            normalizeHex(cfg.MyAddress),
		expectedStep:         cfg.ExpectedStep,
		nextAgentURL:         strings.TrimSpace(cfg.NextAgentURL),
		enablePayloadCompare: cfg.EnablePayloadCompare,
		maxClockSkew:         cfg.MaxClockSkew,

		logger:      cfg.Logger,
		metrics:     cfg.Metrics,
		store:       cfg.Store,
		ethClient:   cfg.EthClient,
		hppkSigner:  cfg.HPPKSigner,
		relayClient: cfg.RelayClient,
	}
}

func (e *Engine) InitSessionAndRelay(ctx context.Context, req InitSessionRequest) error {
	if strings.TrimSpace(req.SessionID) == "" {
		return errors.New("session_id is required")
	}
	if strings.TrimSpace(req.PayloadPath) == "" {
		return errors.New("payload_path is required")
	}
	if len(req.RouteAddresses) == 0 {
		return errors.New("route_addresses is required")
	}
	if normalizeHex(req.RouteAddresses[0]) != e.myAddress {
		return fmt.Errorf("this agent is not the first route address: first=%s my=%s", req.RouteAddresses[0], e.myAddress)
	}

	payload, err := os.ReadFile(req.PayloadPath)
	if err != nil {
		return fmt.Errorf("read payload file: %w", err)
	}

	now := time.Now().UTC().Unix()
	payloadHash := hashBytesHex(payload)
	initialPrev := zeroHashHex()

	packet := RelayPacket{
		SessionID:     normalizeHex(req.SessionID),
		Step:          1,
		From:          e.myAddress,
		To:            nextHop(req.RouteAddresses, 0),
		Payload:       payload,
		PayloadHash:   payloadHash,
		PrevChainHash: initialPrev,
		LocalNonce:    1,
		Meta:          copyMap(req.Meta),
		TimestampUnix: now,
	}

	newChainHash, sig, pubKey, err := e.signPacket(packet)
	if err != nil {
		return fmt.Errorf("sign initial packet: %w", err)
	}
	packet.ChainHash = newChainHash
	packet.Signature = sig
	packet.PubKey = pubKey

	if err := e.submitOnChain(ctx, packet); err != nil {
		return fmt.Errorf("submit initial packet on chain: %w", err)
	}

	if packet.To != "" && e.relayClient != nil && e.nextAgentURL != "" {
		if err := e.relayClient.Send(ctx, e.nextAgentURL, ProcessRelayRequest{Packet: packet}); err != nil {
			return fmt.Errorf("send initial relay to next agent: %w", err)
		}
	}

	if e.logger != nil {
		e.logger.Info("initial session relayed",
			"session_id", req.SessionID,
			"step", packet.Step,
			"to", packet.To,
		)
	}
	return nil
}

func (e *Engine) ProcessRelay(ctx context.Context, req ProcessRelayRequest) (*ProcessRelayResponse, error) {
	pkt := req.Packet

	if err := e.validateIncomingPacket(pkt); err != nil {
		return nil, err
	}

	if e.enablePayloadCompare {
		computedPayloadHash := hashBytesHex(pkt.Payload)
		if !equalHex(computedPayloadHash, pkt.PayloadHash) {
			return nil, fmt.Errorf("payload hash mismatch: computed=%s packet=%s", computedPayloadHash, pkt.PayloadHash)
		}
	}

	if err := e.verifyPreviousProof(pkt); err != nil {
		return nil, fmt.Errorf("verify previous proof: %w", err)
	}

	nextStep := pkt.Step + 1
	newPacket := RelayPacket{
		SessionID:     normalizeHex(pkt.SessionID),
		Step:          nextStep,
		From:          e.myAddress,
		To:            e.resolveNextHop(pkt),
		Payload:       pkt.Payload,
		PayloadHash:   normalizeHex(pkt.PayloadHash),
		PrevChainHash: normalizeHex(pkt.ChainHash),
		LocalNonce:    pkt.LocalNonce + 1,
		Meta:          copyMap(pkt.Meta),
		TimestampUnix: time.Now().UTC().Unix(),
	}

	newChainHash, sig, pubKey, err := e.signPacket(newPacket)
	if err != nil {
		return nil, fmt.Errorf("sign next packet: %w", err)
	}

	newPacket.ChainHash = newChainHash
	newPacket.Signature = sig
	newPacket.PubKey = pubKey

	if err := e.submitOnChain(ctx, newPacket); err != nil {
		return nil, fmt.Errorf("submit on chain: %w", err)
	}

	forwarded := false
	if newPacket.To != "" && e.nextAgentURL != "" && e.relayClient != nil {
		if err := e.relayClient.Send(ctx, e.nextAgentURL, ProcessRelayRequest{Packet: newPacket}); err != nil {
			return nil, fmt.Errorf("forward to next agent: %w", err)
		}
		forwarded = true
	}

	if e.logger != nil {
		e.logger.Info("relay processed",
			"session_id", pkt.SessionID,
			"incoming_step", pkt.Step,
			"new_step", newPacket.Step,
			"forwarded", forwarded,
		)
	}

	return &ProcessRelayResponse{
		OK:           true,
		SessionID:    pkt.SessionID,
		AcceptedStep: newPacket.Step,
		NewChainHash: newPacket.ChainHash,
		Forwarded:    forwarded,
		Message:      "relay processed successfully",
	}, nil
}

func (e *Engine) validateIncomingPacket(pkt RelayPacket) error {
	if strings.TrimSpace(pkt.SessionID) == "" {
		return errors.New("session_id is required")
	}
	if pkt.Step < 1 {
		return errors.New("step must be >= 1")
	}
	if normalizeHex(pkt.To) != e.myAddress {
		return fmt.Errorf("wrong recipient: packet.to=%s my=%s", pkt.To, e.myAddress)
	}
	if pkt.Step != e.expectedStep-1 {
		return fmt.Errorf("unexpected incoming step: got=%d expected_previous=%d", pkt.Step, e.expectedStep-1)
	}
	if pkt.TimestampUnix == 0 {
		return errors.New("timestamp_unix is required")
	}

	ts := time.Unix(pkt.TimestampUnix, 0).UTC()
	now := time.Now().UTC()
	if ts.Before(now.Add(-e.maxClockSkew)) || ts.After(now.Add(e.maxClockSkew)) {
		return fmt.Errorf("timestamp outside allowed skew: packet=%s now=%s",
			ts.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	if strings.TrimSpace(pkt.PayloadHash) == "" {
		return errors.New("payload_hash is required")
	}
	if strings.TrimSpace(pkt.PrevChainHash) == "" {
		return errors.New("prev_chain_hash is required")
	}
	if strings.TrimSpace(pkt.ChainHash) == "" {
		return errors.New("chain_hash is required")
	}
	if len(pkt.Signature) == 0 {
		return errors.New("signature is required")
	}
	if len(pkt.PubKey) == 0 {
		return errors.New("pub_key is required")
	}
	return nil
}

func (e *Engine) verifyPreviousProof(pkt RelayPacket) error {
	recomputed, err := computeChainHash(
		pkt.SessionID,
		pkt.Step,
		normalizeHex(pkt.From),
		normalizeHex(pkt.To),
		pkt.PayloadHash,
		pkt.PrevChainHash,
		pkt.LocalNonce,
		pkt.TimestampUnix,
		pkt.Meta,
	)
	if err != nil {
		return fmt.Errorf("recompute chain hash: %w", err)
	}

	if !equalHex(recomputed, pkt.ChainHash) {
		return fmt.Errorf("chain hash mismatch: recomputed=%s packet=%s", recomputed, pkt.ChainHash)
	}

	ok, err := e.hppkSigner.Verify(pkt.PubKey, mustDecodeHex(pkt.ChainHash), pkt.Signature)
	if err != nil {
		return fmt.Errorf("hppk verify error: %w", err)
	}
	if !ok {
		return errors.New("hppk verification returned false")
	}

	return nil
}

func (e *Engine) resolveNextHop(pkt RelayPacket) string {
	if e.nextAgentURL == "" {
		return ""
	}
	if pkt.Meta != nil {
		if v := normalizeHex(pkt.Meta["next_address"]); v != "" && v != e.myAddress {
			return v
		}
	}
	return ""
}

func (e *Engine) signPacket(pkt RelayPacket) (chainHashHex string, sig []byte, pubKey []byte, err error) {
	chainHashHex, err = computeChainHash(
		pkt.SessionID,
		pkt.Step,
		normalizeHex(pkt.From),
		normalizeHex(pkt.To),
		pkt.PayloadHash,
		pkt.PrevChainHash,
		pkt.LocalNonce,
		pkt.TimestampUnix,
		pkt.Meta,
	)
	if err != nil {
		return "", nil, nil, fmt.Errorf("compute chain hash: %w", err)
	}

	msg := mustDecodeHex(chainHashHex)

	sig, err = e.hppkSigner.Sign(msg)
	if err != nil {
		return "", nil, nil, fmt.Errorf("hppk sign: %w", err)
	}

	pubKey, err = e.hppkSigner.PublicKeyBytes()
	if err != nil {
		return "", nil, nil, fmt.Errorf("load public key bytes: %w", err)
	}

	return chainHashHex, sig, pubKey, nil
}

func (e *Engine) submitOnChain(ctx context.Context, pkt RelayPacket) error {
	if e.ethClient == nil {
		return errors.New("eth client is nil")
	}

	req := eth.SubmitHopRequest{
		SessionID:     pkt.SessionID,
		Step:          pkt.Step,
		From:          pkt.From,
		To:            pkt.To,
		PayloadHash:   pkt.PayloadHash,
		PrevChainHash: pkt.PrevChainHash,
		ChainHash:     pkt.ChainHash,
		LocalNonce:    pkt.LocalNonce,
		PubKey:        pkt.PubKey,
		Signature:     pkt.Signature,
		TimestampUnix: pkt.TimestampUnix,
		Meta:          pkt.Meta,
	}

	return e.ethClient.SubmitHop(ctx, req)
}

func nextHop(route []string, idx int) string {
	if idx+1 >= len(route) {
		return ""
	}
	return normalizeHex(route[idx+1])
}

func computeChainHash(
	sessionID string,
	step int,
	from string,
	to string,
	payloadHash string,
	prevChainHash string,
	localNonce uint64,
	timestampUnix int64,
	meta map[string]string,
) (string, error) {
	metaHash := hashMetaToBytes32(meta)

	args := abi.Arguments{
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("uint256")},
		{Type: mustABIType("address")},
		{Type: mustABIType("address")},
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("uint256")},
		{Type: mustABIType("uint256")},
		{Type: mustABIType("bytes32")},
	}

	encoded, err := args.Pack(
		common.HexToHash(normalizeHex(sessionID)),
		uint256FromInt(step),
		common.HexToAddress(normalizeHex(from)),
		common.HexToAddress(normalizeHex(to)),
		common.HexToHash(normalizeHex(payloadHash)),
		common.HexToHash(normalizeHex(prevChainHash)),
		uint256FromUint64(localNonce),
		uint256FromInt64(timestampUnix),
		metaHash,
	)
	if err != nil {
		return "", err
	}

	hash := ethcrypto.Keccak256Hash(encoded)
	return hash.Hex(), nil
}

func hashBytesHex(b []byte) string {
	return ethcrypto.Keccak256Hash(b).Hex()
}

func zeroHashHex() string {
	return "0x" + strings.Repeat("0", 64)
}

func equalHex(a, b string) bool {
	return strings.EqualFold(normalizeHex(a), normalizeHex(b))
}

func normalizeHex(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strings.ToLower(s)
	}
	return "0x" + strings.ToLower(s)
}

func mustDecodeHex(s string) []byte {
	s = normalizeHex(s)
	s = strings.TrimPrefix(s, "0x")
	out, err := hex.DecodeString(s)
	if err != nil {
		return []byte(s)
	}
	return out
}

func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
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

func hashMetaToBytes32(meta map[string]string) [32]byte {
	var out [32]byte
	if len(meta) == 0 {
		return out
	}
	hash := ethcrypto.Keccak256Hash([]byte(canonicalMeta(meta)))
	copy(out[:], hash.Bytes())
	return out
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

func mustABIType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return typ
}

func uint256FromInt(v int) interface{} {
	return newBigIntFromString(fmt.Sprintf("%d", v))
}

func uint256FromInt64(v int64) interface{} {
	return newBigIntFromString(fmt.Sprintf("%d", v))
}

func uint256FromUint64(v uint64) interface{} {
	return newBigIntFromString(fmt.Sprintf("%d", v))
}

func newBigIntFromString(s string) interface{} {
	n := new(bigInt)
	n.SetString(s, 10)
	return n.Int
}

// big.Int import를 최소 변경으로 감싸기 위한 래퍼
type bigInt struct {
	Int *big.Int
}

func (b *bigInt) SetString(s string, base int) {
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		n = big.NewInt(0)
	}
	b.Int = n
}
