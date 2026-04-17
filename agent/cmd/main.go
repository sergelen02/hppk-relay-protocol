package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sergelen02/hppk-relay-protocol/agent/internal/client"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/config"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/eth"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/hppk"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/logging"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/metrics"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/protocol"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/server"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "agent terminated with error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// ---------------------------------------------------------------------
	// 1) 설정 로드
	// ---------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// ---------------------------------------------------------------------
	// 2) 로거 초기화
	// ---------------------------------------------------------------------
	logger, err := logging.New(cfg.LogLevel, cfg.AgentID)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}

	logger.Info("starting relay agent",
		"agent_id", cfg.AgentID,
		"http_addr", cfg.HTTPListenAddr,
		"eth_address", cfg.EthAddress,
		"rpc_url", cfg.RPCURL,
		"contract_address", cfg.ContractAddress,
	)

	// ---------------------------------------------------------------------
	// 3) 상태 저장소 초기화
	// ---------------------------------------------------------------------
	st, err := store.NewFileStore(cfg.StateFile)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}
	defer func() {
		if cerr := st.Close(); cerr != nil {
			logger.Error("failed to close store", "err", cerr)
		}
	}()

	// ---------------------------------------------------------------------
	// 4) 메트릭 초기화
	// ---------------------------------------------------------------------
	m := metrics.New()

	// ---------------------------------------------------------------------
	// 5) Ethereum 클라이언트 초기화
	// ---------------------------------------------------------------------
	ethClient, err := eth.NewClient(ctx, eth.ClientConfig{
		RPCURL:          cfg.RPCURL,
		ChainID:         cfg.ChainID,
		ContractAddress: cfg.ContractAddress,
		PrivateKeyHex:   cfg.EthPrivateKey,
		FromAddress:     cfg.EthAddress,
		ConfirmTimeout:  cfg.TxConfirmTimeout,
	})
	if err != nil {
		return fmt.Errorf("init ethereum client: %w", err)
	}
	defer func() {
		if cerr := ethClient.Close(); cerr != nil {
			logger.Error("failed to close ethereum client", "err", cerr)
		}
	}()

	// ---------------------------------------------------------------------
	// 6) HPPK signer / verifier 초기화
	// ---------------------------------------------------------------------
	hppkSigner, err := hppk.NewSigner(hppk.SignerConfig{
		PublicKeyPath:  cfg.HPPKPublicKeyPath,
		SecretKeyPath:  cfg.HPPKSecretKeyPath,
		AlgorithmName:  cfg.HPPKAlgorithm,
		EnableVerify:   true,
		StrictKeyCheck: true,
	})
	if err != nil {
		return fmt.Errorf("init hppk signer: %w", err)
	}

	// ---------------------------------------------------------------------
	// 7) 다음 agent로 전송하는 HTTP 클라이언트
	// ---------------------------------------------------------------------
	nextClient := client.NewRelayClient(client.Config{
		Timeout:       cfg.NextRelayTimeout,
		MaxRetries:    cfg.NextRelayMaxRetries,
		RetryInterval: cfg.NextRelayRetryInterval,
		Logger:        logger,
	})

	// ---------------------------------------------------------------------
	// 8) 프로토콜 엔진 초기화
	// ---------------------------------------------------------------------
	engine := protocol.NewEngine(protocol.EngineConfig{
		AgentID:              cfg.AgentID,
		MyAddress:            cfg.EthAddress,
		ExpectedStep:         cfg.ExpectedStep,
		NextAgentURL:         cfg.NextAgentURL,
		EnablePayloadCompare: cfg.EnablePayloadCompare,
		MaxClockSkew:         cfg.MaxClockSkew,
		Logger:               logger,
		Metrics:              m,
		Store:                st,
		EthClient:            ethClient,
		HPPKSigner:           hppkSigner,
		RelayClient:          nextClient,
	})

	// ---------------------------------------------------------------------
	// 9) HTTP 서버 핸들러 구성
	// ---------------------------------------------------------------------
	srv, err := server.New(server.Config{
		Logger:            logger,
		Metrics:           m,
		Store:             st,
		ProtocolEngine:    engine,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("init server: %w", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.HTTPListenAddr,
		Handler:           srv.Router(),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// ---------------------------------------------------------------------
	// 10) 부팅 전 점검
	// ---------------------------------------------------------------------
	if err := bootChecks(ctx, logger, ethClient, hppkSigner, st); err != nil {
		return fmt.Errorf("boot checks failed: %w", err)
	}

	// ---------------------------------------------------------------------
	// 11) HTTP 서버 시작
	// ---------------------------------------------------------------------
	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", cfg.HTTPListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// ---------------------------------------------------------------------
	// 12) 초기 세션 시작 옵션 (선택)
	//     U1 같은 시작 에이전트에서만 사용 가능
	// ---------------------------------------------------------------------
	if cfg.AutoInitSession {
		go func() {
			time.Sleep(2 * time.Second)

			logger.Info("auto init session enabled")

			initReq := protocol.InitSessionRequest{
				SessionID:      cfg.InitSessionID,
				PayloadPath:    cfg.InitPayloadPath,
				RouteAddresses: cfg.RouteAddresses,
				Meta:           cfg.InitMeta,
			}

			if err := engine.InitSessionAndRelay(ctx, initReq); err != nil {
				logger.Error("auto init session failed", "err", err)
				return
			}

			logger.Info("auto init session completed",
				"session_id", cfg.InitSessionID)
		}()
	}

	// ---------------------------------------------------------------------
	// 13) 종료 신호 / 서버 에러 대기
	// ---------------------------------------------------------------------
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server failed: %w", err)
		}
		logger.Info("http server exited")
	}

	// ---------------------------------------------------------------------
	// 14) graceful shutdown
	// ---------------------------------------------------------------------
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	logger.Info("shutting down http server")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("http server shutdown failed", "err", err)
		if cerr := httpServer.Close(); cerr != nil {
			logger.Error("http server close failed", "err", cerr)
		}
	}

	logger.Info("relay agent stopped")
	return nil
}

func bootChecks(
	ctx context.Context,
	logger logging.Logger,
	ethClient *eth.Client,
	hppkSigner *hppk.Signer,
	st store.Store,
) error {
	logger.Info("running boot checks")

	// 1) state store 정상 확인
	if err := st.Ping(ctx); err != nil {
		return fmt.Errorf("store ping failed: %w", err)
	}

	// 2) Ethereum RPC 정상 확인
	if err := ethClient.Ping(ctx); err != nil {
		return fmt.Errorf("ethereum rpc ping failed: %w", err)
	}

	chainID, err := ethClient.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("get chain id failed: %w", err)
	}
	logger.Info("ethereum rpc ok", "chain_id", chainID)

	// 3) 컨트랙트 코드 존재 확인
	ok, err := ethClient.HasContractCode(ctx)
	if err != nil {
		return fmt.Errorf("check contract code failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("contract code not found at configured contract address")
	}

	// 4) HPPK 키 정상 확인
	pubKeyHash, err := hppkSigner.PublicKeyHash()
	if err != nil {
		return fmt.Errorf("hppk public key hash failed: %w", err)
	}
	logger.Info("hppk signer ready", "pubkey_hash", pubKeyHash)

	return nil
}
