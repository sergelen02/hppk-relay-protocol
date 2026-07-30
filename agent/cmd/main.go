package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"agent terminated with error: %v\n",
			err,
		)
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

	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	// ---------------------------------------------------------------------
	// 2) 로거 초기화
	// ---------------------------------------------------------------------
	logger, err := logging.New(
		cfg.LogLevel,
		cfg.AgentID,
	)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}

	logger.Info(
		"starting relay agent",
		"agent_id", cfg.AgentID,
		"http_addr", cfg.HTTPListenAddr,
		"eth_address", cfg.EthAddress,
		"rpc_url", cfg.RPCURL,
		"contract_address", cfg.ContractAddress,
		"hppk_algorithm", cfg.HPPKAlgorithm,
		"hppk_public_key_path", cfg.HPPKPublicKeyPath,
	)

	// ---------------------------------------------------------------------
	// 3) 상태 저장소 초기화
	// ---------------------------------------------------------------------
	st, err := store.NewFileStore(cfg.StateFile)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}

	defer func() {
		if closeErr := st.Close(); closeErr != nil {
			logger.Error(
				"failed to close store",
				"err", closeErr,
			)
		}
	}()

	// ---------------------------------------------------------------------
	// 4) 메트릭 초기화
	// ---------------------------------------------------------------------
	m := metrics.New()

	// ---------------------------------------------------------------------
	// 5) Ethereum 클라이언트 초기화
	// ---------------------------------------------------------------------
	ethClient, err := eth.NewClient(
		ctx,
		eth.ClientConfig{
			RPCURL:          cfg.RPCURL,
			ChainID:         cfg.ChainID,
			ContractAddress: cfg.ContractAddress,
			PrivateKeyHex:   cfg.EthPrivateKey,
			FromAddress:     cfg.EthAddress,
			ConfirmTimeout:  cfg.TxConfirmTimeout,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"init ethereum client: %w",
			err,
		)
	}

	defer func() {
		if closeErr := ethClient.Close(); closeErr != nil {
			logger.Error(
				"failed to close ethereum client",
				"err", closeErr,
			)
		}
	}()

	// ---------------------------------------------------------------------
	// 6) 실제 HPPK signer/verifier 초기화
	// ---------------------------------------------------------------------
	hppkSigner, err := hppk.NewSigner(
		hppk.SignerConfig{
			PublicKeyPath:  cfg.HPPKPublicKeyPath,
			SecretKeyPath:  cfg.HPPKSecretKeyPath,
			AlgorithmName:  cfg.HPPKAlgorithm,
			EnableVerify:   true,
			StrictKeyCheck: true,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"init HPPK signer: %w",
			err,
		)
	}

	// 실제 HPPK 키 로드 상태를 초기화 직후 확인합니다.
	pubKeyHash, err := hppkSigner.PublicKeyHash()
	if err != nil {
		return fmt.Errorf(
			"calculate HPPK public key hash: %w",
			err,
		)
	}
	if strings.TrimSpace(pubKeyHash) == "" {
		return errors.New(
			"HPPK public key hash is empty",
		)
	}

	logger.Info(
		"HPPK signer initialized",
		"algorithm", cfg.HPPKAlgorithm,
		"pubkey_hash", pubKeyHash,
	)

	// ---------------------------------------------------------------------
	// 7) 다음 agent로 전송하는 HTTP 클라이언트
	// ---------------------------------------------------------------------
	nextClient := client.NewRelayClient(
		client.Config{
			Timeout:       cfg.NextRelayTimeout,
			MaxRetries:    cfg.NextRelayMaxRetries,
			RetryInterval: cfg.NextRelayRetryInterval,
			Logger:        logger,
		},
	)

	if nextClient == nil {
		return errors.New(
			"relay client initialization returned nil",
		)
	}

	// ---------------------------------------------------------------------
	// 8) 프로토콜 엔진 초기화
	// ---------------------------------------------------------------------
	engine := protocol.NewEngine(
		protocol.EngineConfig{
			AgentID:              cfg.AgentID,
			MyAddress:            cfg.EthAddress,
			ExpectedStep:         cfg.ExpectedStep,
			NextAgentURL:         cfg.NextAgentURL,
			EnablePayloadCompare: cfg.EnablePayloadCompare,
			MaxClockSkew:         cfg.MaxClockSkew,

			Logger:      logger,
			Metrics:     m,
			Store:       st,
			EthClient:   ethClient,
			HPPKSigner:  hppkSigner,
			RelayClient: nextClient,
		},
	)

	if engine == nil {
		return errors.New(
			"protocol engine initialization returned nil",
		)
	}

	// ---------------------------------------------------------------------
	// 9) HTTP 서버 핸들러 구성
	// ---------------------------------------------------------------------
	srv, err := server.New(
		server.Config{
			Logger:            logger,
			Metrics:           m,
			Store:             st,
			ProtocolEngine:    engine,
			ReadTimeout:       15 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"init server: %w",
			err,
		)
	}

	if srv == nil {
		return errors.New(
			"server initialization returned nil",
		)
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
	if err := bootChecks(
		ctx,
		logger,
		ethClient,
		hppkSigner,
		st,
	); err != nil {
		return fmt.Errorf(
			"boot checks failed: %w",
			err,
		)
	}

	// ---------------------------------------------------------------------
	// 11) HTTP 서버 시작
	// ---------------------------------------------------------------------
	errCh := make(chan error, 1)

	go func() {
		logger.Info(
			"http server listening",
			"addr", cfg.HTTPListenAddr,
		)

		err := httpServer.ListenAndServe()

		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}

		select {
		case errCh <- err:
		default:
			logger.Error(
				"could not deliver HTTP server result",
				"err", err,
			)
		}
	}()

	// ---------------------------------------------------------------------
	// 12) 초기 세션 시작 옵션
	// ---------------------------------------------------------------------
	if cfg.AutoInitSession {
		go func() {
			timer := time.NewTimer(
				2 * time.Second,
			)
			defer timer.Stop()

			select {
			case <-ctx.Done():
				logger.Info(
					"auto init session cancelled before start",
				)
				return

			case <-timer.C:
			}

			logger.Info(
				"auto init session enabled",
				"session_id", cfg.InitSessionID,
				"payload_path", cfg.InitPayloadPath,
			)

			initReq := protocol.InitSessionRequest{
				SessionID:      cfg.InitSessionID,
				PayloadPath:    cfg.InitPayloadPath,
				RouteAddresses: cfg.RouteAddresses,
				Meta:           cfg.InitMeta,
			}

			if err := engine.InitSessionAndRelay(
				ctx,
				initReq,
			); err != nil {
				if errors.Is(
					err,
					context.Canceled,
				) {
					logger.Info(
						"auto init session cancelled",
					)
					return
				}

				logger.Error(
					"auto init session failed",
					"session_id", cfg.InitSessionID,
					"err", err,
				)
				return
			}

			logger.Info(
				"auto init session completed",
				"session_id", cfg.InitSessionID,
			)
		}()
	}

	// ---------------------------------------------------------------------
	// 13) 종료 신호 또는 서버 에러 대기
	// ---------------------------------------------------------------------
	select {
	case <-ctx.Done():
		logger.Info(
			"shutdown signal received",
			"reason", ctx.Err(),
		)

	case serveErr := <-errCh:
		if serveErr != nil {
			return fmt.Errorf(
				"http server failed: %w",
				serveErr,
			)
		}

		logger.Info(
			"http server exited",
		)
	}

	// ---------------------------------------------------------------------
	// 14) graceful shutdown
	// ---------------------------------------------------------------------
	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	defer shutdownCancel()

	logger.Info(
		"shutting down http server",
	)

	if err := httpServer.Shutdown(
		shutdownCtx,
	); err != nil {
		logger.Error(
			"http server shutdown failed",
			"err", err,
		)

		if closeErr := httpServer.Close(); closeErr != nil {
			logger.Error(
				"http server forced close failed",
				"err", closeErr,
			)
		}
	}

	logger.Info(
		"relay agent stopped",
	)

	return nil
}

func validateConfig(
	cfg *config.Config,
) error {
	if cfg == nil {
		return errors.New(
			"config is nil",
		)
	}

	if strings.TrimSpace(cfg.AgentID) == "" {
		return errors.New(
			"agent ID is required",
		)
	}

	if strings.TrimSpace(cfg.HTTPListenAddr) == "" {
		return errors.New(
			"HTTP listen address is required",
		)
	}

	if strings.TrimSpace(cfg.RPCURL) == "" {
		return errors.New(
			"Ethereum RPC URL is required",
		)
	}

	if strings.TrimSpace(cfg.ContractAddress) == "" {
		return errors.New(
			"contract address is required",
		)
	}

	if strings.TrimSpace(cfg.EthAddress) == "" {
		return errors.New(
			"Ethereum address is required",
		)
	}

	if strings.TrimSpace(
		cfg.HPPKPublicKeyPath,
	) == "" {
		return errors.New(
			"HPPK public key path is required",
		)
	}

	if strings.TrimSpace(
		cfg.HPPKSecretKeyPath,
	) == "" {
		return errors.New(
			"HPPK secret key path is required",
		)
	}

	if strings.TrimSpace(
		cfg.HPPKAlgorithm,
	) == "" {
		return errors.New(
			"HPPK algorithm name is required",
		)
	}

	if cfg.MaxClockSkew < 0 {
		return errors.New(
			"max clock skew cannot be negative",
		)
	}

	if cfg.AutoInitSession {
		if strings.TrimSpace(
			cfg.InitSessionID,
		) == "" {
			return errors.New(
				"init session ID is required when auto init is enabled",
			)
		}

		if strings.TrimSpace(
			cfg.InitPayloadPath,
		) == "" {
			return errors.New(
				"init payload path is required when auto init is enabled",
			)
		}

		if len(cfg.RouteAddresses) == 0 {
			return errors.New(
				"route addresses are required when auto init is enabled",
			)
		}
	}

	return nil
}

func bootChecks(
	ctx context.Context,
	logger logging.Logger,
	ethClient *eth.Client,
	hppkSigner *hppk.Signer,
	st store.Store,
) error {
	if logger == nil {
		return errors.New(
			"logger is nil",
		)
	}

	if st == nil {
		return errors.New(
			"store is nil",
		)
	}

	if ethClient == nil {
		return errors.New(
			"Ethereum client is nil",
		)
	}

	if hppkSigner == nil {
		return errors.New(
			"HPPK signer is nil",
		)
	}

	logger.Info(
		"running boot checks",
	)

	// ---------------------------------------------------------------------
	// 1) state store 정상 확인
	// ---------------------------------------------------------------------
	if err := st.Ping(ctx); err != nil {
		return fmt.Errorf(
			"store ping failed: %w",
			err,
		)
	}

	logger.Info(
		"state store ok",
	)

	// ---------------------------------------------------------------------
	// 2) Ethereum RPC 정상 확인
	// ---------------------------------------------------------------------
	if err := ethClient.Ping(ctx); err != nil {
		return fmt.Errorf(
			"ethereum RPC ping failed: %w",
			err,
		)
	}

	chainID, err := ethClient.ChainID(ctx)
	if err != nil {
		return fmt.Errorf(
			"get chain ID failed: %w",
			err,
		)
	}

	logger.Info(
		"ethereum RPC ok",
		"chain_id", chainID,
	)

	// ---------------------------------------------------------------------
	// 3) 컨트랙트 코드 존재 확인
	// ---------------------------------------------------------------------
	hasCode, err := ethClient.HasContractCode(ctx)
	if err != nil {
		return fmt.Errorf(
			"check contract code failed: %w",
			err,
		)
	}

	if !hasCode {
		return fmt.Errorf(
			"contract code not found at configured contract address",
		)
	}

	logger.Info(
		"contract code found",
	)

	// ---------------------------------------------------------------------
	// 4) 실제 HPPK 키 정상 확인
	// ---------------------------------------------------------------------
	pubKeyBytes, err := hppkSigner.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf(
			"load HPPK public key bytes: %w",
			err,
		)
	}

	if len(pubKeyBytes) == 0 {
		return errors.New(
			"HPPK public key bytes are empty",
		)
	}

	pubKeyHash, err := hppkSigner.PublicKeyHash()
	if err != nil {
		return fmt.Errorf(
			"HPPK public key hash failed: %w",
			err,
		)
	}

	if strings.TrimSpace(pubKeyHash) == "" {
		return errors.New(
			"HPPK public key hash is empty",
		)
	}

	// 실제 서명/검증 self-test
	testMessage := []byte(
		"hppk-relay-protocol-boot-self-test",
	)

	signature, err := hppkSigner.Sign(
		testMessage,
	)
	if err != nil {
		return fmt.Errorf(
			"HPPK boot self-test sign failed: %w",
			err,
		)
	}

	if len(signature) == 0 {
		return errors.New(
			"HPPK boot self-test returned empty signature",
		)
	}

	verifyOK, err := hppkSigner.Verify(
		pubKeyBytes,
		testMessage,
		signature,
	)
	if err != nil {
		return fmt.Errorf(
			"HPPK boot self-test verify failed: %w",
			err,
		)
	}

	if !verifyOK {
		return errors.New(
			"HPPK boot self-test verification returned false",
		)
	}

	logger.Info(
		"HPPK signer ready",
		"pubkey_hash", pubKeyHash,
		"public_key_bytes", len(pubKeyBytes),
		"signature_bytes", len(signature),
	)

	return nil
}
