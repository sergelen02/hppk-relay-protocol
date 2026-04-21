package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/sergelen02/hppk-relay-protocol/agent/internal/logging"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/metrics"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/protocol"
	"github.com/sergelen02/hppk-relay-protocol/agent/internal/store"
)

type Config struct {
	Logger            logging.Logger
	Metrics           *metrics.Metrics
	Store             store.Store
	ProtocolEngine    *protocol.Engine
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

type Server struct {
	logger  logging.Logger
	metrics *metrics.Metrics
	store   store.Store
	engine  *protocol.Engine
	mux     *http.ServeMux
}

func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	if cfg.ProtocolEngine == nil {
		return nil, errors.New("protocol engine is required")
	}

	s := &Server{
		logger:  cfg.Logger,
		metrics: cfg.Metrics,
		store:   cfg.Store,
		engine:  cfg.ProtocolEngine,
		mux:     http.NewServeMux(),
	}

	s.routes()
	return s, nil
}

func (s *Server) Router() http.Handler {
	return s.loggingMiddleware(s.recoverMiddleware(s.mux))
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
	s.mux.HandleFunc("/state", s.handleState)
	s.mux.HandleFunc("/relay", s.handleRelay)
	s.mux.HandleFunc("/init-session", s.handleInitSession)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	// 현재는 최소 준비 상태만 응답.
	// 이후 eth ping, store ping 추가 가능.
	writeJSON(w, http.StatusOK, map[string]any{
		"ready":     true,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service":   "relay-agent",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleRelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	defer r.Body.Close()

	var req protocol.ProcessRelayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode relay request", "err", err)
		writeError(w, http.StatusBadRequest, "invalid relay request body")
		return
	}

	resp, err := s.engine.ProcessRelay(r.Context(), req)
	if err != nil {
		s.logger.Error("relay processing failed",
			"session_id", req.Packet.SessionID,
			"step", req.Packet.Step,
			"err", err,
		)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleInitSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	defer r.Body.Close()

	var req protocol.InitSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode init-session request", "err", err)
		writeError(w, http.StatusBadRequest, "invalid init-session request body")
		return
	}

	if err := s.engine.InitSessionAndRelay(r.Context(), req); err != nil {
		s.logger.Error("init session failed",
			"session_id", req.SessionID,
			"err", err,
		)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"session_id": req.SessionID,
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic recovered", "panic", rec)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": msg,
	})
}
