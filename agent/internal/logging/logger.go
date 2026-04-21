package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
}

type logger struct {
	l *slog.Logger
}

func New(level, agentID string) (Logger, error) {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(level),
	})

	base := slog.New(handler).With(
		"service", "relay-agent",
		"agent_id", agentID,
	)

	return &logger{l: base}, nil
}

func NewWithWriter(level, agentID string, w io.Writer) (Logger, error) {
	if w == nil {
		w = os.Stdout
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: parseLevel(level),
	})

	base := slog.New(handler).With(
		"service", "relay-agent",
		"agent_id", agentID,
	)

	return &logger{l: base}, nil
}

func (x *logger) Info(msg string, args ...any) {
	x.l.Info(msg, args...)
}

func (x *logger) Warn(msg string, args ...any) {
	x.l.Warn(msg, args...)
}

func (x *logger) Error(msg string, args ...any) {
	x.l.Error(msg, args...)
}

func (x *logger) Debug(msg string, args ...any) {
	x.l.Debug(msg, args...)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "info", "":
		return slog.LevelInfo
	default:
		return slog.LevelInfo
	}
}
