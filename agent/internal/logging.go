package logging

type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

func New(level, agentID string) (Logger, error)
