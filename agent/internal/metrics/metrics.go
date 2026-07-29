package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	HPPKSignTotal              prometheus.Counter
	HPPKVerifyTotal            *prometheus.CounterVec
	RelayMessagesTotal         prometheus.Counter
	RelayVerifyDurationSeconds prometheus.Histogram
	RelayRequestsTotal         *prometheus.CounterVec
	SessionCreatedTotal        prometheus.Counter
	BlockchainAnchorTotal      prometheus.Counter

	RelayReplayRejectedTotal    prometheus.Counter
	RelaySequenceRejectedTotal  prometheus.Counter
	RelayTimestampRejectedTotal prometheus.Counter
	RelaySignatureFailedTotal   prometheus.Counter
	RelayChainHashFailedTotal   prometheus.Counter
	RelayPayloadTamperTotal     prometheus.Counter
}

func New() *Metrics {
	m := &Metrics{
		HPPKSignTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "hppk_sign_total",
				Help: "Total number of HPPK signature operations.",
			},
		),

		HPPKVerifyTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "hppk_verify_total",
				Help: "Total number of HPPK verification operations by result.",
			},
			[]string{"result"},
		),

		RelayMessagesTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "relay_messages_total",
				Help: "Total number of relay messages received and processed.",
			},
		),

		RelayVerifyDurationSeconds: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name: "relay_verify_duration_seconds",
				Help: "Time spent verifying relay messages in seconds.",
				Buckets: []float64{
					0.000001,
					0.000005,
					0.00001,
					0.00005,
					0.0001,
					0.0005,
					0.001,
					0.005,
					0.01,
					0.05,
					0.1,
					0.5,
					1,
				},
			},
		),

		RelayRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "relay_requests_total",
				Help: "Total number of HTTP requests by method, path, and status.",
			},
			[]string{"method", "path", "status"},
		),

		SessionCreatedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "session_created_total",
				Help: "Total number of relay sessions created.",
			},
		),

		BlockchainAnchorTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "blockchain_anchor_total",
				Help: "Total number of blockchain anchor attempts by result.",
			},
		),

		RelayReplayRejectedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "relay_replay_rejected_total",
				Help: "Total number of relay messages rejected as replay attacks.",
			},
		),

		RelaySequenceRejectedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "relay_sequence_rejected_total",
				Help: "Total number of relay messages rejected because of invalid sequence.",
			},
		),

		RelayTimestampRejectedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "relay_timestamp_rejected_total",
				Help: "Total number of relay messages rejected because of invalid or expired timestamps.",
			},
		),

		RelaySignatureFailedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "relay_signature_failed_total",
				Help: "Total number of relay messages rejected because signature verification failed.",
			},
		),

		RelayChainHashFailedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "relay_chainhash_failed_total",
				Help: "Total number of relay messages rejected because chain hash verification failed.",
			},
		),

		RelayPayloadTamperTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "relay_payload_tamper_total",
				Help: "Total number of relay messages rejected because payload tampering was detected.",
			},
		),
	}

	prometheus.MustRegister(
		m.HPPKSignTotal,
		m.HPPKVerifyTotal,
		m.RelayMessagesTotal,
		m.RelayVerifyDurationSeconds,
		m.RelayRequestsTotal,
		m.SessionCreatedTotal,
		m.BlockchainAnchorTotal,
		m.RelayReplayRejectedTotal,
		m.RelaySequenceRejectedTotal,
		m.RelayTimestampRejectedTotal,
		m.RelaySignatureFailedTotal,
		m.RelayChainHashFailedTotal,
		m.RelayPayloadTamperTotal,
	)

	// CounterVec는 실제 값이 증가하기 전까지 /metrics에 나타나지 않을 수 있으므로
	// 초기 label 값을 생성합니다.
	m.HPPKVerifyTotal.WithLabelValues("success").Add(0)
	m.HPPKVerifyTotal.WithLabelValues("failure").Add(0)

	m.RelayRequestsTotal.WithLabelValues("GET", "/metrics", "200").Add(0)
	m.RelayRequestsTotal.WithLabelValues("POST", "/relay", "200").Add(0)
	m.RelayRequestsTotal.WithLabelValues("POST", "/relay", "400").Add(0)

	return m
}

func (m *Metrics) IncHPPKSign() {
	if m == nil {
		return
	}

	m.HPPKSignTotal.Inc()
}

func (m *Metrics) IncHPPKVerify(success bool) {
	if m == nil {
		return
	}

	result := "failure"
	if success {
		result = "success"
	}

	m.HPPKVerifyTotal.WithLabelValues(result).Inc()
}

func (m *Metrics) IncRelayMessage() {
	if m == nil {
		return
	}

	m.RelayMessagesTotal.Inc()
}

func (m *Metrics) ObserveRelayVerifyDuration(duration time.Duration) {
	if m == nil {
		return
	}

	m.RelayVerifyDurationSeconds.Observe(duration.Seconds())
}

func (m *Metrics) IncRelayRequest(method, path, status string) {
	if m == nil {
		return
	}

	m.RelayRequestsTotal.WithLabelValues(method, path, status).Inc()
}

func (m *Metrics) IncSessionCreated() {
	if m == nil {
		return
	}

	m.SessionCreatedTotal.Inc()
}

func (m *Metrics) IncBlockchainAnchor() {
	if m == nil {
		return
	}

	m.BlockchainAnchorTotal.Inc()
}

func (m *Metrics) IncReplayRejected() {
	if m == nil {
		return
	}

	m.RelayReplayRejectedTotal.Inc()
}

func (m *Metrics) IncSequenceRejected() {
	if m == nil {
		return
	}

	m.RelaySequenceRejectedTotal.Inc()
}

func (m *Metrics) IncTimestampRejected() {
	if m == nil {
		return
	}

	m.RelayTimestampRejectedTotal.Inc()
}

func (m *Metrics) IncSignatureFailed() {
	if m == nil {
		return
	}

	m.RelaySignatureFailedTotal.Inc()
}

func (m *Metrics) IncChainHashFailed() {
	if m == nil {
		return
	}

	m.RelayChainHashFailedTotal.Inc()
}

func (m *Metrics) IncPayloadTamper() {
	if m == nil {
		return
	}

	m.RelayPayloadTamperTotal.Inc()
}
