package eth

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
