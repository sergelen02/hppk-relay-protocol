package internal
package hppk

type SignerConfig struct {
	PublicKeyPath  string
	SecretKeyPath  string
	AlgorithmName  string
	EnableVerify   bool
	StrictKeyCheck bool
}

type Signer struct{}

func NewSigner(cfg SignerConfig) (*Signer, error)
func (s *Signer) PublicKeyHash() (string, error)