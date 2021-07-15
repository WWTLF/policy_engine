package defaultpolicyprovider

import (
	"github.com/WWTLF/policy_engine/pkg/policyprovider"
)

type SimpleProvider struct {
	Policlies map[string]string
}

func (p *SimpleProvider) Get(name string) (string, error) {
	return p.Policlies[name], nil
}

func Init(policies map[string]string) policyprovider.Provider {
	p := SimpleProvider{
		Policlies: policies,
	}
	return &p
}
