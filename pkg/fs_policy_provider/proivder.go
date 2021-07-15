package fspolicyprovider

import (
	"io/ioutil"

	"github.com/WWTLF/policy_engine/pkg/policyprovider"
)

type Provider struct {
	path string
}

func (p *Provider) Get(name string) (string, error) {
	b, err := ioutil.ReadFile(p.path + name + ".json")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func Init(path string) policyprovider.Provider {
	p := Provider{
		path: path,
	}
	return &p
}
