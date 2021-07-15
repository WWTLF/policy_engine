package test

import (
	"testing"

	defaultpolicyprovider "github.com/WWTLF/policy_engine/pkg/default_policy_provider"
	authorizer "github.com/WWTLF/policy_engine/pkg/services/authorizer"
)

var (
	testPolicy1 = `
		{
			"Name": "testPolicy1",
			"Version": "2021-07-07",
			"Statement":[
				{
					"Sid": "Allow rule to resource cfge:123:*, cfge:567:* ",
					"Effect": "Allow",
					"Action":["cfge:*", "cfge:UPDATE", "cfge:DELETE"],
					"Resource":["cfge:123:*", "cfge:567:*"]
				},
				{
					"Sid": "Deny rule to resource  cfge:567:* ",
					"Effect": "Deny",
					"Action":["cfge:*"],
					"Resource":["cfge:567:*"]
				}
			]
		}`
	testPolicy2 = `
		{
			"Name": "testPolicy2",
			"Version": "2021-07-07",
			"Statement":[
				{
					"Sid": "Deny rule to resource cfge:789:*",
					"Effect": "Deny",
					"Action":["cfge:delete"],
					"Resource":["cfge:789:*"]
				}
			]
		}
	`
)

func TestSomkeAllow(t *testing.T) {
	policies := map[string]string{
		"testPolicy1": testPolicy1,
		"testPolicy2": testPolicy2,
	}

	policy_provider := defaultpolicyprovider.Init(policies)
	authorizer := authorizer.Init(policy_provider)
	allow, err := authorizer.Check("", "", []string{"testPolicy1", "testPolicy2"}, "cfge:123:567", "cfge:create")
	if !allow {
		t.Fatal("allow test failed")
	}

	if err != nil {
		t.Fatal("allow test failed ", err)
	}

	allow, err = authorizer.Check("", "", []string{"testPolicy1", "testPolicy2"}, "cfge:567:567", "cfge:create")
	t.Log("Deny test failed ", err)
	if allow {
		t.Fatal("Deny test failed")
	}

}
