package authorizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/WWTLF/policy_engine/pkg/models"
	"github.com/WWTLF/policy_engine/pkg/policyprovider"
	"github.com/WWTLF/policy_engine/pkg/utils"
)

type Authorizer struct {
	provider    policyprovider.Provider
	policyCache map[string]*models.PolicyModel
}

func (a *Authorizer) unmarshalPolicy(policyRaw string) (*models.PolicyModel, error) {
	var pm models.PolicyModel
	err := json.Unmarshal([]byte(policyRaw), &pm)
	return &pm, err
}

func (a *Authorizer) loadStatemens(policies []string) ([]models.PolicyStatement, error) {
	var statements []models.PolicyStatement

	for _, policyName := range policies {
		if _, ok := a.policyCache[policyName]; !ok {
			policyRaw, err := a.provider.Get(policyName)
			if err != nil {
				return []models.PolicyStatement{}, err
			}
			a.policyCache[policyName], err = a.unmarshalPolicy(policyRaw)
			if err != nil {
				return []models.PolicyStatement{}, err
			}
		}

		statements = append(statements, a.policyCache[policyName].Statement...)
	}
	return statements, nil
}

func (a *Authorizer) Check(principal string, principalType string, policies []string, resource string, action string, skip_action bool) (bool, error) {

	authResult := false
	principalMatched := true

	if principal != "" {
		principalMatched = false
	}

	statements, err := a.loadStatemens(policies)
	if err != nil {
		return false, err
	}

	for _, statement := range statements {

		statementActionMateched := false
		statementResourceMatched := false
		matchedResourceTemp := ""
		matchedActionTemp := ""

		for _, statementAction := range statement.Action {
			if utils.MatchWildCard(statementAction, action) {
				statementActionMateched = true
				matchedActionTemp = statementAction
			}
		}

		for _, statementResource := range statement.Resource {

			if utils.MatchWildCard(statementResource, resource) {
				statementResourceMatched = true

				matchedResourceTemp = statementResource
			}

		}

		if !principalMatched {
			for _, statementPrincipal := range statement.Principal[principalType] {
				if utils.MatchWildCard(statementPrincipal, principal) {
					principalMatched = true
				}
			}
		}

		if skip_action {
			statementActionMateched = true
		}

		if statementActionMateched && statementResourceMatched && principalMatched && strings.ToLower(statement.Effect) == "deny" {
			return false, fmt.Errorf("%s %s: %s->%s, %s->%s has deny effect", principal, statement.Sid, action, matchedActionTemp, resource, matchedResourceTemp)
		}

		if strings.ToLower(statement.Effect) == "allow" && statementActionMateched && principalMatched && statementResourceMatched {
			authResult = true
		}
	}

	return authResult, nil
}

func Init(provider policyprovider.Provider) *Authorizer {
	a := Authorizer{
		provider:    provider,
		policyCache: make(map[string]*models.PolicyModel),
	}
	return &a
}
