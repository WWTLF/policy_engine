package models

type PolicyModel struct {
	Name      string
	Version   string
	Statement []PolicyStatement
}

type PolicyStatement struct {
	Sid         string
	Effect      string
	Action      []string
	Resource    []string
	NotAction   []string
	NotResource []string
	Principal   map[string][]string
}
