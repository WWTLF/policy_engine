package policyprovider

type Provider interface {
	Get(string) (string, error)
}
