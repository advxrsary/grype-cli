package scanner

type Vulnerability struct {
	PURL      string
	ID        string
	Severity  string
	Package   string
	Type      string
	Version   string
	FixState  string
	FixedIn   []string
	Namespace string
	URLs      []string
}
