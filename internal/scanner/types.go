package scanner

import "github.com/facebookincubator/nvdtools/wfn"

type CPE = wfn.Attributes

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
