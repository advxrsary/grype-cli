package scanner

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/sirupsen/logrus"
)

type Grype struct {
	store          *store.Store
	dbCloser       *db.Closer
	config         grypeConfig
	relatedEntries map[string]string
	onlyFixed      bool
	minSeverity    string
}

type grypeConfig struct {
	Distro string             `yaml:"distro" json:"distro" mapstructure:"distro"`
	Ignore []match.IgnoreRule `yaml:"ignore"`
	PURL   string             `yaml:"purl" json:"purl" mapstructure:"purl"`
}

func New(minSeverity string, onlyFixed, withoutK8s bool) (Grype, error) {

	config := db.Config{
		ListingURL: "https://toolbox-data.anchore.io/grype/databases/listing.json",
		DBRootDir:  "/Users/mad/Library/Caches/grype/db/",
	}

	logrus.Debug("Load vulnerability database")
	store, dbStatus, dbCloser, err := grype.LoadVulnerabilityDB(config, true)
	if err = validateDBLoad(err, dbStatus); err != nil {
		logrus.Error(err)
		return Grype{}, err
	}

	return Grype{
		store:          store,
		dbCloser:       dbCloser,
		minSeverity:    minSeverity,
		onlyFixed:      onlyFixed,
		relatedEntries: map[string]string{},
	}, nil
}

func (s *Grype) ScanItem(item string, dist string) ([]Vulnerability, error) {
	packages, context, err := pkg.Provide(item, pkg.ProviderConfig{CatalogingOptions: cataloger.DefaultConfig()})
	split := strings.Split(dist, ":")
	d := split[0]
	v := ""
	if len(split) > 1 {
		v = split[1]
	}
	context.Distro = &linux.Release{
		PrettyName: d,
		Name:       d,
		ID:         d,
		IDLike:     []string{d},
		VersionID:  v,
		Version:    v,
	}
	if err != nil {
		logrus.WithError(err).Error("Grype scan failed")
		return []Vulnerability{}, err
	}
	matchers := matcher.NewDefaultMatchers(matcher.Config{})
	allMatches := grype.FindVulnerabilitiesForPackage(*s.store, context.Distro, matchers, packages)
	remainingMatches, _ := match.ApplyIgnoreRules(allMatches, s.config.Ignore)
	vulns := s.buildVulnerabilities(remainingMatches)
	return s.filterVulnerabilities(vulns), nil
}

func (s *Grype) Close() {
	s.dbCloser.Close()
}

func validateDBLoad(loadErr error, status *db.Status) error {
	if loadErr != nil {
		return fmt.Errorf("failed to load vulnerability db: %w", loadErr)
	}
	if status == nil {
		return fmt.Errorf("unable to determine DB status")
	}
	if status.Err != nil {
		return fmt.Errorf("db could not be loaded: %w", status.Err)
	}
	return nil
}

func (s *Grype) buildVulnerabilities(matches match.Matches) []Vulnerability {
	vulnerabilities := make([]Vulnerability, 0)

	for m := range matches.Enumerate() {
		metadata, err := s.store.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
		if err != nil {
			continue
		}

		fixedIn := []string{}
		if m.Vulnerability.Fix.State == v5.FixedState {
			fixedIn = m.Vulnerability.Fix.Versions
		}

		if m.Vulnerability.RelatedVulnerabilities != nil {
			for _, ref := range m.Vulnerability.RelatedVulnerabilities {
				s.relatedEntries[fmt.Sprintf("%s:%s", m.Vulnerability.Namespace, m.Vulnerability.ID)] =
					fmt.Sprintf("%s:%s", ref.Namespace, ref.ID)
			}
		}

		v := Vulnerability{
			PURL:      m.Package.PURL,
			ID:        m.Vulnerability.ID,
			Severity:  metadata.Severity,
			Package:   m.Package.Name,
			Type:      string(m.Package.Type),
			Version:   m.Package.Version,
			Namespace: m.Vulnerability.Namespace,
			FixState:  string(m.Vulnerability.Fix.State),
			FixedIn:   fixedIn,
			URLs:      metadata.URLs,
		}

		vulnerabilities = append(vulnerabilities, v)
	}
	// fmt.Printf("Found %v vulnerabilities", vulnerabilities)

	return vulnerabilities
}

func (s *Grype) filterVulnerabilities(allVulns []Vulnerability) []Vulnerability {
	minSeverity := vulnerability.ParseSeverity(s.minSeverity)

	vulns := make([]Vulnerability, 0)

	for _, v := range allVulns {
		if s.hasRelated(v, allVulns) {
			continue
		}

		sev := vulnerability.ParseSeverity(v.Severity)
		if sev >= minSeverity && v.Version != "" {
			if s.onlyFixed {
				if v.FixState == string(v5.FixedState) {
					vulns = append(vulns, v)
				}
			} else {
				vulns = append(vulns, v)
			}
		}
	}

	return vulns
}

func (s *Grype) hasRelated(v Vulnerability, all []Vulnerability) bool {
	for original, related := range s.relatedEntries {
		if original == fmt.Sprintf("%s:%s", v.Namespace, v.ID) {
			for _, a := range all {
				if fmt.Sprintf("%s:%s", a.Namespace, a.ID) == related {
					return true
				}
			}

			return false
		}
	}

	return false
}
