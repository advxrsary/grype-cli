package cli

import (
	"fmt"
	"os"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

func Cli(sbom string) match.Matches {
	
	// SBOM is set as an argument

	store, _, _, err := grype.LoadVulnerabilityDB(db.Config{}, true)
	if err != nil {
		fmt.Printf("Error loading vulnerability DB: %v", err)
		os.Exit(1)
	}
	scopeOpt := source.ParseScope("squashedscope")
	// I dont know where to get the data for these parameters
	// So I just hardcoded them to nil and linux/amd64
	regOptions := image.RegistryOptions{
		InsecureSkipTLSVerify: false,
		InsecureUseHTTP:       false,
		Credentials:           nil,
		Platform:              "linux/amd64",
	}
	matches, context, packages, err := grype.FindVulnerabilities(*store, sbom, scopeOpt, &regOptions)
	if err != nil {
		fmt.Print(err)
	}

	for _, pkg := range packages {
		fmt.Printf("pkg=%s\tvuln=%s\tseverity=%s\n", pkg.Name)
	}
	// debug output
	fmt.Printf("matches: %s,\ncontext: %v\n", matches, context)

	return matches
}