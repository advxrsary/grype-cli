package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/advxrsary/vuln-scanner/internal/scanner/grype"
)

func main() {
	// if there is flag 'o' then output to file	else output to stdout
	var (
		bom      = flag.String("f", "", "image")
		dist     = flag.String("d", "", "distro:version")
		output   = flag.String("o", "", "output file (optional)")
		severity = flag.String("s", "low", "minimum severity (optional)")
	)
	flag.Parse()

	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s -f <image> -d <distro:version> <optional flags>", os.Args[0])
		os.Exit(1)
	}
	// * Declare severity level here!
	grypeScanner, err := grype.New(*severity, false, true)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// * shouuld be distro:version
	vulns, err := grypeScanner.ScanItem("sbom:"+*bom, *dist)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Output format:
	// pkg=pkg:rpm/kernel@3.10.0-1127.el7, vuln=CVE-2017-18595, severity=High
	// pkg=pkg:rpm/zlib@1.2.7-18.el7, vuln=CVE-2018-25032, severity=High
	// pkg=pkg:rpm/dbus@1.10.24-14.el7_8, vuln=CVE-2019-12749, severity=High

	// create a new file in format of <[0] of Split.(image, '.')>-<dd-mm-yyyy-hh-mm-ss>.txt
	if *output != "" {
		t := time.Now()
		fileName := *output + "_" + t.Format("02-01-2006-15-04-05") + ".txt"
		file, err := os.Create(fileName)
		if err != nil {
			log.Fatal("Cannot create file", err)
		}
		defer file.Close()
		for _, vuln := range vulns {
			fmt.Fprintf(file, "pkg=%s, vuln=%s, severity=%s\n", vuln.Package, vuln.ID, vuln.Severity)
		}
	} else {
		for _, vuln := range vulns {
			fmt.Printf("pkg=%s, vuln=%s, severity=%s\n", vuln.Package, vuln.ID, vuln.Severity)
		}
	}
}
