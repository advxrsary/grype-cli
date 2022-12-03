package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/advxrsary/vuln-scanner/internal/scanner"
	"github.com/ryanuber/columnize"
)

func main() {
	// if there is flag 'o' then output to file	else output to stdout
	var (
		bom      = flag.String("f", "", "image")
		dist     = flag.String("d", "", "distro:version")
		output   = flag.String("o", "", "output filename")
		severity = flag.String("s", "low", "minimum severity")
		// ! requires -o flag
		toJSON = flag.Bool("j", false, "output to json")
		help   = flag.Bool("h", false, "help")
	)
	if len(os.Args) < 3 || *help {
		fmt.Printf("Usage:\n\t%s -f <bom> -d <distro:version> [-o <output>] [-s <severity>] [-j]\n", os.Args[0])
		fmt.Println("Examples:\n\tJSON output:\tvuln-scanner -f bom.json -d alpine:3.12.0 -s high -o output.txt -j")
		fmt.Println("\tTo file:\tvuln-scanner -f bom.json -d alpine:3.12.0 -o output.txt")
		fmt.Println("\tStandard output:vuln-scanner -f bom.json -d alpine:3.12.0 -s low")
		fmt.Println("Flags:")
		fmt.Println("\t-f <bom> - path to bom.json")
		fmt.Println("\t-d <distro:version> - distro and version")
		fmt.Println("\t-o <output> - output filename (optional)")
		fmt.Println("\t-s <severity> - minimum severity (optional, default: low)")
		fmt.Println("\t-j - output to json (optional, requires -o)")
		fmt.Println("\t-h - help")
		os.Exit(1)
	}
	flag.Parse()
	// * Declare severity level here!
	grypeScanner, err := scanner.New(*severity, false, true)
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

	if !*toJSON {
		if *output != "" {
			timestamp := time.Now()
			fileName := *output + "_" + timestamp.Format("2006-01-02_15:04:05") + ".txt"
			file, err := os.Create(fileName)
			if err != nil {
				log.Fatal("Cannot create file", err)
			}
			defer file.Close()
			for _, vuln := range vulns {
				fmt.Fprintf(file, "pkg=%s, vuln=%s, severity=%s\n", vuln.PURL, vuln.ID, vuln.Severity)
			}
		} else {
			var Columns []string
			for _, vuln := range vulns {
				Columns = append(Columns, fmt.Sprintf("pkg=%s | vuln=%s | severity=%s\n", vuln.PURL, vuln.ID, vuln.Severity))
			}
			result := columnize.SimpleFormat(Columns)
			fmt.Println(result)
		}
	}
	// * Output to JSON (full vuln object)
	if *toJSON {

		json, err := json.MarshalIndent(vulns, "", "\t")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// Create a new json file
		timestamp := time.Now()
		fileName := *output + "_" + timestamp.Format("2006-01-02_15:04:05") + ".json"
		file, err := os.Create(fileName)
		if err != nil {
			log.Fatal("Cannot create file", err)
		}
		defer file.Close()
		// Write to the file
		file.Write(json)
	}

}
