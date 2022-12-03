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
		dist     = flag.String("d", "centos:07", "distro:version")
		output   = flag.String("o", "", "output filename")
		severity = flag.String("s", "low", "minimum severity")
		// ! requires -o flag
		toJSON = flag.Bool("j", false, "output to json")
		help   = flag.Bool("h", false, "help")
	)
	if len(os.Args) < 2 || *help {
		fmt.Printf("Usage:\n\t%s -f <bom> [-d <distro:version>] [-o <output>] [-s <severity>] [-j]\n", os.Args[0])
		fmt.Println("\tFlags in square brackets are optional")
		fmt.Printf("Examples:\n\tJSON output:\t%s -f bom.json -d alpine:3.12.0 -s high -o output.txt -j\n", os.Args[0])
		fmt.Printf("\tTXT file:\t%s -f bom.json -d alpine:3.12.0 -o output.txt\n", os.Args[0])
		fmt.Printf("\tSTD output:\t%s -f bom.json -d alpine:3.12.0\n", os.Args[0])
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
	grypeScanner, err := scanner.New(*severity, false, true)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	vulns, err := grypeScanner.ScanItem("sbom:"+*bom, *dist)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

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
