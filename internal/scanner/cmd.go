package scanner

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/anchore/syft/syft/linux"
	"github.com/ryanuber/columnize"
)

var (
	BK = color.New(color.FgBlack).SprintFunc()
	WH = color.New(color.FgWhite).SprintFunc()
	GR = color.New(color.FgGreen).SprintFunc()
	YE = color.New(color.FgYellow).SprintFunc()
	BL = color.New(color.FgBlue).SprintFunc()
	MA = color.New(color.FgMagenta).SprintFunc()
	CY = color.New(color.FgCyan).SprintFunc()
)

func ParseDistro(distro string) (linux.Release, error) {
	split := strings.Split(distro, ":")
	d := split[0]
	v := ""
	if len(split) > 1 {
		v = split[1]
	}
	release := linux.Release{
		PrettyName: d,
		Name:       d,
		ID:         d,
		IDLike: []string{
			d,
		},
		Version:   v,
		VersionID: v,
	}
	return release, nil
}

func CmdRun() {

	var (
		bom           = flag.String("f", "", "image")
		dist          = flag.String("d", "centos:07", "distro:version") // * if you want to change default distro change the second argument
		output        = flag.String("o", "", "output filename")
		severity      = flag.String("s", "high", "minimum severity")
		columnizeBool = flag.Bool("c", false, "columnize standard output")
		fixed         = flag.Bool("of", false, "only fixed")
		// ! requires -o flag
		toJSON           = flag.Bool("j", false, "output to json")
		dont_show_params = flag.Bool("p", false, "dont show flags parameters")
		help             = flag.Bool("h", false, "help")
	)
	show_params := true
	if *dont_show_params {
		show_params = false
	}
	if len(os.Args) < 2 || *help {
		fmt.Println(GR("\nVuln Scanner") + " " + YE("v0.1.0"))
		fmt.Println("-------------------")
		fmt.Printf("Usage:\n\t%s -f <bom> [-d <distro:version>] [-o <output>] [-s <severity>] [-j]\n", os.Args[0])
		fmt.Println("\tFlags in square brackets are optional")
		fmt.Printf("Examples:\n\tJSON output:\t%s -f bom.json -d alpine:3.12.0 -s high -o output.txt -j\n", os.Args[0])
		fmt.Printf("\tTXT file:\t%s -f bom.json -d alpine:3.12.0 -o output.txt\n", os.Args[0])
		fmt.Printf("\tSTD output:\t%s -f bom.json -d alpine:3.12.0\n", os.Args[0])
		fmt.Println("Flags:")
		fmt.Println("\t-f <bom> - path to bom.json")
		fmt.Println("\t-d <distro:version> - distro and version")
		fmt.Println("\t-o <output> - output filename (optional)")
		fmt.Println("\t-s <severity> - minimum severity (optional, default: high)")
		fmt.Println("\t-c - columnize standard output (optional)")
		fmt.Println("\t-of - only fixed (optional")
		fmt.Println("\t-j - output to json (optional, requires -o)")
		fmt.Println("\t-p - dont show flag parameters")
		fmt.Println("\t-h - help")
		os.Exit(0)
	}
	flag.Parse()
	parsedDist, err := ParseDistro(*dist)
	if err != nil {
		log.Fatal("Cannot parse distro", err)
	}

	if show_params {
		// fmt.Printf("%s %s\n", GR("Vuln Scanner"), YE("v0.1.0"))
		// fmt.Printf("%s %s\n", "BOM:", BL(*bom))
		// fmt.Printf("%s %s\n", "Distro:", BL(*dist))
		// fmt.Printf("%s %s\n", "Severity:", BL(*severity))
		// fmt.Printf("%s %s\n", "Columnize:", BL(*columnizeBool))
		// fmt.Printf("%s %s\n", "Only fixed:", BL(*fixed))
		// fmt.Printf("%s %s\n\n", "JSON:", BL(*toJSON))
		// Columnize commented code above with colors
		out := []string{
			GR("\nVuln Scanner") + " " + YE("v0.1.0"),
			"-------------------",
			"BOM:\t\t" + BL(*bom),
			"Distro:\t\t" + BL(*dist),
			"Severity:\t" + BL(*severity),
			"Columnize:\t" + BL(*columnizeBool),
			"Only fixed:\t" + BL(*fixed),
			"JSON:\t\t" + BL(*toJSON),
			"-------------------",
		}
		fmt.Println(columnize.SimpleFormat(out))

	}

	grypeScanner, err := New(*severity, *fixed)
	if err != nil {
		log.Fatal("Cannot create scanner", err)
	}
	fmt.Println("Scanning...")
	vulns, err := grypeScanner.ScanItem("sbom:"+*bom, parsedDist)
	if err != nil {
		log.Fatal("Cannot scan item", err)
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
		} else if *columnizeBool {
			var Columns []string
			for _, vuln := range vulns {
				Columns = append(Columns, fmt.Sprintf("pkg=%s | vuln=%s | severity=%s\n", vuln.PURL, vuln.ID, vuln.Severity))
			}
			result := columnize.SimpleFormat(Columns)
			fmt.Println(result)
		} else {
			for _, vuln := range vulns {
				fmt.Printf("pkg=%s, vuln=%s, severity=%s\n", vuln.PURL, vuln.ID, vuln.Severity)
			}
		}
	}
	// * Output to JSON (full vuln object)
	if *toJSON {

		json, err := json.MarshalIndent(vulns, "", "\t")
		if err != nil {
			log.Fatal("Cannot marshal to json", err)
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
