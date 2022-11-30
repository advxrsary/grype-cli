package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/advxrsary/vuln-scanner/cli"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <image>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	image, err := filepath.Abs(os.Args[1])
	if err != nil {
		fmt.Printf("Error getting absolute path for image: %v", err)
		os.Exit(1)
	}
	cli.Cli(image)
}
