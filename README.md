# vuln-scanner

### Description
This is a command line interface tool based on the @anchore's grype. It scans SBOM file and reports the vulnerabilities found in the image. This tool has its benefits over grype. It is less resource intensive and has simple and easy to use interface.

### Installation
```
$ git clone
$ cd vuln-scanner
$ go build -o vuln-scanner
```

### Usage
```
$ ./vuln-scanner -h

Usage:
        ./vuln-scanner -f <bom> [-d <distro:version>] [-o <output>] [-s <severity>] [-j]
        Flags in square brackets are optional
Examples:
        JSON output:    ./vuln-scanner -f bom.json -d alpine:3.12.0 -s high -o output.txt -j
        TXT file:       ./vuln-scanner -f bom.json -d alpine:3.12.0 -o output.txt
        STD output:     ./vuln-scanner -f bom.json
Flags:
        -f <bom> - path to bom.json
        -d <distro:version> - distro and version
        -o <output> - output filename (optional)
        -s <severity> - minimum severity (optional, default: high)
        -j - output to json (optional, requires -o)
        -h - help
```

### Example
```
$ ./vuln-scanner -f bom.json -d alpine:3.12.0 -o output.txt
pkg=pkg:rpm/rsync@3.1.2-10.el7                         vuln=CVE-2022-29154  severity=High
pkg=pkg:rpm/kernel@3.10.0-1127.19.1.el7                vuln=CVE-2021-4083   severity=High
pkg=pkg:rpm/xz@5.2.2-1.el7                             vuln=CVE-2022-1271   severity=High
pkg=pkg:rpm/freetype@2.8-14.el7                        vuln=CVE-2020-15999  severity=High
...
```
