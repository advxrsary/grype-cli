# How I made it work
---

#### Task
Requirements:
- Application should be written in Go
- It must use grype library as API. Usage of grype CLI is not allowed
- Application should take SBOM (Software Bill of Materials) as input and output vulnerability report
- Application should output only high severity vulnerabilities

Example of the output:
```
$ ./vuln-scanner /tmp/sbom.json 

pkg=pkg:rpm/kernel@3.10.0-1127.el7, vuln=CVE-2017-18595, severity=High
pkg=pkg:rpm/zlib@1.2.7-18.el7, vuln=CVE-2018-25032, severity=High
...
pkg=pkg:rpm/dbus@1.10.24-14.el7_8, vuln=CVE-2019-12749, severity=High

```

#### Solution

I started by reading the documentation of the grype library. I found the following functions useful:

###### Provides a set of packages and context metadata describing where they were sourced from:
    pkg.Provide(item, pkg.ProviderConfig{CatalogingOptions: cataloger.DefaultConfig()})

###### Creates a set of default matchers:
    matcher.NewDefaultMatchers(matcher.Config{})
    
###### Returns a map of vulnerabilities with given package and distro. With this function we can get all vulnerabilities for a given package:
    grype.FindVulnerabilitiesForPackage(ctx context.Context, db *grype.DB, pkg *pkg.Package, distro *distro.Distro) ([]*vulnerability.Vulnerability, error)


###### Applies ignore rules to the given matches. It is useful when we want to ignore some vulnerabilities:
    match.ApplyIgnoreRules(allMatches, s.config.Ignore)

Grype does not provide a documentation on its library usage, so I had to read other people's code to understand how to use it. On basis of these functions I was able to create a simple application that takes SBOM as input and outputs vulnerabilities. After successfull creation of the application I started to work on the requirements and also added some extra features.





