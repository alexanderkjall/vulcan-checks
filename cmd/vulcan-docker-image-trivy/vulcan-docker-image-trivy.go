package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"

	report "github.com/adevinta/vulcan-report"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
)

var (
	checkName        = "vulcan-docker-image-trivy"
	trivyCachePath   = "trivy_cache"
	reportOutputFile = "report.json"
)

type options struct {
	ForceUpdateDB bool   `json:"force_update_db"`
	IgnoreUnfixed bool   `json:"ignore_unfixed"`
	Severities    string `json:"severities"`
}

type ScanResponse []struct {
	Target          string `json:"Target"`
	Vulnerabilities []struct {
		VulnerabilityID  string   `json:"VulnerabilityID"`
		PkgName          string   `json:"PkgName"`
		InstalledVersion string   `json:"InstalledVersion"`
		FixedVersion     string   `json:"FixedVersion"`
		Title            string   `json:"Title,omitempty"`
		Description      string   `json:"Description,omitempty"`
		Severity         string   `json:"Severity"`
		References       []string `json:"References,omitempty"`
	} `json:"Vulnerabilities"`
}

type outdatedPackage struct {
	name     string
	version  string
	severity string
	fixedBy  string
}

type vulnerability struct {
	name     string
	severity string
	link     string
}

var vuln = report.Vulnerability{
	Summary:     "Outdated Packages in Docker Image (BETA)",
	Description: "Vulnerabilities have been found in outdated packages installed in the Docker image.",
	CWEID:       937,
	Recommendations: []string{
		"Update affected packages to the versions specified in the resources table or newer.",
		"This check is in BETA phase.",
	},
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target string, optJSON string, state state.State) error {
	// Load required env vars for docker registry authentication.
	registryEnvDomain := os.Getenv("REGISTRY_DOMAIN")
	registryEnvUsername := os.Getenv("REGISTRY_USERNAME")
	registryEnvPassword := os.Getenv("REGISTRY_PASSWORD")

	// TODO: If options are "malformed" perhaps we should not return error
	// but only log and error and return.
	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	// TODO: If target is "malformed" perhaps we should not return error
	// but only log and error and return.
	slashSplit := strings.SplitAfterN(target, "/", 2)
	if len(slashSplit) <= 1 {
		return errors.New(target + " is not a valid target")
	}
	// TODO: If target is "malformed" perhaps we should not return error
	// but only log and error and return.
	targetSplit := strings.Split(slashSplit[1], ":")
	if len(targetSplit) != 2 {
		return errors.New(target + "is not a valid target")
	}

	registryDomain := strings.Trim(slashSplit[0], "/")
	// If docker registry equals registryDomain, export trivy credential env vars.
	if registryDomain == registryEnvDomain {
		os.Setenv("TRIVY_AUTH_URL", fmt.Sprintf("https://%s", registryEnvDomain))
		os.Setenv("TRIVY_USERNAME", registryEnvUsername)
		os.Setenv("TRIVY_PASSWORD", registryEnvPassword)
	}

	// Build trivy command with arguments.
	triviCmd := "./trivy"
	triviArgs := []string{
		"--cache-dir", trivyCachePath,
		"-f", "json",
		"-o", reportOutputFile,
	}
	// Force vulnerability db cache update.
	if opt.ForceUpdateDB {
		triviArgs = append(triviArgs, "--skip-update")
	}
	// Show only vulnerabilities with fixes.
	if opt.IgnoreUnfixed {
		triviArgs = append(triviArgs, "--ignore-unfixed")
	}
	// Show only vulnerabilities with specific severities.
	if opt.Severities != "" {
		severitiesFlag := []string{"--severity", opt.Severities}
		triviArgs = append(triviArgs, severitiesFlag...)
	}
	// Append the target (docker image including registry hostname).
	triviArgs = append(triviArgs, target)

	log.Printf("Running command: %s %s\n", triviCmd, triviArgs)
	cmd := exec.Command(triviCmd, triviArgs...)
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("exec.Command() failed with %s\nCommand output: %s\n", err, string(cmdOutput))
		return errors.New("trivy command execution failed")
	}
	log.Printf("trivy command execution completed successfully")

	jsonFile, err := os.Open(reportOutputFile)
	if err != nil {
		log.Fatalf("trivy report output file read failed with error: %s\n", err)
		return errors.New("trivy report output file open failed")
	}
	log.Printf("successfully open trivy report output file %s\n", reportOutputFile)
	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatalf("trivy report output file read failed with error: %s\n", err)
		return errors.New("trivy report output file read failed")
	}

	var results ScanResponse
	err = json.Unmarshal(byteValue, &results)
	if err != nil {
		return errors.New("unmarshal trivy output failed")
	}

	// If there are no vulnerabilities we can return.
	if len(results) < 1 {
		return nil
	}

	ap := report.ResourcesGroup{
		Name: "Affected Packages",
		Header: []string{
			"Name",
			"Version",
			"Severity",
			"FixedBy",
		},
	}

	vp := report.ResourcesGroup{
		Name: "Package Vulnerabilities",
		Header: []string{
			"Name",
			"Version",
			"Vulnerabilities",
		},
	}

	var rows []map[string]string
	// As we are scanning only one container per check, we have only one item
	// in results array.
	for _, feature := range results[0].Vulnerabilities {
		p := outdatedPackage{
			name:     feature.PkgName,
			version:  feature.InstalledVersion,
			severity: feature.Severity,
			fixedBy:  feature.FixedVersion,
		}

		var vulns []vulnerability

		v := vulnerability{
			name:     feature.PkgName,
			link:     feature.Description,
			severity: feature.Severity,
		}
		vulns = append(vulns, v)

		score := getScore(p.severity)
		if score > vuln.Score {
			vuln.Score = score
		}

		// Sort vulns by severity and alphabetical order name.
		sort.Slice(vulns, func(i, j int) bool {
			v := vulns
			si := getScore(v[i].severity)
			sj := getScore(v[j].severity)
			switch {
			case si != sj:
				return si > sj
			default:
				return v[i].name < v[j].name
			}
		})

		var vulnsText []string
		for _, v := range vulns {
			t := fmt.Sprintf("[%s](%s) (%s)", v.name, v.link, v.severity)
			vulnsText = append(vulnsText, t)
		}

		affectedPackage := map[string]string{
			"Name":            p.name,
			"Version":         p.version,
			"Severity":        p.severity,
			"FixedBy":         p.fixedBy,
			"Vulnerabilities": strings.Join(vulnsText, "\n\n"),
		}

		rows = append(rows, affectedPackage)
	}

	// Sort rows by severity, alphabetical order of the package name and version.
	sort.Slice(rows, func(i, j int) bool {
		si := getScore(rows[i]["Severity"])
		sj := getScore(rows[j]["Severity"])
		switch {
		case si != sj:
			return si > sj
		case rows[i]["Name"] != rows[j]["Name"]:
			return rows[i]["Name"] < rows[j]["Name"]
		default:
			return rows[i]["Version"] < rows[j]["Version"]
		}
	})

	ap.Rows = rows
	vp.Rows = rows

	vuln.Resources = append(vuln.Resources, ap, vp)
	state.AddVulnerabilities(vuln)

	b, err := json.Marshal(results)
	if err != nil {
		log.Printf("error mashaling results: %v, %v", err, results)
	} else {
		state.Data = b
	}

	return nil
}

func getScore(severity string) float32 {
	if severity == "CRITICAL" {
		return report.SeverityThresholdCritical
	}
	if severity == "HIGH" {
		return report.SeverityThresholdHigh
	}
	if severity == "MEDIUM" {
		return report.SeverityThresholdMedium
	}
	if severity == "LOW" {
		return report.SeverityThresholdLow
	}
	return report.SeverityThresholdNone
}
