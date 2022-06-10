// Package alma implements a vulnerability source updater using
// ALSA (Alma Linux Security Advisories).

package alma

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/httputil"
)

const (
	urlFormat  = "https://errata.almalinux.org/%d/errata.json"
	linkFormat = "https://errata.almalinux.org/%d/%s.html"
	updateFlag = "almaUpdater"
)

var osVersions = []int{8, 9}
var rpmReleaseRegexp = regexp.MustCompile(`.*\.(module_)?el(?P<version>[\d]+)`)

type jsonAdvisory struct {
	UpdateInfoID string          `json:"updateinfo_id"`
	Type         string          `json:"type"`
	Title        string          `json:"title"`
	Severity     string          `json:"severity"`
	Description  string          `json:"description"`
	Pkglist      jsonPkglist     `json:"pkglist"`
	References   []jsonReference `json:"references"`
}

type jsonPkglist struct {
	Packages []jsonPackages `json:"packages"`
}

type jsonPackages struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Release string `json:"release"`
}

type jsonReference struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("alma", &updater{})
}

func (u *updater) Update(datastore vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "AlmaLinux").Info("Start fetching vulnerabilites")

	for _, osVer := range osVersions {
		url := fmt.Sprintf(urlFormat, osVer)

		// Download JSON
		r, err := httputil.GetWithUserAgent(url)
		if err != nil {
			log.WithError(err).Errorf("could now download Alma's %d update", osVer)
			return resp, commonerr.ErrCouldNotDownload
		}
		defer r.Body.Close()

		if !httputil.Status2xx(r) {
			log.WithField("StatusCode", r.StatusCode).Errorf("failed to update Alma %d", osVer)
			return resp, commonerr.ErrCouldNotDownload
		}

		// Parse JSON
		vulns, err := parseAlmaJSON(r.Body, osVer)
		if err != nil {
			return resp, err
		}

		resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)
	}

	return resp, nil
}

func (u *updater) Clean() {}

func parseAlmaJSON(jsonReader io.Reader, osVer int) (vulnerabilities []database.Vulnerability, err error) {
	// Unmarshal JSON
	var data []jsonAdvisory
	err = json.NewDecoder(jsonReader).Decode(&data)
	if err != nil {
		log.WithError(err).Errorf("could not unmarshal Alma's %d JSON", osVer)
		return vulnerabilities, commonerr.ErrCouldNotParse
	}

	vulns := make(map[string]*database.Vulnerability)

	for _, advisory := range data {
		if !strings.EqualFold(advisory.Type, "security") {
			continue
		}

		vulnName := advisory.UpdateInfoID
		vulnerability, vulnerabilityAlreadyExists := vulns[vulnName]

		if !vulnerabilityAlreadyExists {
			var subCVEs []string

			for _, reference := range advisory.References {
				if strings.EqualFold(reference.Type, "cve") {
					subCVEs = append(subCVEs, reference.ID)
				}
			}

			vulnerability = &database.Vulnerability{
				Name:        vulnName,
				Link:        fmt.Sprintf(linkFormat, osVer, strings.Replace(advisory.UpdateInfoID, ":", "-", -1)),
				Severity:    normalizeSeverity(advisory.Severity),
				Description: advisory.Description,
				SubCVEs:     subCVEs,
			}
		}

		for _, rpmPackage := range advisory.Pkglist.Packages {

			r := rpmReleaseRegexp.FindStringSubmatch(rpmPackage.Release)
			if len(r) < 2 {
				continue
			}

			releaseVersion := r[len(r)-1]

			// Create and add the feature version
			pkg := database.FeatureVersion{

				Feature: database.Feature{
					Name: rpmPackage.Name,
					Namespace: database.Namespace{
						Name:          "alma:" + releaseVersion,
						VersionFormat: rpm.ParserName,
					},
				},
				Version: rpmPackage.Version + "-" + rpmPackage.Release,
			}
			vulnerability.FixedIn = append(vulnerability.FixedIn, pkg)
		}

		// Store the vulnerability
		vulns[vulnName] = vulnerability
	}

	for _, v := range vulns {
		vulnerabilities = append(vulnerabilities, *v)
	}

	return
}

func normalizeSeverity(severity string) database.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return database.LowSeverity
	case "moderate":
		return database.MediumSeverity
	case "important":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.WithField("severity", severity).Warning("could not determine vulnerability severity")
		return database.UnknownSeverity
	}
}
