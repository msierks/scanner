// Package alma implements a vulnerability source updater using
// ALSA (Alma Linux Security Advisories).

package alma

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stretchr/testify/assert"
)

func TestAlmaParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testFile, _ := os.Open(filepath.Join(filepath.Dir(filename)) + "/testdata/fetcher_alma_test.json")

	vulns, err := parseAlmaJSON(testFile, 8)
	if assert.Nil(t, err) && assert.Len(t, vulns, 1) {
		for _, vulnerability := range vulns {

			if vulnerability.Name == "ALSA-2021:2988" {
				assert.Equal(t, "https://errata.almalinux.org/8/ALSA-2021-2988.html", vulnerability.Link)
				assert.Equal(t, database.HighSeverity, vulnerability.Severity)
				assert.Equal(t, "Varnish Cache is a high-performance HTTP accelerator. It stores web pages in memory so web servers don't have to create the same web page over and over again, giving the website a significant speed up.\n\nSecurity Fix(es):\n\n* varnish: HTTP/2 request smuggling attack via a large Content-Length header for a POST request (CVE-2021-36740)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.", vulnerability.Description)

				expectedFeatureVersions := []database.FeatureVersion{
					{
						Feature: database.Feature{
							Namespace: database.Namespace{
								Name:          "alma:8",
								VersionFormat: rpm.ParserName,
							},
							Name: "varnish",
						},
						Version: "6.0.6-2.module_el8.4.0+2514+e762eaa1.1",
					},
					{
						Feature: database.Feature{
							Namespace: database.Namespace{
								Name:          "alma:8",
								VersionFormat: rpm.ParserName,
							},
							Name: "varnish",
						},
						Version: "6.0.6-2.module_el8.4.0+2514+e762eaa1.1",
					},
				}

				for _, expectedFeatureVersion := range expectedFeatureVersions {
					assert.Contains(t, vulnerability.FixedIn, expectedFeatureVersion)
				}
			}

		}
	}
}
