package cpe

import (
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/wfn"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	numRegex = regexp.MustCompile(`[0-9].*$`)
)

func generateNameKeys(componentName string, hasVendor bool) set.StringSet {
	if componentName == "" {
		return set.NewStringSet()
	}
	nameSet := set.NewStringSet(
		componentName,
		strings.ReplaceAll(componentName, "_", "-"),
		strings.ReplaceAll(componentName, "-", "_"),
	)

	if hasVendor {
		nameSet.Add(numRegex.ReplaceAllString(componentName, ""))
		for name := range nameSet {
			if idx := strings.Index(name, "-"); idx != -1 {
				nameSet.Add(name[:idx])
			}
		}
	}

	return nameSet
}

func generateVersionKeys(c *component.Component) set.StringSet {
	return set.NewStringSet(c.Version, strings.ReplaceAll(c.Version, ".", `\.`))
}

func normalVersionKeys(v string) string {
	return strings.ReplaceAll(v, `\.`, ".")
}

type nameVersion struct {
	name, version string
}

func getFeaturesFromMatchResults(layer string, matchResults []matchResult) []database.FeatureVersion {
	if len(matchResults) == 0 {
		return nil
	}

	featuresMap := make(map[nameVersion]*database.FeatureVersion)
	featuresToVulns := make(map[nameVersion]set.StringSet)
	for _, m := range matchResults {
		if len(m.CPEs) == 0 {
			log.Errorf("Found 0 CPEs in match with CVE %q", m.CVE.ID())
			continue
		}
		for _, cpe := range m.CPEs {
			name, version := cpe.Product, normalVersionKeys(cpe.Version)
			nameVersion := nameVersion{
				name:    name,
				version: version,
			}

			vulnSet, ok := featuresToVulns[nameVersion]
			if !ok {
				vulnSet = set.NewStringSet()
				featuresToVulns[nameVersion] = vulnSet
			}
			if !vulnSet.Add(m.CVE.ID()) {
				continue
			}

			feature, ok := featuresMap[nameVersion]
			if !ok {
				feature = &database.FeatureVersion{
					Feature: database.Feature{
						Name:       name,
						SourceType: m.source.String(),
					},
					Version: version,
					AddedBy: database.Layer{
						Name: layer,
					},
				}
				featuresMap[nameVersion] = feature
			}
			vuln := nvdtoolscache.NewVulnerability(m.CVE.(*nvd.Vuln).CVEItem)
			vuln.FixedBy = cpe.FixedIn
			feature.AffectedBy = append(feature.AffectedBy, *vuln)
		}
	}
	features := make([]database.FeatureVersion, 0, len(featuresMap))
	for _, feature := range featuresMap {
		features = append(features, *feature)
	}
	return features
}

func getAttributes(c *component.Component) []*wfn.Attributes {
	vendorSet := set.NewStringSet()
	nameSet := set.NewStringSet()
	versionSet := generateVersionKeys(c)

	if generator, ok := generators[c.SourceType]; ok {
		generator(c, vendorSet, nameSet, versionSet)
	}

	nameSet = nameSet.Union(generateNameKeys(c.Name, vendorSet.Cardinality() != 0))
	if vendorSet.Cardinality() == 0 {
		vendorSet.Add("")
	}
	attributes := make([]*wfn.Attributes, 0, vendorSet.Cardinality()*nameSet.Cardinality()*versionSet.Cardinality())
	for vendor := range vendorSet {
		for name := range nameSet {
			for version := range versionSet {
				var tgtSW string
				if c.SourceType == component.NPMSourceType {
					tgtSW = `node\.js`
				}
				attributes = append(attributes, &wfn.Attributes{
					Vendor:   strings.ToLower(vendor),
					Product:  strings.ToLower(name),
					Version:  strings.ToLower(version),
					TargetSW: tgtSW,
				})
			}
		}
	}
	return attributes
}

func filterMatchResultsByTargetSoftware(matchResults []matchResult) []matchResult {
	filteredResults := make([]matchResult, 0, len(matchResults))
	for _, f := range matchResults {
		// If the CPE has a language specified, then ensure that the language is ensured in the result CPE
		var tgt string
		for _, matchedAttribute := range f.CPEs {
			if tgt = matchedAttribute.TargetSW; tgt != "" {
				break
			}
		}
		if tgt == "" {
			return matchResults
		}
		for _, cveCPE := range f.CVE.Config() {
			if cveCPE.TargetSW == tgt {
				filteredResults = append(filteredResults, f)
			}
		}
	}
	return filteredResults
}

type matchResult struct {
	CVE    cvefeed.Vuln
	CPEs   []wfn.AttributesWithFixedIn
	source component.SourceType
}

func CheckForVulnerabilities(layer string, components []*component.Component) []database.FeatureVersion {
	cache := nvdtoolscache.Singleton()
	var matchResults []matchResult
	for _, c := range components {
		attributes := getAttributes(c)

		products := set.NewStringSet()
		for _, a := range attributes {
			if a.Product != "" {
				products.Add(a.Product)
			}
		}

		vulns, err := cache.GetVulnsForProducts(products.AsSlice())
		if err != nil {
			log.Errorf("error getting vulns for products: %v", err)
			continue
		}
		for _, v := range vulns {
			if matchesWithFixed := v.MatchWithFixedIn(attributes, false); len(matchesWithFixed) > 0 {
				matchResults = append(matchResults, matchResult{CVE: v, CPEs: matchesWithFixed, source: c.SourceType})
			}
		}
	}
	matchResults = filterMatchResultsByTargetSoftware(matchResults)

	return getFeaturesFromMatchResults(layer, matchResults)
}