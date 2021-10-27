//nolint:golint
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
	clair "github.com/stackrox/scanner"
	"github.com/stackrox/scanner/cpe"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/imagefmt"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/singletons/requiredfilenames"

	// Register database driver.
	_ "github.com/stackrox/scanner/database/pgsql"

	// Register extensions.
	_ "github.com/stackrox/scanner/cpe/validation/all"
	_ "github.com/stackrox/scanner/ext/featurefmt/apk"
	_ "github.com/stackrox/scanner/ext/featurefmt/dpkg"
	_ "github.com/stackrox/scanner/ext/featurefmt/rpm"
	_ "github.com/stackrox/scanner/ext/featurens/alpinerelease"
	_ "github.com/stackrox/scanner/ext/featurens/aptsources"
	_ "github.com/stackrox/scanner/ext/featurens/lsbrelease"
	_ "github.com/stackrox/scanner/ext/featurens/osrelease"
	_ "github.com/stackrox/scanner/ext/featurens/redhatrelease"
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"
	_ "github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	_ "github.com/stackrox/scanner/ext/vulnsrc/alpine"
	_ "github.com/stackrox/scanner/ext/vulnsrc/amzn"
	_ "github.com/stackrox/scanner/ext/vulnsrc/debian"
	_ "github.com/stackrox/scanner/ext/vulnsrc/rhel"
	_ "github.com/stackrox/scanner/ext/vulnsrc/ubuntu"
)

type manifestMatcher struct{}

func (m *manifestMatcher) Match(fullPath string, _ os.FileInfo, _ io.ReaderAt) (matches bool, extract bool) {
	return fullPath == "manifest.json" || strings.HasSuffix(fullPath, ".tar"), true
}

type Config struct {
	Layers []string
}

func filterComponentsByName(components []*component.Component, name string) []*component.Component {
	if name == "" {
		return components
	}
	filtered := components[:0]
	for _, c := range components {
		if strings.Contains(c.Name, name) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func analyzeLocalImage(path string) error {
	fmt.Println(path)
	// Get local .tar.gz path
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	// Extract
	var matcher manifestMatcher
	tarutil.SetMaxExtractableFileSize(1024 * 1024 * 1024)
	filemap, err := tarutil.ExtractFiles(f, &matcher)
	if err != nil {
		return err
	}

	if _, ok := filemap["manifest.json"]; !ok {
		return errors.New("malformed .tar does not contain manifest.json")
	}

	var configs []Config
	if err := json.Unmarshal(filemap["manifest.json"].Contents, &configs); err != nil {
		panic(err)
	}
	if len(configs) == 0 {
		return errors.New("no configs found in tar")
	}
	config := configs[0]

	// detect namespace
	var namespace *database.Namespace
	for _, l := range config.Layers {
		layerTarReader := io.NopCloser(bytes.NewBuffer(filemap[l].Contents))
		files, err := imagefmt.ExtractFromReader(layerTarReader, "Docker", requiredfilenames.SingletonMatcher())
		if err != nil {
			return err
		}
		namespace = clair.DetectNamespace(l, files, nil, false)
		if namespace != nil {
			break
		}
	}
	fmt.Println(namespace)
	var total time.Duration
	for _, l := range config.Layers {
		layerTarReader := io.NopCloser(bytes.NewBuffer(filemap[l].Contents))
		_, _, _, rhelv2Components, languageComponents, removedComponents, err := clair.DetectContentFromReader(layerTarReader, "Docker", l, &database.Layer{Namespace: namespace}, false)
		if err != nil {
			return err
		}

		if rhelv2Components != nil {
			fmt.Printf("RHELv2 Components (%d): %s\n", len(rhelv2Components.Packages), rhelv2Components)
		}

		fmt.Printf("Removed components: %v\n", removedComponents)

		languageComponents = filterComponentsByName(languageComponents, "")

		t := time.Now()
		features := cpe.CheckForVulnerabilities(l, languageComponents)

		sort.Slice(features, func(i, j int) bool {
			return features[i].Feature.Name < features[j].Feature.Name
		})

		total += time.Since(t)
		fmt.Printf("%s (%d components)\n", l, len(languageComponents))
		for _, f := range features {
			fmt.Println("\t", f.Feature.Name, f.Version, f.Feature.SourceType, f.Feature.Location, fmt.Sprintf("(%d vulns)", len(f.AffectedBy)))
			sort.Slice(f.AffectedBy, func(i, j int) bool {
				return f.AffectedBy[i].Name < f.AffectedBy[j].Name
			})
			for _, v := range f.AffectedBy {
				fmt.Println("\t\t", v.Name, v.FixedBy)
			}
		}
	}
	fmt.Printf("\n%0.4f seconds took Checking for vulns\n", total.Seconds())
	return nil
}

func main() {
	if err := mainCmd(); err != nil {
		panic(err)
	}
}

// Assumes Working Directory is the repo's top-level directory (scanner/).
func mainCmd() error {
	nvdtoolscache.BoltPath = "/tmp/temp.db"
	nvdPath, err := filepath.Abs("image/scanner/dump/nvd")
	if err != nil {
		return err
	}
	utils.Must(os.Setenv("NVD_DEFINITIONS_DIR", nvdPath))
	nvdtoolscache.Singleton()

	paths := os.Args[1:]
	if len(paths) == 0 {
		return errors.New("no files specified")
	}

	for _, path := range paths {
		if err := process(path); err != nil {
			return err
		}
	}

	return nil
}

func process(filePath string) error {
	st, err := os.Stat(filePath)
	if err != nil {
		return errors.Wrapf(err, "stat'ing %s", filePath)
	}

	if !st.IsDir() {
		return analyzeLocalImage(filePath)
	}

	entries, err := os.ReadDir(filePath)
	if err != nil {
		return err
	}

	for _, e := range entries {
		if err := process(filepath.Join(filePath, e.Name())); err != nil {
			return err
		}
	}

	return err
}
