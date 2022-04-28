package updater

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/clientconn"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/wellknowndirnames"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	repoToCPEFilename = "rhvel2/repository-to-cpe.json"
)

var (
	slimUpdaterDir = filepath.Join(wellknowndirnames.WriteableDir, "slim-updater-artifacts.d")
)

// SlimUpdater updates the Scanner's vulnerability definitions, contacting
// Sensor, instead of Central as the Updater does.
type SlimUpdater struct {
	interval        time.Duration
	lastUpdatedTime time.Time
	stopSig         *concurrency.Signal

	sensorClient           *http.Client
	repoToCPE              *repo2cpe.Mapping
	repoToCPELocalFilename string
	repoToCPEURL           string
}

// NewSlimUpdater creates and initialize a new slim updater.
func NewSlimUpdater(updaterConfig Config, sensorEndpoint string, repoToCPE *repo2cpe.Mapping) (*SlimUpdater, error) {
	// Get the most recent genesis dump UUID, and construct the update URL.
	uuid, err := getMostRecentGenesisDumpUUID()
	if err != nil {
		return nil, errors.Wrap(err, "getting genesis UUID")
	}
	repoToCPEURL, err := urlfmt.FullyQualifiedURL(
		strings.Join([]string{
			urlfmt.FormatURL(sensorEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash),
			"/scanner/definitions",
		}, "/"),
		url.Values{
			"uuid": []string{uuid},
			"file": []string{repoToCPEFilename},
		})
	utils.CrashOnError(err)

	// Create sensor's HTTP client.
	//
	// FIXME Adopt clientconn.NewHTTPClient() when available in the repository.
	transport, err := clientconn.AuthenticatedHTTPTransport(
		sensorEndpoint,
		mtls.SensorSubject,
		nil,
		clientconn.UseServiceCertToken(true),
	)
	sensorClient := newHttpClient(transport)
	if err != nil {
		return nil, errors.Wrap(err, "generating TLS client config for Central")
	}

	// Initialize the updater object.
	stopSig := concurrency.NewSignal()
	slimUpdater := &SlimUpdater{
		interval:               updaterConfig.Interval,
		stopSig:                &stopSig,
		sensorClient:           sensorClient,
		repoToCPE:              repoToCPE,
		repoToCPELocalFilename: path.Join(slimUpdaterDir, repoToCPEFilename),
		repoToCPEURL:           repoToCPEURL,
	}

	return slimUpdater, nil
}

func (u SlimUpdater) RunForever() {
	t := time.NewTicker(u.interval)
	defer t.Stop()
	for {
		if err := u.update(); err != nil {
			logrus.WithError(err).Error("slim update failed")
		}
		select {
		case <-t.C:
			continue
		case <-u.stopSig.Done():
			return
		}
	}

}

func (u SlimUpdater) Stop() {
	u.stopSig.Signal()
}

// update performs the slim updater steps.
func (u SlimUpdater) update() error {
	logrus.Info("starting slim update")
	startTime := time.Now()
	if err := os.MkdirAll(path.Dir(u.repoToCPELocalFilename), 0700); err != nil {
		return errors.Wrap(err, "creating slim updater output dir")
	}
	fetched, err := fetchDumpFromURL(
		u.stopSig,
		u.sensorClient,
		u.repoToCPEURL,
		u.lastUpdatedTime,
		u.repoToCPELocalFilename,
	)
	if err != nil {
		return errors.Wrap(err, "fetching update from URL")
	}
	if !fetched {
		logrus.Info("already up-to-date, nothing to do")
		return nil
	}
	if err := u.repoToCPE.Load(u.repoToCPELocalFilename); err != nil {
		return errors.Wrap(err, "failed to load repoToCPE mapping")
	}
	u.lastUpdatedTime = startTime
	logrus.Info("Finished slim update.")
	return nil
}
