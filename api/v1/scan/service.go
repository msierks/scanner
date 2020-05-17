package scan

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	apiGRPC "github.com/stackrox/scanner/api/grpc"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/licenses"
	server "github.com/stackrox/scanner/pkg/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service interface {
	apiGRPC.APIService

	v1.ScanServiceServer
}

// NewService returns the service for scanning
func NewService(licenseManager licenses.Manager, db database.Datastore) Service {
	return &serviceImpl{
		licenseManager: licenseManager,
		db:             db,
	}
}

type serviceImpl struct {
	licenseManager licenses.Manager
	db             database.Datastore
}

func (s *serviceImpl) checkLicense() error {
	if !s.licenseManager.ValidLicenseExists() {
		return status.Error(codes.Internal, licenses.ErrNoValidLicense.Error())
	}
	return nil
}

func (s *serviceImpl) GetLanguageLevelComponents(ctx context.Context, req *v1.GetLanguageLevelComponentsRequest) (*v1.GetLanguageLevelComponentsResponse, error) {
	if err := s.checkLicense(); err != nil {
		return nil, err
	}

	layerName, err := s.getLayerNameFromImageSpec(req.GetImageSpec())
	if err != nil {
		return nil, err
	}
	components, err := s.db.GetLayerLanguageComponents(layerName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve components from DB: %v", err)
	}
	return &v1.GetLanguageLevelComponentsResponse{
		LayerToComponents: convertComponents(components),
	}, nil
}

func (s *serviceImpl) ScanImage(ctx context.Context, req *v1.ScanImageRequest) (*v1.ScanImageResponse, error) {
	if err := s.checkLicense(); err != nil {
		return nil, err
	}

	image, err := types.GenerateImageFromString(req.GetImage())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "could not parse image %q", req.GetImage())
	}

	reg := req.GetRegistry()

	digest, err := server.ProcessImage(s.db, image, &types.ImageRequest{
		Image:               image.String(),
		Registry:            reg.GetUrl(),
		Insecure:            reg.GetInsecure(),
		UnsupportedHeadCall: reg.GetUnsupportedHeadCall(),
	}, reg.GetUsername(), reg.GetPassword())
	if err != nil {
		return nil, err
	}

	return &v1.ScanImageResponse{
		Status: v1.ScanStatus_SUCCEEDED,
		Image: &v1.ImageSpec{
			Digest: digest,
			Image:  image.TaggedName(),
		},
	}, nil
}

func (s *serviceImpl) getLayer(layerName string) (*v1.GetScanResponse, error) {
	dbLayer, err := s.db.FindLayer(layerName, true, true)
	if err == commonerr.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "Could not find Clair layer %q", layerName)
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	layer, err := apiV1.LayerFromDatabaseModel(s.db, dbLayer, true, true)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	features, err := convertFeatures(layer.Features)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting features: %v", err)
	}

	return &v1.GetScanResponse{
		Status: v1.ScanStatus_SUCCEEDED,
		Image: &v1.Image{
			Features: features,
		},
	}, nil
}

func (s *serviceImpl) getLayerNameFromImageSpec(imgSpec *v1.ImageSpec) (string, error) {
	if stringutils.AllEmpty(imgSpec.GetImage(), imgSpec.GetDigest()) {
		return "", status.Error(codes.InvalidArgument, "either image or digest must be specified")
	}

	var layerFetcher func(s string) (string, bool, error)
	var argument string
	if digest := imgSpec.GetDigest(); digest != "" {
		logrus.Debugf("Getting layer SHA by digest %s", digest)
		argument = digest
		layerFetcher = s.db.GetLayerBySHA
	} else {
		logrus.Debugf("Getting layer SHA by image %s", imgSpec.GetImage())
		argument = imgSpec.GetImage()
		layerFetcher = s.db.GetLayerByName
	}
	layerName, exists, err := layerFetcher(argument)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", status.Errorf(codes.NotFound, "image with reference %q not found", argument)
	}
	return layerName, nil
}

func (s *serviceImpl) GetScan(ctx context.Context, req *v1.GetScanRequest) (*v1.GetScanResponse, error) {
	if err := s.checkLicense(); err != nil {
		return nil, err
	}

	layerName, err := s.getLayerNameFromImageSpec(req.GetImageSpec())
	if err != nil {
		return nil, err
	}
	return s.getLayer(layerName)
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterScanServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterScanServiceHandler(ctx, mux, conn)
}
