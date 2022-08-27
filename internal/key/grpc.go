package key

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/helper/pointerutil"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/k8sdeploy/key-service/internal/config"
	pb "github.com/k8sdeploy/protos/generated/key/v1"
)

type Server struct {
	pb.UnimplementedKeyServiceServer
	Config *config.Config
}

const MissingUserID = "missing user-id"
const MissingServiceKey = "missing service-key"
const InvalidServiceKey = "invalid service key"

func (s *Server) Create(c context.Context, r *pb.CreateRequest) (*pb.KeyResponse, error) {
	if r.UserId == "" {
		bugLog.Info(MissingUserID)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingUserID),
		}, nil
	}

	if r.ServiceKey == "" {
		bugLog.Info(MissingServiceKey)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	k := NewKey(s.Config)
	if !k.ValidateServiceKey(r.ServiceKey) {
		bugLog.Info(InvalidServiceKey)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(InvalidServiceKey),
		}, nil
	}

	keys, err := k.GetKeys(25)
	if err != nil {
		bugLog.Info(err)
		status := "internal error, 1"
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(status),
		}, nil
	}

	if err := NewMongo(k.Config).Create(DataSet{
		UserID:    r.UserId,
		Generated: time.Now().Unix(),
		Keys: struct {
			UserService        string `json:"user_service" bson:"user_service"`
			HooksService       string `json:"hooks_service" bson:"hooks_service"`
			CompanyService     string `json:"company_service" bson:"company_service"`
			BillingService     string `json:"billing_service" bson:"billing_service"`
			PermissionsService string `json:"permissions_service" bson:"permissions_service"`
		}{
			UserService:        keys.User,
			HooksService:       keys.Hooks,
			CompanyService:     keys.Company,
			BillingService:     keys.Billing,
			PermissionsService: keys.Permissions,
		},
	}); err != nil {
		bugLog.Info(err)
		status := "internal error, 2"
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(status),
		}, nil
	}

	return &pb.KeyResponse{
		User:    keys.User,
		Hooks:   keys.Hooks,
		Company: keys.Company,
		Billing: keys.Billing,
	}, nil
}

func (s *Server) Get(c context.Context, r *pb.GetRequest) (*pb.KeyResponse, error) {
	if r.UserId == "" {
		bugLog.Info(MissingUserID)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingUserID),
		}, nil
	}

	if r.ServiceKey == "" {
		bugLog.Info(MissingServiceKey)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	k := NewKey(s.Config)
	if !k.ValidateServiceKey(r.ServiceKey) {
		bugLog.Info(InvalidServiceKey)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(InvalidServiceKey),
		}, nil
	}

	keys, err := NewMongo(k.Config).Get(r.UserId)
	if err != nil {
		bugLog.Info(err)
		status := "internal error, 3"
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(status),
		}, nil
	}

	if keys == nil {
		status := "user not found"
		bugLog.Info("no keys or expired for user")
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(status),
		}, nil
	}

	return &pb.KeyResponse{
		User:        keys.Keys.UserService,
		Hooks:       keys.Keys.HooksService,
		Company:     keys.Keys.CompanyService,
		Billing:     keys.Keys.BillingService,
		Permissions: keys.Keys.PermissionsService,
	}, nil
}

//nolint:gocyclo
func (s *Server) Validate(c context.Context, r *pb.ValidateRequest) (*pb.ValidResponse, error) {
	if r.UserId == "" {
		bugLog.Info(MissingUserID)
		return &pb.ValidResponse{
			Status: pointerutil.StringPtr(MissingUserID),
		}, nil
	}

	if r.ServiceKey == "" {
		bugLog.Info(MissingServiceKey)
		return &pb.ValidResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	if r.CheckKey == "" {
		status := "missing check-key"
		bugLog.Info(status)
		return &pb.ValidResponse{
			Status: &status,
		}, nil
	}

	k := NewKey(s.Config)
	if !k.ValidateServiceKey(r.ServiceKey) {
		bugLog.Info(InvalidServiceKey)
		return &pb.ValidResponse{
			Valid:  false,
			Status: pointerutil.StringPtr(InvalidServiceKey),
		}, nil
	}

	if s.Config.Local.Development {
		return &pb.ValidResponse{
			Valid: true,
		}, nil
	}

	keys, err := NewMongo(k.Config).Get(r.UserId)
	if err != nil {
		status := "internal error, 4"
		bugLog.Info(err)
		return &pb.ValidResponse{
			Valid:  false,
			Status: &status,
		}, nil
	}

	if r.CheckKey == keys.Keys.UserService ||
		r.CheckKey == keys.Keys.HooksService ||
		r.CheckKey == keys.Keys.CompanyService ||
		r.CheckKey == keys.Keys.BillingService ||
		r.CheckKey == keys.Keys.PermissionsService {
		return &pb.ValidResponse{
			Valid: true,
		}, nil
	}

	return &pb.ValidResponse{
		Valid: false,
	}, nil
}
